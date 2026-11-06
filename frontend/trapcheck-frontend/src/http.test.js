import test from "node:test";
import assert from "node:assert/strict";
import {
  HttpError, errorMessage, normalizeThreat, readResponse,
  validateAnalysis, validateAuth, validateHistory, validateStats
} from "./http.js";

const response = (data, status = 200) => new Response(JSON.stringify(data), { status });
const analysis = {
  threat_level:"SAFE", summary:"No known indicators found.",
  explanation:"This is not a guarantee of safety.", action:"Verify the sender.",
  red_flags:[], saved_to_history:true
};
const scan = {
  id:1, message_preview:"Test message", scanned_at:"2026-01-01",
  threat_level:"DANGER", channel:"SMS", scam_type:"Phishing", confidence:"90%"
};
const stats = {
  total_scans:1, scams_caught:1, member_since:"2026-01-01",
  by_threat_level:{dangerous:1, suspicious:0, safe:0},
  top_scam_types:{Phishing:1}, by_channel:{SMS:1}
};

test("reads valid JSON success", async () => {
  assert.deepEqual(await readResponse(response({message:"Accepted"})), {message:"Accepted"});
});

for (const status of [400, 401, 403, 422, 429, 500, 503]) {
  test(`rejects HTTP ${status} even with an analysis-shaped body`, async () => {
    await assert.rejects(readResponse(response(analysis, status)), err =>
      err instanceof HttpError && err.status === status && typeof err.message === "string");
  });
}

test("formats FastAPI 422 details without exposing input or rendering objects", async () => {
  const detail = [{loc:["body", "email"], msg:"Invalid email", input:"private-value"}, {msg:"Required field"}];
  await assert.rejects(readResponse(response({detail}, 422)), err =>
    err.message === "Invalid email; Required field" && !err.message.includes("private-value"));
});

test("handles string, object, and unrecognized error details safely", async () => {
  for (const detail of ["Denied", {msg:"Denied"}, {unexpected:"value"}, null]) {
    await assert.rejects(readResponse(response({detail}, 400)), err =>
      typeof err.message === "string" && !err.message.includes("[object Object]"));
  }
});

test("does not display proxy HTML or raw non-JSON errors", async () => {
  for (const body of ["<html>Internal server error</html>", "upstream unavailable", ""]) {
    await assert.rejects(readResponse(new Response(body, {status:502})), /HTTP 502/);
  }
  await assert.rejects(readResponse(new Response("<html>Expired</html>", {status:401})), err =>
    err.status === 401 && err.message.includes("Session expired"));
});

test("rejects malformed success payloads and unexpected empty responses", async () => {
  for (const body of ["", "not json", "null", "[]", '"text"', "false"]) {
    await assert.rejects(readResponse(new Response(body)), /invalid response/);
  }
});

test("accepts empty success only when explicitly allowed", async () => {
  assert.equal(await readResponse(new Response(null, {status:204}), {allowEmpty:true}), null);
  await assert.rejects(readResponse(new Response(null, {status:204})), /invalid response/);
  await assert.rejects(readResponse(new Response(null, {status:500}), {allowEmpty:true}), /HTTP 500/);
  await assert.rejects(readResponse(new Response("not json"), {allowEmpty:true}), /invalid response/);
});

test("limits error text length", async () => {
  await assert.rejects(readResponse(response({detail:"x".repeat(1000)}, 400)), err => err.message.length === 500);
});

test("validates login credentials before accepting a session", () => {
  const auth = {access_token:"token", email:"test@example.com"};
  assert.equal(validateAuth(auth), auth);
  for (const data of [null, {}, {access_token:"", email:"user"}, {access_token:"token", email:{}}, {access_token:{}, email:"user"}]) {
    assert.throws(() => validateAuth(data), /invalid response/);
  }
});

test("normalizes known threat aliases and never treats unknown values as safe", () => {
  assert.equal(normalizeThreat("DANGER"), "DANGEROUS");
  assert.equal(normalizeThreat("WARNING"), "SUSPICIOUS");
  assert.equal(normalizeThreat("SAFE"), "SAFE");
  for (const level of [undefined, null, "", "safe", "LOW", {}, []]) {
    assert.equal(normalizeThreat(level), "UNKNOWN");
    assert.throws(() => validateAnalysis({...analysis, threat_level:level}), /No safety verdict/);
  }
});

test("requires complete analysis and string-only flags and display fields", () => {
  assert.deepEqual(validateAnalysis(analysis), analysis);
  assert.equal(validateAnalysis({...analysis, threat_level:"WARNING"}).threat_level, "SUSPICIOUS");
  for (const patch of [
    {red_flags:"flag"}, {red_flags:[{}]}, {red_flags:null}, {red_flags:undefined},
    {summary:{}}, {explanation:[]}, {action:""}, {threat_emoji:{}},
    {matched_scam_type:{}}, {saved_to_history:"false"}
  ]) {
    assert.throws(() => validateAnalysis({...analysis, ...patch}), /No safety verdict/);
  }
});

test("history normalizes aliases and labels unknown verdicts without marking them safe", () => {
  const result = validateHistory({scans:[scan, {...scan, id:2, threat_level:"INVALID"}]});
  assert.equal(result[0].threat_level, "DANGEROUS");
  assert.equal(result[1].threat_level, "UNKNOWN");
  assert.equal(scan.threat_level, "DANGER");
  assert.deepEqual(validateHistory({scans:[]}), []);
});

test("rejects malformed history, duplicate keys, and unsafe render/search fields", () => {
  for (const data of [{}, {scans:{}}, {scans:[null]}, {scans:[scan, scan]}]) {
    assert.throws(() => validateHistory(data), /invalid scan history/);
  }
  for (const patch of [{id:{}}, {message_preview:{}}, {scam_type:[]}, {confidence:{}}, {scanned_at:{}}, {channel:{}}]) {
    assert.throws(() => validateHistory({scans:[{...scan, ...patch}]}), /invalid scan history/);
  }
});

test("validates statistics rather than substituting zero for broken responses", () => {
  assert.equal(validateStats(stats), stats);
  for (const patch of [
    {total_scans:"1"}, {scams_caught:-1}, {member_since:{}},
    {by_threat_level:{}}, {by_threat_level:{dangerous:1, suspicious:0, safe:{}}},
    {top_scam_types:{Phishing:{}}}, {by_channel:[]}
  ]) {
    assert.throws(() => validateStats({...stats, ...patch}), /invalid history statistics/);
  }
});

test("unknown thrown values produce a renderable fallback", () => {
  assert.equal(errorMessage(new Error("Network unavailable")), "Network unavailable");
  assert.equal(errorMessage({detail:{}}), "Request failed. Please try again.");
});
