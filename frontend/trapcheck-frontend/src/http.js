export class HttpError extends Error {
  constructor(message, status) {
    super(message);
    this.name = "HttpError";
    this.status = status;
  }
}

const isObject = value => value !== null && typeof value === "object" && !Array.isArray(value);
const isText = value => typeof value === "string" && value.trim().length > 0;
const isCount = value => Number.isInteger(value) && value >= 0;

function detailMessage(detail) {
  if (isText(detail)) return detail.slice(0, 500);
  if (Array.isArray(detail)) return detail.map(detailMessage).filter(Boolean).join("; ").slice(0, 500);
  if (isObject(detail) && isText(detail.msg)) return detail.msg.slice(0, 500);
  return "";
}

export async function readResponse(response, { allowEmpty = false } = {}) {
  const text = await response.text();
  let data;
  try {
    data = text.trim() ? JSON.parse(text) : undefined;
  } catch {
    // Non-JSON errors (including proxy HTML) are not shown as server messages.
  }
  if (!response.ok) {
    const fallback = response.status === 401
      ? "Session expired. Please login again."
      : `Request failed (HTTP ${response.status}). Please try again.`;
    throw new HttpError(detailMessage(data?.detail) || detailMessage(data?.message) || fallback, response.status);
  }
  if (allowEmpty && !text.trim()) return null;
  if (!isObject(data)) throw new Error("The server returned an invalid response. Please try again.");
  return data;
}

export function errorMessage(error) {
  return error instanceof Error && isText(error.message)
    ? error.message
    : "Request failed. Please try again.";
}

export function validateAuth(data) {
  if (!isObject(data) || !isText(data.access_token) || !isText(data.email)) {
    throw new Error("Login returned an invalid response. Please sign in again.");
  }
  return data;
}

export function normalizeThreat(level) {
  if (level === "DANGER") return "DANGEROUS";
  if (level === "WARNING") return "SUSPICIOUS";
  return ["DANGEROUS", "SUSPICIOUS", "SAFE"].includes(level) ? level : "UNKNOWN";
}

export function validateAnalysis(data) {
  if (!isObject(data) || normalizeThreat(data.threat_level) === "UNKNOWN" ||
      !["summary", "explanation", "action"].every(key => isText(data[key])) ||
      !Array.isArray(data.red_flags) || !data.red_flags.every(isText) ||
      (data.threat_emoji != null && typeof data.threat_emoji !== "string") ||
      (data.matched_scam_type != null && typeof data.matched_scam_type !== "string") ||
      (data.saved_to_history != null && typeof data.saved_to_history !== "boolean")) {
    throw new Error("The analysis response is incomplete or invalid. No safety verdict is available. Please retry.");
  }
  return { ...data, threat_level: normalizeThreat(data.threat_level) };
}

export function validateHistory(data) {
  if (!isObject(data) || !Array.isArray(data.scans) || !data.scans.every(scan =>
    isObject(scan) && (isText(scan.id) || Number.isInteger(scan.id)) &&
    typeof scan.message_preview === "string" && isText(scan.scanned_at) &&
    ["channel", "scam_type", "threat_level"].every(key => scan[key] == null || typeof scan[key] === "string") &&
    (scan.confidence == null || typeof scan.confidence === "string" || Number.isFinite(scan.confidence))
  ) || new Set(data.scans.map(scan => String(scan.id))).size !== data.scans.length) {
    throw new Error("The server returned invalid scan history. Please retry.");
  }
  return data.scans.map(scan => ({ ...scan, threat_level: normalizeThreat(scan.threat_level) }));
}

export function validateStats(data) {
  const countMap = value => isObject(value) && Object.values(value).every(isCount);
  if (!isObject(data) || !isCount(data.total_scans) || !isCount(data.scams_caught) ||
      !isText(data.member_since) || !countMap(data.by_threat_level) ||
      !["dangerous", "suspicious", "safe"].every(key => isCount(data.by_threat_level[key])) ||
      !countMap(data.top_scam_types) || !countMap(data.by_channel)) {
    throw new Error("The server returned invalid history statistics. Please retry.");
  }
  return data;
}
