import { useState, useEffect, useRef, useCallback } from "react";
import { HttpError, errorMessage, readResponse, validateHistory, validateStats } from "./http.js";

const API_BASE = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

const threatColor = level => {
  if (level==="DANGEROUS"||level==="DANGER")   return { bg:"#ff2d2d18", border:"#ff2d2d", text:"#ff4444", emoji:"🔴" };
  if (level==="SUSPICIOUS"||level==="WARNING") return { bg:"#ffb30018", border:"#ffb300", text:"#ffcc00", emoji:"🟡" };
  if (level === "SAFE") return { bg:"#00e57618", border:"#00e576", text:"#00e576", emoji: null };
  return { bg:"#88888818", border:"#888888", text:"#aaaaaa", emoji:"?" };
};

// ── Stat card ─────────────────────────────────────────────────────────────────
function StatCard({ label, value, sub, color="#00e576" }) {
  return (
    <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid #1a1a1a", borderRadius:"12px", padding:"1.2rem", borderTop:`2px solid ${color}` }}>
      <div style={{ fontSize:"2rem", fontWeight:900, color, marginBottom:"0.2rem", letterSpacing:"-1px" }}>{value}</div>
      <div style={{ fontSize:"0.72rem", color:"#555", letterSpacing:"2px", textTransform:"uppercase" }}>{label}</div>
      {sub && <div style={{ fontSize:"0.7rem", color:"#333", marginTop:"0.3rem" }}>{sub}</div>}
    </div>
  );
}

// ── Scan row ──────────────────────────────────────────────────────────────────
function ScanRow({ scan }) {
  const [expanded, setExpanded] = useState(false);
  const c = threatColor(scan.threat_level);

  return (
    <div style={{ border:`1px solid #1a1a1a`, borderRadius:"10px", overflow:"hidden", transition:"all 0.2s" }}>
      <div role="button" tabIndex={0} aria-expanded={expanded}
        onKeyDown={event => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setExpanded(value => !value); } }}
        onClick={() => setExpanded(value => !value)}
        style={{ display:"flex", alignItems:"center", gap:"0.8rem", padding:"0.85rem 1rem", cursor:"pointer", background:"rgba(255,255,255,0.01)", transition:"background 0.15s" }}
        onMouseEnter={e=>e.currentTarget.style.background="rgba(255,255,255,0.03)"}
        onMouseLeave={e=>e.currentTarget.style.background="rgba(255,255,255,0.01)"}>

        <span style={{ fontSize:"1.1rem", flexShrink:0 }}>{c.emoji || <span style={{display:"inline-block",width:"1rem",height:"1rem",borderRadius:"50%",background:c.text}} />}</span>

        <div style={{ flex:1, minWidth:0 }}>
          <div style={{ fontSize:"0.85rem", color:"#ccc", whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
            {scan.message_preview}
          </div>
          <div style={{ fontSize:"0.68rem", color:"#444", marginTop:"0.2rem" }}>
            {scan.scam_type && <span style={{ color:"#555", marginRight:"0.8rem" }}>{scan.scam_type}</span>}
            {scan.channel && <span style={{ marginRight:"0.8rem" }}>via {scan.channel}</span>}
            {scan.scanned_at}
          </div>
        </div>

        <div style={{ display:"flex", alignItems:"center", gap:"0.6rem", flexShrink:0 }}>
          <span style={{ fontSize:"0.68rem", color:c.text, padding:"0.15rem 0.6rem", background:`${c.text}15`, border:`1px solid ${c.text}30`, borderRadius:"100px", letterSpacing:"1px" }}>
            {scan.threat_level}
          </span>
          <span style={{ fontSize:"0.68rem", color:"#333" }}>{scan.confidence}</span>
          <span style={{ color:"#333", fontSize:"0.8rem", transform:expanded?"rotate(180deg)":"none", transition:"transform 0.2s" }}>▾</span>
        </div>
      </div>

      {expanded && (
        <div style={{ padding:"0.8rem 1rem 1rem", borderTop:"1px solid #141414", background:"rgba(0,0,0,0.2)" }}>
          <div style={{ fontSize:"0.78rem", color:"#555", letterSpacing:"1px", marginBottom:"0.4rem", textTransform:"uppercase" }}>Message Preview</div>
          <p style={{ fontSize:"0.84rem", color:"#888", margin:"0 0 0.8rem", lineHeight:1.6, fontFamily:"inherit" }}>{scan.message_preview}...</p>
          <div style={{ display:"flex", gap:"0.5rem", flexWrap:"wrap" }}>
            <span style={{ fontSize:"0.7rem", color:"#444", padding:"0.2rem 0.6rem", border:"1px solid #1e1e1e", borderRadius:"100px" }}>📱 {scan.channel}</span>
            {scan.scam_type && <span style={{ fontSize:"0.7rem", color:"#444", padding:"0.2rem 0.6rem", border:"1px solid #1e1e1e", borderRadius:"100px" }}>🎯 {scan.scam_type}</span>}
            <span style={{ fontSize:"0.7rem", color:"#444", padding:"0.2rem 0.6rem", border:"1px solid #1e1e1e", borderRadius:"100px" }}>📅 {scan.scanned_at}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main History component ─────────────────────────────────────────────────────
export default function History(props) {
  return <HistoryView key={props.token} {...props} />;
}

function HistoryView({ token, userEmail, onBack, onUnauthorized }) {
  const [stats, setStats]     = useState(null);
  const [scans, setScans]     = useState([]);
  const [loading, setLoading] = useState(Boolean(token));
  const [filter, setFilter]   = useState("ALL");
  const [search, setSearch]   = useState("");
  const [error, setError]     = useState(token ? "" : "Please login to view your history.");
  const requestRef = useRef(null);

  const fetchData = useCallback(async () => {
    if (!token || requestRef.current) return;
    const controller = new AbortController();
    requestRef.current = controller;
    setLoading(true); setError(""); setStats(null); setScans([]);
    try {
      const options = { headers: { Authorization: `Bearer ${token}` }, signal:controller.signal };
      const [statsRes, historyRes] = await Promise.all([
        fetch(`${API_BASE}/auth/stats`, options),
        fetch(`${API_BASE}/auth/history?limit=100`, options)
      ]);
      if (statsRes.status === 401 || historyRes.status === 401) {
        throw new HttpError("Session expired. Please login again.", 401);
      }
      const [statsData, historyData] = await Promise.all([
        readResponse(statsRes), readResponse(historyRes)
      ]);
      const validStats = validateStats(statsData);
      const validScans = validateHistory(historyData);
      if (controller.signal.aborted) return;
      setStats(validStats); setScans(validScans);
    } catch (err) {
      if (controller.signal.aborted) return;
      setError(errorMessage(err));
      if (err.status === 401) onUnauthorized?.();
    } finally {
      if (requestRef.current === controller) requestRef.current = null;
      if (!controller.signal.aborted) setLoading(false);
    }
  }, [token, onUnauthorized]);

  useEffect(() => {
    fetchData();
    return () => { requestRef.current?.abort(); requestRef.current = null; };
  }, [fetchData]);

  // Filter + search
  const filtered = scans.filter(s => {
    const matchFilter = filter === "ALL" || s.threat_level === filter || (filter === "DANGEROUS" && s.threat_level === "DANGER") || (filter === "SUSPICIOUS" && s.threat_level === "WARNING");
    const matchSearch = !search || s.message_preview?.toLowerCase().includes(search.toLowerCase()) || s.scam_type?.toLowerCase().includes(search.toLowerCase());
    return matchFilter && matchSearch;
  });

  return (
    <div style={{ minHeight:"100vh", background:"#0a0a0f", fontFamily:"'Courier New',monospace", color:"#ccc" }}>
      <div style={{ position:"fixed", inset:0, zIndex:0, backgroundImage:"linear-gradient(rgba(0,229,118,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,118,0.02) 1px,transparent 1px)", backgroundSize:"40px 40px" }} />

      {/* Header */}
      <div style={{ position:"sticky", top:0, zIndex:10, background:"rgba(10,10,15,0.97)", backdropFilter:"blur(20px)", borderBottom:"1px solid rgba(0,229,118,0.08)", padding:"0.8rem 1.5rem", display:"flex", alignItems:"center", justifyContent:"space-between" }}>
        <div style={{ display:"flex", alignItems:"center", gap:"1rem" }}>
          <button onClick={onBack} style={{ background:"none", border:"1px solid #1e1e1e", borderRadius:"8px", color:"#555", cursor:"pointer", fontFamily:"inherit", fontSize:"0.8rem", padding:"0.3rem 0.7rem" }}>← Back</button>
          <div>
            <div style={{ fontWeight:900, fontSize:"1rem", background:"linear-gradient(135deg,#00e576,#00b8d4)", WebkitBackgroundClip:"text", WebkitTextFillColor:"transparent" }}>Scan History</div>
            <div style={{ fontSize:"0.6rem", color:"#333", letterSpacing:"2px" }}>YOUR PROTECTION RECORD</div>
          </div>
        </div>
        <span style={{ fontSize:"0.7rem", color:"#444" }}>👤 {userEmail}</span>
      </div>

      <div style={{ maxWidth:800, margin:"0 auto", padding:"1.5rem", position:"relative", zIndex:1 }}>

        {error && (
          <div role="alert" style={{ background:"rgba(255,45,45,0.05)", border:"1px solid rgba(255,45,45,0.2)", borderRadius:"10px", padding:"1rem", marginBottom:"1.5rem", color:"#ff6b6b", fontSize:"0.85rem" }}>
            {error}
            {token && <button disabled={loading} onClick={fetchData} style={{display:"block",marginTop:"0.6rem",background:"none",border:"1px solid #555",borderRadius:"6px",padding:"0.3rem 0.8rem",color:"#ccc",fontFamily:"inherit",cursor:"pointer"}}>Retry history</button>}
          </div>
        )}

        {loading ? (
          <div style={{ textAlign:"center", padding:"4rem", color:"#333" }}>
            <div style={{ fontSize:"2rem", marginBottom:"1rem" }}>🛡️</div>
            <p style={{ fontSize:"0.8rem", letterSpacing:"2px" }}>LOADING YOUR HISTORY...</p>
          </div>
        ) : !error && (
          <>
            {/* Stats grid */}
            {stats && (
              <div style={{ marginBottom:"2rem" }}>
                <div style={{ fontSize:"0.65rem", color:"#333", letterSpacing:"3px", textTransform:"uppercase", marginBottom:"1rem" }}>Your Protection Stats</div>
                <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(140px,1fr))", gap:"0.8rem", marginBottom:"1rem" }}>
                  <StatCard label="Total Scans"   value={stats.total_scans}   color="#00b8d4" />
                  <StatCard label="Scams Caught"  value={stats.scams_caught}  color="#ff4444" sub={stats.total_scans > 0 ? `${Math.round(stats.scams_caught/stats.total_scans*100)}% of scans` : ""} />
                  <StatCard label="Safe Messages" value={stats.by_threat_level?.safe || 0} color="#00e576" />
                  <StatCard label="Member Since"  value={stats.member_since}  color="#ffb300" />
                </div>

                {/* Threat breakdown bar */}
                {stats.total_scans > 0 && (
                  <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid #1a1a1a", borderRadius:"12px", padding:"1.2rem", marginBottom:"1rem" }}>
                    <div style={{ fontSize:"0.65rem", color:"#444", letterSpacing:"2px", marginBottom:"0.8rem", textTransform:"uppercase" }}>Threat Breakdown</div>
                    <div style={{ display:"flex", height:8, borderRadius:"100px", overflow:"hidden", gap:2 }}>
                      {stats.by_threat_level?.dangerous > 0 && <div style={{ flex:stats.by_threat_level.dangerous, background:"#ff4444", borderRadius:"100px" }} />}
                      {stats.by_threat_level?.suspicious > 0 && <div style={{ flex:stats.by_threat_level.suspicious, background:"#ffb300", borderRadius:"100px" }} />}
                      {stats.by_threat_level?.safe > 0 && <div style={{ flex:stats.by_threat_level.safe, background:"#00e576", borderRadius:"100px" }} />}
                    </div>
                    <div style={{ display:"flex", gap:"1.5rem", marginTop:"0.6rem" }}>
                      <span style={{ fontSize:"0.68rem", color:"#ff4444" }}>🔴 {stats.by_threat_level?.dangerous || 0} Dangerous</span>
                      <span style={{ fontSize:"0.68rem", color:"#ffb300" }}>🟡 {stats.by_threat_level?.suspicious || 0} Suspicious</span>
                      <span style={{ fontSize:"0.68rem", color:"#00e576" }}>🟢 {stats.by_threat_level?.safe || 0} Safe</span>
                    </div>
                  </div>
                )}

                {/* Top scam types + channels */}
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:"0.8rem" }}>
                  {stats.top_scam_types && Object.keys(stats.top_scam_types).length > 0 && (
                    <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid #1a1a1a", borderRadius:"12px", padding:"1rem" }}>
                      <div style={{ fontSize:"0.65rem", color:"#444", letterSpacing:"2px", marginBottom:"0.7rem", textTransform:"uppercase" }}>Top Scam Types</div>
                      {Object.entries(stats.top_scam_types).map(([type, count]) => (
                        <div key={type} style={{ display:"flex", justifyContent:"space-between", marginBottom:"0.4rem" }}>
                          <span style={{ fontSize:"0.78rem", color:"#777" }}>{type}</span>
                          <span style={{ fontSize:"0.78rem", color:"#ff4444", fontWeight:700 }}>{count}x</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {stats.by_channel && Object.keys(stats.by_channel).length > 0 && (
                    <div style={{ background:"rgba(255,255,255,0.02)", border:"1px solid #1a1a1a", borderRadius:"12px", padding:"1rem" }}>
                      <div style={{ fontSize:"0.65rem", color:"#444", letterSpacing:"2px", marginBottom:"0.7rem", textTransform:"uppercase" }}>By Channel</div>
                      {Object.entries(stats.by_channel).map(([ch, count]) => (
                        <div key={ch} style={{ display:"flex", justifyContent:"space-between", marginBottom:"0.4rem" }}>
                          <span style={{ fontSize:"0.78rem", color:"#777" }}>{ch}</span>
                          <span style={{ fontSize:"0.78rem", color:"#00b8d4", fontWeight:700 }}>{count}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Scan history list */}
            <div>
              <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:"1rem", flexWrap:"wrap", gap:"0.5rem" }}>
                <div style={{ fontSize:"0.65rem", color:"#333", letterSpacing:"3px", textTransform:"uppercase" }}>
                  Scan History ({filtered.length} records)
                </div>
                <button disabled={loading || !token} onClick={fetchData} style={{ fontSize:"0.68rem", color:"#444", background:"none", border:"1px solid #1a1a1a", borderRadius:"6px", padding:"0.25rem 0.6rem", cursor:"pointer", fontFamily:"inherit" }}>↻ Refresh</button>
              </div>

              {/* Search */}
              <input
                value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search messages or scam types..."
                style={{ width:"100%", padding:"0.65rem 1rem", background:"rgba(255,255,255,0.02)", border:"1px solid #1a1a1a", borderRadius:"8px", color:"#ccc", fontFamily:"inherit", fontSize:"0.84rem", outline:"none", marginBottom:"0.8rem", boxSizing:"border-box" }}
              />

              {/* Filter pills */}
              <div style={{ display:"flex", gap:"0.4rem", marginBottom:"1rem", flexWrap:"wrap" }}>
                {["ALL","DANGEROUS","SUSPICIOUS","SAFE"].map(f => (
                  <button key={f} onClick={() => setFilter(f)}
                    style={{ padding:"0.25rem 0.7rem", fontSize:"0.68rem", background:filter===f?"rgba(0,229,118,0.1)":"transparent", border:`1px solid ${filter===f?"#00e576":"#1a1a1a"}`, borderRadius:"100px", color:filter===f?"#00e576":"#444", cursor:"pointer", fontFamily:"inherit", letterSpacing:"0.5px" }}>
                    {f==="ALL"?"All Scans":f==="DANGEROUS"?"🔴 Dangerous":f==="SUSPICIOUS"?"🟡 Suspicious":"🟢 Safe"}
                  </button>
                ))}
              </div>

              {/* Scan list */}
              {filtered.length === 0 ? (
                <div style={{ textAlign:"center", padding:"3rem", color:"#222" }}>
                  <div style={{ fontSize:"2rem", marginBottom:"0.8rem" }}>🛡️</div>
                  <p style={{ fontSize:"0.8rem", letterSpacing:"1px" }}>
                    {scans.length === 0 ? "No scans yet. Go analyze a suspicious message!" : "No scans match your filter."}
                  </p>
                </div>
              ) : (
                <div style={{ display:"flex", flexDirection:"column", gap:"0.5rem" }}>
                  {filtered.map(scan => <ScanRow key={scan.id} scan={scan} />)}
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}