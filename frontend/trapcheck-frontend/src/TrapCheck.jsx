import { useState, useRef, useEffect, useCallback } from "react";
import History from "./History.jsx";
import { errorMessage, readResponse, validateAnalysis, validateAuth } from "./http.js";

const LANGUAGES = [
  { code:"en", label:"English",  greeting:"Hello! I'm TrapCheck. Paste a suspicious message, URL, email, or SMS and I'll analyze it for you." },
  { code:"te", label:"తెలుగు",   greeting:"నమస్కారం! నేను TrapCheck. అనుమానాస్పద మెసేజ్, URL, ఇమెయిల్ లేదా SMS పేస్ట్ చేయండి, నేను విశ్లేషిస్తాను." },
  { code:"hi", label:"हिंदी",    greeting:"नमस्ते! मैं TrapCheck हूँ। कोई संदिग्ध संदेश, URL, ईमेल या SMS पेस्ट करें, मैं उसका विश्लेषण करूँगा।" },
  { code:"ta", label:"தமிழ்",   greeting:"வணக்கம்! நான் TrapCheck. சந்தேகமான செய்தி, URL, மின்னஞ்சல் அல்லது SMS ஒட்டுங்கள்." },
];

// ── Feature 3: Full native language UI labels ─────────────────────────────────
const UI = {
  en: { channel:"CHANNEL", placeholder:"Paste suspicious message, URL, or email here...", loginRequired:"Please login to analyze messages. Messages are sent to the backend and stored in your scan history.", redFlags:"RED FLAGS", analysis:"ANALYSIS", whatToDo:"WHAT TO DO", reportBtn:"🚩 Report to community", reportDone:"✅ Reported! Thank you.", analyzing:"Analyzing...", loginNow:"Login Now →", register:"Register", logout:"logout", history:"history" },
  te: { channel:"ఛానల్", placeholder:"అనుమానాస్పద మెసేజ్ ఇక్కడ పేస్ట్ చేయండి...", loginRequired:"మెసేజ్‌లను విశ్లేషించడానికి ముందుగా లాగిన్ చేయండి. మెసేజ్‌లు బ్యాకెండ్‌కు పంపబడి, స్కాన్ చరిత్రలో నిల్వ చేయబడతాయి.", redFlags:"హెచ్చరిక సంకేతాలు", analysis:"విశ్లేషణ", whatToDo:"మీరు చేయవలసింది", reportBtn:"🚩 కమ్యూనిటీకి రిపోర్ట్ చేయండి", reportDone:"✅ రిపోర్ట్ చేయబడింది! ధన్యవాదాలు.", analyzing:"విశ్లేషిస్తున్నాము...", loginNow:"లాగిన్ చేయండి →", register:"నమోదు చేయండి", logout:"లాగ్అవుట్", history:"చరిత్ర" },
  hi: { channel:"चैनल", placeholder:"संदिग्ध संदेश यहाँ पेस्ट करें...", loginRequired:"संदेशों की जांच के लिए पहले लॉगिन करें। संदेश बैकएंड को भेजे जाते हैं और स्कैन इतिहास में सहेजे जाते हैं।", redFlags:"खतरे के संकेत", analysis:"विश्लेषण", whatToDo:"आपको क्या करना चाहिए", reportBtn:"🚩 समुदाय को रिपोर्ट करें", reportDone:"✅ रिपोर्ट हो गई! धन्यवाद।", analyzing:"जांच हो रही है...", loginNow:"लॉगिन करें →", register:"रजिस्टर करें", logout:"लॉगआउट", history:"इतिहास" },
  ta: { channel:"சேனல்", placeholder:"சந்தேகமான செய்தியை இங்கே ஒட்டுங்கள்...", loginRequired:"பகுப்பாய்வு செய்ய முதலில் login செய்யுங்கள்.", redFlags:"அபாய அறிகுறிகள்", analysis:"பகுப்பாய்வு", whatToDo:"நீங்கள் என்ன செய்ய வேண்டும்", reportBtn:"🚩 சமுதாயத்திற்கு தெரிவிக்கவும்", reportDone:"✅ தெரிவிக்கப்பட்டது! நன்றி.", analyzing:"பகுப்பாய்வு செய்கிறோம்...", loginNow:"உள்நுழையுங்கள் →", register:"பதிவு செய்யுங்கள்", logout:"வெளியேறு", history:"வரலாறு" },
};

const CHANNELS = ["SMS","WhatsApp","Email","URL"];
const API_BASE  = import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000";

const threatColor = level => {
  if (level==="DANGEROUS"||level==="DANGER")   return { bg:"#ff2d2d12", border:"#ff2d2d", text:"#ff4444" };
  if (level==="SUSPICIOUS"||level==="WARNING") return { bg:"#ffb30012", border:"#ffb300", text:"#ffcc00" };
  if (level === "SAFE") return { bg:"#00e57612", border:"#00e576", text:"#00e576" };
  return { bg:"#88888812", border:"#888888", text:"#aaaaaa" };
};

// ── Auth Modal (outside main to fix cursor bug) ────────────────────────────────
function AuthModal({ authMode, setAuthMode, onSuccess, onClose }) {
  const [email, setEmail]     = useState("");
  const [password, setPassword] = useState("");
  const [error, setError]     = useState("");
  const [loading, setLoading] = useState(false);
  const [step, setStep]       = useState("auth");
  const [otp, setOtp]         = useState("");
  const [newPass, setNewPass] = useState("");
  const [notice, setNotice] = useState("");
  const emailRef = useRef(null);
  const requestRef = useRef(null);
  useEffect(() => {
    const timer = setTimeout(() => emailRef.current?.focus(), 50);
    return () => { clearTimeout(timer); requestRef.current?.abort(); };
  }, []);

  const runAuth = async task => {
    if (requestRef.current) return;
    const controller = new AbortController();
    requestRef.current = controller;
    setLoading(true); setError(""); setNotice("");
    try {
      await task(controller.signal);
    } catch (err) {
      if (!controller.signal.aborted) setError(errorMessage(err));
    } finally {
      if (requestRef.current === controller) requestRef.current = null;
      if (!controller.signal.aborted) setLoading(false);
    }
  };

  const login = async (secret, signal, completedAction = "") => {
    try {
      const form = new FormData(); form.append("username", email.trim()); form.append("password", secret);
      const res = await fetch(`${API_BASE}/auth/login`, { method:"POST", body:form, signal });
      const data = validateAuth(await readResponse(res));
      if (!signal.aborted) onSuccess(data.access_token, data.email);
    } catch (err) {
      if (signal.aborted) return;
      if (completedAction) {
        setStep("auth"); setAuthMode("login"); setPassword(""); setNewPass(""); setOtp("");
        throw new Error(`${completedAction} Automatic login failed: ${errorMessage(err)} Please sign in manually.`);
      }
      throw err;
    }
  };

  const handleForgot = () => {
    if (requestRef.current) return;
    if (!email.trim()) { setError("Enter your email first"); return; }
    return runAuth(async signal => {
      const res = await fetch(`${API_BASE}/auth/forgot-password`, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({email:email.trim()}), signal });
      await readResponse(res, { allowEmpty:true });
      if (!signal.aborted) {
        setNotice("If an account exists, check your email for a reset code."); setStep("otp");
      }
    });
  };

  const handleReset = () => {
    if (requestRef.current) return;
    if (otp.length!==6) { setError("Enter the 6-digit OTP"); return; }
    if (newPass.length<8) { setError("Password must be at least 8 characters"); return; }
    return runAuth(async signal => {
      const res = await fetch(`${API_BASE}/auth/reset-password`, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({email:email.trim(), otp, password:newPass}), signal });
      await readResponse(res, { allowEmpty:true });
      if (!signal.aborted) await login(newPass, signal, "Password reset.");
    });
  };

  const handleSubmit = () => {
    if (requestRef.current) return;
    if (!email.trim()||!password) { setError("Please fill in all fields"); return; }
    if (authMode === "register" && password.length<8) { setError("Password must be at least 8 characters"); return; }
    return runAuth(async signal => {
      if (authMode === "register") {
        const res = await fetch(`${API_BASE}/auth/register`, { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({email:email.trim(), password}), signal });
        await readResponse(res, { allowEmpty:true });
        if (!signal.aborted) await login(password, signal, "Account created.");
      } else {
        await login(password, signal);
      }
    });
  };

  const close = () => { requestRef.current?.abort(); onClose(); };

  const inp = {width:"100%",padding:"0.75rem 1rem",background:"rgba(255,255,255,0.04)",border:"1px solid #2a2a2a",borderRadius:"8px",color:"#ddd",fontFamily:"inherit",fontSize:"0.9rem",outline:"none",boxSizing:"border-box"};
  const lbl = {display:"block",fontSize:"0.68rem",color:"#555",letterSpacing:"1px",marginBottom:"0.4rem"};

  return (
    <div style={{position:"fixed",inset:0,background:"rgba(0,0,0,0.87)",zIndex:100,display:"flex",alignItems:"center",justifyContent:"center",backdropFilter:"blur(4px)"}} onClick={e=>e.target===e.currentTarget&&close()}>
      <div style={{background:"#111",border:"1px solid rgba(0,229,118,0.15)",borderRadius:"16px",padding:"1.8rem",width:"min(380px,90vw)",fontFamily:"'Courier New',monospace",boxShadow:"0 0 60px rgba(0,229,118,0.08)"}}>
        {step==="otp" ? (<>
          <div style={{textAlign:"center",marginBottom:"1.5rem"}}>
            <div style={{fontSize:"2rem",marginBottom:"0.5rem"}}>📧</div>
            <div style={{fontWeight:700,color:"#00e576",fontSize:"1rem"}}>Check Your Email</div>
            <div style={{fontSize:"0.75rem",color:"#555",marginTop:"0.3rem"}}>Reset code for {email}</div>
          </div>
          <label style={lbl}>6-DIGIT OTP</label>
          <input disabled={loading} value={otp} onChange={e=>setOtp(e.target.value.replace(/[^0-9]/g,"").slice(0,6))} placeholder="123456" type="text" maxLength={6} style={{...inp,marginBottom:"1rem",fontSize:"1.5rem",letterSpacing:"8px",textAlign:"center"}} onKeyDown={e=>e.key==="Enter"&&handleReset()} autoFocus />
          <label style={lbl}>NEW PASSWORD</label>
          <input disabled={loading} value={newPass} onChange={e=>setNewPass(e.target.value)} placeholder="Minimum 8 characters" type="password" style={{...inp,marginBottom:"1.2rem"}} onKeyDown={e=>e.key==="Enter"&&handleReset()} />
          {(error || notice) && <div role={error ? "alert" : "status"} style={{padding:"0.6rem 0.8rem",borderRadius:"8px",marginBottom:"1rem",border:"1px solid #333",color:error ? "#ff6b6b" : "#00e576",fontSize:"0.8rem"}}>{error || notice}</div>}
          <button onClick={handleReset} disabled={loading} style={{width:"100%",padding:"0.85rem",background:loading?"#1a1a1a":"linear-gradient(135deg,#00e576,#00b8d4)",border:"none",borderRadius:"10px",color:loading?"#444":"#0a0a0f",fontWeight:700,cursor:loading?"not-allowed":"pointer",fontFamily:"inherit",fontSize:"0.88rem"}}>
            {loading?"⏳ Resetting...":"Reset Password →"}
          </button>
          <button disabled={loading} onClick={()=>{setStep("auth");setAuthMode("login");setError("");setNotice("");setOtp("");}} style={{width:"100%",padding:"0.5rem",marginTop:"0.5rem",background:"none",border:"none",color:"#333",cursor:"pointer",fontFamily:"inherit",fontSize:"0.78rem"}}>← Back to Login</button>
        </>) : (<>
          <div style={{display:"flex",marginBottom:"1.5rem",borderBottom:"1px solid #1e1e1e"}}>
            {["login","register"].map(mode=>(
              <button key={mode} disabled={loading} onClick={()=>{setAuthMode(mode);setError("");setNotice("");}}
                style={{flex:1,padding:"0.7rem",background:"none",border:"none",borderBottom:`2px solid ${authMode===mode?"#00e576":"transparent"}`,color:authMode===mode?"#00e576":"#444",cursor:"pointer",fontFamily:"inherit",fontSize:"0.82rem",fontWeight:authMode===mode?700:400,textTransform:"uppercase",letterSpacing:"1px"}}>
                {mode==="login"?"🔑 Login":"📝 Register"}
              </button>
            ))}
          </div>
          <label style={lbl}>EMAIL</label>
          <input disabled={loading} ref={emailRef} value={email} onChange={e=>setEmail(e.target.value)} placeholder="you@gmail.com" type="email" autoComplete="email" style={{...inp,marginBottom:"1rem"}} onKeyDown={e=>e.key==="Enter"&&handleSubmit()} />
          <label style={lbl}>PASSWORD</label>
          <input disabled={loading} value={password} onChange={e=>setPassword(e.target.value)} placeholder="Minimum 8 characters" type="password" autoComplete={authMode==="login"?"current-password":"new-password"} style={{...inp,marginBottom:authMode==="login"?"0.4rem":"1.2rem"}} onKeyDown={e=>e.key==="Enter"&&handleSubmit()} />
          {authMode==="login"&&<div style={{textAlign:"right",marginBottom:"1rem"}}><button disabled={loading} onClick={handleForgot} style={{background:"none",border:"none",color:"#444",cursor:"pointer",fontFamily:"inherit",fontSize:"0.72rem",textDecoration:"underline"}}>Forgot password?</button></div>}
          {(error || notice) && <div role={error ? "alert" : "status"} style={{padding:"0.6rem 0.8rem",borderRadius:"8px",marginBottom:"1rem",border:"1px solid #333",color:error ? "#ff6b6b" : "#00e576",fontSize:"0.8rem"}}>{error || notice}</div>}
          <button onClick={handleSubmit} disabled={loading} style={{width:"100%",padding:"0.85rem",background:loading?"#1a1a1a":"linear-gradient(135deg,#00e576,#00b8d4)",border:"none",borderRadius:"10px",color:loading?"#444":"#0a0a0f",fontWeight:700,cursor:loading?"not-allowed":"pointer",fontFamily:"inherit",fontSize:"0.88rem"}}>
            {loading?"⏳ Please wait...":authMode==="login"?"Login →":"Create Account →"}
          </button>
          <button onClick={close} style={{width:"100%",padding:"0.5rem",marginTop:"0.5rem",background:"none",border:"none",color:"#333",cursor:"pointer",fontFamily:"inherit",fontSize:"0.78rem"}}>Cancel</button>
        </>)}
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────
export default function TrapCheck() {
  const [messages, setMessages]       = useState([]);
  const [input, setInput]             = useState("");
  const [loading, setLoading]         = useState(false);
  const [language, setLanguage]       = useState(LANGUAGES[0]);
  const [channel, setChannel]         = useState(CHANNELS[0]);
  const [started, setStarted]         = useState(false);
  const [token, setToken]             = useState(null);
  const [userEmail, setUserEmail]     = useState(null);
  const [showAuth, setShowAuth]       = useState(false);
  const [authMode, setAuthMode]       = useState("login");
  const [showHistory, setShowHistory] = useState(false);
  const [reported, setReported]       = useState({});
  const [reportErrors, setReportErrors] = useState({});
  const [reporting, setReporting] = useState({});
  const sessionRef = useRef(0);
  const analysisRef = useRef(null);
  const reportsRef = useRef(new Map());
  const nextMessageId = useRef(0);
  const bottomRef = useRef(null);
  const inputRef  = useRef(null);

  // Current language UI labels
  const L = UI[language.code] || UI.en;

  useEffect(() => { bottomRef.current?.scrollIntoView({behavior:"smooth"}); }, [messages, loading]);

  const cancelRequests = useCallback(() => {
    sessionRef.current += 1;
    analysisRef.current?.abort();
    analysisRef.current = null;
    reportsRef.current.forEach(controller => controller?.abort());
    reportsRef.current.clear();
  }, []);

  useEffect(() => cancelRequests, [cancelRequests]);

  const clearPrivateState = useCallback(() => {
    cancelRequests();
    setMessages([]); setInput(""); setLoading(false);
    setReported({}); setReporting({}); setReportErrors({}); setShowHistory(false);
  }, [cancelRequests]);

  const logout = useCallback(() => {
    clearPrivateState(); setToken(null); setUserEmail(null); setShowAuth(false);
  }, [clearPrivateState]);

  const expireSession = useCallback(() => {
    logout();
    setMessages([{role:"assistant", type:"login_required", content:"Session expired. Please login again."}]);
    setAuthMode("login"); setShowAuth(true);
  }, [logout]);

  const handleAuthSuccess = useCallback((accessToken, email) => {
    clearPrivateState();
    setToken(accessToken); setUserEmail(email); setShowAuth(false);
    setMessages([{role:"assistant",type:"greeting",content:`Logged in as ${email}. Messages are sent to the backend for local-model analysis and stored in your scan history.`}]);
    inputRef.current?.focus();
  }, [clearPrivateState]);

  const startChat = lang => { setLanguage(lang); setStarted(true); setMessages([{role:"assistant",content:lang.greeting,type:"greeting"}]); };

  const reportScam = async msg => {
    if (!token) { setShowAuth(true); return; }
    if (reportsRef.current.has(msg.id)) return;
    const controller = new AbortController();
    const session = sessionRef.current;
    reportsRef.current.set(msg.id, controller);
    setReporting(prev => ({...prev, [msg.id]:true}));
    setReportErrors(prev => ({...prev, [msg.id]:""}));
    try {
      const res = await fetch(`${API_BASE}/report`, {
        method:"POST", signal:controller.signal,
        headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body:JSON.stringify({scam_text:msg.submission.message, category:msg.parsed.matched_scam_type||"Unknown", language:msg.submission.language, channel:msg.submission.channel})
      });
      await readResponse(res, { allowEmpty:true });
      if (session !== sessionRef.current || controller.signal.aborted) return;
      reportsRef.current.set(msg.id, null);
      setReported(prev => ({...prev, [msg.id]:true}));
    } catch (err) {
      if (session !== sessionRef.current || controller.signal.aborted) return;
      reportsRef.current.delete(msg.id);
      if (err.status === 401) { expireSession(); return; }
      setReportErrors(prev => ({...prev, [msg.id]:`Report not confirmed: ${errorMessage(err)}`}));
    } finally {
      if (session === sessionRef.current && !controller.signal.aborted) {
        setReporting(prev => ({...prev, [msg.id]:false}));
      }
    }
  };

  const analyzeMessage = async retry => {
    if (analysisRef.current) return;
    const submission = retry?.submission || {message:input.trim(), channel, language:language.code};
    if (!submission.message) return;
    if (!token) { setShowAuth(true); return; }
    const controller = new AbortController();
    const session = sessionRef.current;
    const id = retry?.id ?? nextMessageId.current++;
    analysisRef.current = controller;
    setLoading(true);
    if (retry) {
      setMessages(prev => prev.map(msg => msg.id === id ? {...msg, type:"pending"} : msg));
    } else {
      setInput("");
      setMessages(prev => [...prev,
        {role:"user", content:submission.message, channel:submission.channel},
        {id, role:"assistant", type:"pending", submission}
      ]);
    }
    try {
      const res = await fetch(`${API_BASE}/analyze`, {
        method:"POST", signal:controller.signal,
        headers:{"Content-Type":"application/json","Authorization":`Bearer ${token}`},
        body:JSON.stringify(submission)
      });
      const data = validateAnalysis(await readResponse(res));
      if (session !== sessionRef.current || controller.signal.aborted) return;
      setMessages(prev => prev.map(msg => msg.id === id ? {...msg, parsed:data, type:"analysis"} : msg));
    } catch (err) {
      if (session !== sessionRef.current || controller.signal.aborted) return;
      if (err.status === 401) { expireSession(); return; }
      setMessages(prev => prev.map(msg => msg.id === id ? {...msg, type:"error", content:errorMessage(err)} : msg));
    } finally {
      if (session === sessionRef.current && !controller.signal.aborted) {
        analysisRef.current = null;
        setLoading(false); inputRef.current?.focus();
      }
    }
  };

  if (showHistory) return <History key={token} token={token} userEmail={userEmail} onBack={()=>setShowHistory(false)} onUnauthorized={expireSession} />;

  if (!started) return (
    <div style={{minHeight:"100vh",background:"#0a0a0f",display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",fontFamily:"'Courier New',monospace",padding:"2rem"}}>
      <div style={{position:"fixed",inset:0,backgroundImage:"linear-gradient(rgba(0,229,118,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,118,0.03) 1px,transparent 1px)",backgroundSize:"40px 40px"}}/>
      <div style={{position:"relative",zIndex:1,textAlign:"center",maxWidth:600}}>
        <div style={{width:80,height:80,margin:"0 auto 2rem",background:"linear-gradient(135deg,#00e576,#00b8d4)",borderRadius:"20px",display:"flex",alignItems:"center",justifyContent:"center",fontSize:36,boxShadow:"0 0 60px rgba(0,229,118,0.3)"}}>🛡️</div>
        <h1 style={{fontSize:"clamp(2.5rem,6vw,4rem)",fontWeight:900,margin:"0 0 0.5rem",background:"linear-gradient(135deg,#00e576 0%,#00b8d4 50%,#fff 100%)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent",letterSpacing:"-2px"}}>TrapCheck</h1>
        <p style={{color:"#555",fontSize:"0.8rem",letterSpacing:"4px",marginBottom:"0.5rem",textTransform:"uppercase"}}>AI-Powered Scam Detector</p>
        <p style={{color:"#333",fontSize:"0.78rem",marginBottom:"3rem"}}>Multi-channel · Telugu · Hindi · Tamil · English · Local-model analysis</p>
        <p style={{color:"#666",fontSize:"0.85rem",marginBottom:"1.5rem"}}>Choose your language / భాష ఎంచుకోండి / भाषा चुनें</p>
        <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:"1rem",maxWidth:380,margin:"0 auto 3rem"}}>
          {LANGUAGES.map(lang=>(
            <button key={lang.code} onClick={()=>startChat(lang)}
              style={{padding:"1.1rem",background:"rgba(255,255,255,0.02)",border:"1px solid rgba(0,229,118,0.15)",borderRadius:"12px",color:"#fff",cursor:"pointer",fontSize:"1rem",fontFamily:"inherit",transition:"all 0.2s"}}
              onMouseEnter={e=>{e.currentTarget.style.background="rgba(0,229,118,0.07)";e.currentTarget.style.borderColor="#00e576";e.currentTarget.style.transform="translateY(-2px)";}}
              onMouseLeave={e=>{e.currentTarget.style.background="rgba(255,255,255,0.02)";e.currentTarget.style.borderColor="rgba(0,229,118,0.15)";e.currentTarget.style.transform="none";}}>
              <div style={{fontSize:"1.4rem",marginBottom:"0.4rem"}}>🇮🇳</div>{lang.label}
            </button>
          ))}
        </div>
        <div style={{display:"flex",gap:"1rem",justifyContent:"center",flexWrap:"wrap"}}>
          {["UPI Fraud","KYC Scams","OTP Theft","Fake Jobs","Phishing URLs"].map(tag=>(
            <span key={tag} style={{fontSize:"0.7rem",color:"#333",letterSpacing:"1px",padding:"0.3rem 0.8rem",border:"1px solid #1a1a1a",borderRadius:"100px"}}>{tag}</span>
          ))}
        </div>
      </div>
    </div>
  );

  return (
    <div style={{minHeight:"100vh",background:"#0a0a0f",fontFamily:"'Courier New',monospace",display:"flex",flexDirection:"column"}}>
      {showAuth&&<AuthModal authMode={authMode} setAuthMode={setAuthMode} onSuccess={handleAuthSuccess} onClose={()=>setShowAuth(false)}/>}
      <div style={{position:"fixed",inset:0,zIndex:0,backgroundImage:"linear-gradient(rgba(0,229,118,0.02) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,118,0.02) 1px,transparent 1px)",backgroundSize:"40px 40px"}}/>

      {/* Header */}
      <div style={{position:"sticky",top:0,zIndex:10,background:"rgba(10,10,15,0.97)",backdropFilter:"blur(20px)",borderBottom:"1px solid rgba(0,229,118,0.08)",padding:"0.8rem 1.5rem",display:"flex",alignItems:"center",justifyContent:"space-between"}}>
        <div style={{display:"flex",alignItems:"center",gap:"0.8rem"}}>
          <span style={{fontSize:"1.4rem"}}>🛡️</span>
          <div>
            <div style={{fontWeight:900,fontSize:"1rem",background:"linear-gradient(135deg,#00e576,#00b8d4)",WebkitBackgroundClip:"text",WebkitTextFillColor:"transparent"}}>TrapCheck</div>
            <div style={{fontSize:"0.6rem",color:"#333",letterSpacing:"2px"}}>SCAM ANALYSIS</div>
          </div>
        </div>
        <div style={{display:"flex",gap:"0.4rem",alignItems:"center",flexWrap:"wrap"}}>
          {LANGUAGES.map(lang=>(
            <button key={lang.code} onClick={()=>setLanguage(lang)} style={{padding:"0.25rem 0.55rem",fontSize:"0.68rem",background:language.code===lang.code?"rgba(0,229,118,0.1)":"transparent",border:`1px solid ${language.code===lang.code?"#00e576":"#1e1e1e"}`,borderRadius:"6px",color:language.code===lang.code?"#00e576":"#444",cursor:"pointer",fontFamily:"inherit"}}>{lang.label}</button>
          ))}
          {userEmail ? (
            <div style={{display:"flex",alignItems:"center",gap:"0.4rem"}}>
              <span style={{fontSize:"0.68rem",color:"#00e576",padding:"0.25rem 0.6rem",border:"1px solid rgba(0,229,118,0.25)",borderRadius:"6px"}}>👤 {userEmail.split("@")[0]}</span>
              <button onClick={()=>setShowHistory(true)} style={{fontSize:"0.65rem",color:"#00b8d4",background:"none",border:"1px solid rgba(0,184,212,0.2)",borderRadius:"5px",cursor:"pointer",fontFamily:"inherit",padding:"0.15rem 0.5rem"}}>{L.history}</button>
              <button onClick={logout} style={{fontSize:"0.65rem",color:"#333",background:"none",border:"none",cursor:"pointer",fontFamily:"inherit"}}>{L.logout}</button>
            </div>
          ) : (
            <button onClick={()=>{setAuthMode("login");setShowAuth(true);}} style={{fontSize:"0.68rem",color:"#00e576",padding:"0.25rem 0.7rem",border:"1px solid rgba(0,229,118,0.3)",borderRadius:"6px",background:"rgba(0,229,118,0.05)",cursor:"pointer",fontFamily:"inherit",fontWeight:700}}>Login</button>
          )}
        </div>
      </div>

      {/* Messages */}
      <div style={{flex:1,overflowY:"auto",padding:"1.5rem",position:"relative",zIndex:1}}>
        <div style={{maxWidth:720,margin:"0 auto",display:"flex",flexDirection:"column",gap:"1.5rem"}}>
          {messages.map((msg,i)=>msg.type === "pending" ? null : (
            <div key={i} style={{display:"flex",flexDirection:msg.role==="user"?"row-reverse":"row",gap:"0.8rem",alignItems:"flex-start"}}>
              <div style={{width:34,height:34,borderRadius:"10px",flexShrink:0,background:msg.role==="user"?"rgba(255,255,255,0.04)":"linear-gradient(135deg,#00e576,#00b8d4)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:"0.9rem",border:msg.role==="user"?"1px solid #1e1e1e":"none"}}>
                {msg.role==="user"?"👤":"🛡️"}
              </div>
              <div style={{maxWidth:"85%",flex:1}}>
                {msg.role==="user"&&(<>
                  <div style={{textAlign:"right",marginBottom:"0.3rem"}}><span style={{fontSize:"0.62rem",color:"#333",padding:"0.15rem 0.5rem",border:"1px solid #1e1e1e",borderRadius:"100px"}}>via {msg.channel}</span></div>
                  <div style={{background:"rgba(255,255,255,0.03)",border:"1px solid #1e1e1e",borderRadius:"12px 4px 12px 12px",padding:"0.8rem 1rem",color:"#bbb",fontSize:"0.9rem",lineHeight:1.6,wordBreak:"break-word"}}>{msg.content}</div>
                </>)}
                {msg.type==="greeting"&&<div style={{background:"rgba(0,229,118,0.04)",border:"1px solid rgba(0,229,118,0.1)",borderRadius:"4px 12px 12px 12px",padding:"0.8rem 1rem",color:"#888",fontSize:"0.9rem",lineHeight:1.7}}>{msg.content}</div>}
                {msg.type==="error"&&<div role="alert" style={{background:"rgba(255,45,45,0.05)",border:"1px solid rgba(255,45,45,0.2)",borderRadius:"4px 12px 12px 12px",padding:"0.8rem 1rem",color:"#ff6b6b",fontSize:"0.88rem",lineHeight:1.6}}>
                  {msg.content}
                  <button disabled={loading} onClick={()=>analyzeMessage(msg)} style={{display:"block",marginTop:"0.5rem",background:"none",border:"1px solid #555",borderRadius:"6px",padding:"0.3rem 0.8rem",color:"#ccc",fontFamily:"inherit",cursor:"pointer"}}>Retry analysis</button>
                </div>}
                {msg.type==="login_required"&&(
                  <div style={{background:"rgba(255,179,0,0.05)",border:"1px solid rgba(255,179,0,0.2)",borderRadius:"4px 12px 12px 12px",padding:"1rem 1.2rem"}}>
                    <p style={{color:"#ffb300",fontSize:"0.88rem",margin:"0 0 0.8rem",lineHeight:1.6}}>🔐 {msg.content}</p>
                    <button onClick={()=>{setAuthMode("login");setShowAuth(true);}} style={{padding:"0.5rem 1.2rem",background:"linear-gradient(135deg,#00e576,#00b8d4)",border:"none",borderRadius:"8px",color:"#0a0a0f",fontWeight:700,cursor:"pointer",fontFamily:"inherit",fontSize:"0.82rem"}}>{L.loginNow}</button>
                    <button onClick={()=>{setAuthMode("register");setShowAuth(true);}} style={{marginLeft:"0.6rem",padding:"0.5rem 1.2rem",background:"transparent",border:"1px solid #333",borderRadius:"8px",color:"#666",cursor:"pointer",fontFamily:"inherit",fontSize:"0.82rem"}}>{L.register}</button>
                  </div>
                )}
                {msg.type==="analysis"&&msg.parsed&&(()=>{
                  const c=threatColor(msg.parsed.threat_level);
                  return(
                    <div style={{background:c.bg,border:`1px solid ${c.border}25`,borderRadius:"4px 12px 12px 12px",padding:"1.2rem",borderLeft:`3px solid ${c.border}`}}>
                      <div style={{display:"flex",alignItems:"center",gap:"0.8rem",marginBottom:"1rem"}}>
                        <span style={{fontSize:"1.6rem"}}>{msg.parsed.threat_emoji}</span>
                        <div>
                          <span style={{fontSize:"0.72rem",fontWeight:700,letterSpacing:"2px",color:c.text,padding:"0.2rem 0.8rem",background:`${c.text}18`,borderRadius:"100px",border:`1px solid ${c.text}35`}}>{msg.parsed.threat_level}</span>
                          {msg.parsed.matched_scam_type&&<span style={{fontSize:"0.7rem",color:"#444",marginLeft:"0.5rem"}}>· {msg.parsed.matched_scam_type}</span>}
                          {msg.parsed.saved_to_history === false && <span style={{fontSize:"0.65rem",color:"#ffb300",marginLeft:"0.5rem"}}>Not saved to history</span>}
                          {msg.parsed.saved_to_history&&<span style={{fontSize:"0.65rem",color:"#00e576",marginLeft:"0.5rem"}}>· ✅ saved</span>}
                        </div>
                      </div>
                      <p style={{color:"#ddd",fontSize:"0.95rem",fontWeight:600,marginBottom:"1rem",lineHeight:1.6}}>{msg.parsed.summary}</p>
                      {Array.isArray(msg.parsed.red_flags)&&msg.parsed.red_flags.length>0&&(
                        <div style={{marginBottom:"1rem"}}>
                          <div style={{fontSize:"0.65rem",color:"#444",letterSpacing:"2px",marginBottom:"0.5rem"}}>{L.redFlags}</div>
                          {msg.parsed.red_flags.map((flag,fi)=>(
                            <div key={fi} style={{display:"flex",gap:"0.5rem",marginBottom:"0.3rem"}}>
                              <span style={{color:c.text,fontSize:"0.75rem"}}>▸</span>
                              <span style={{color:"#999",fontSize:"0.84rem"}}>{flag}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      <div style={{marginBottom:"1rem"}}>
                        <div style={{fontSize:"0.65rem",color:"#444",letterSpacing:"2px",marginBottom:"0.5rem"}}>{L.analysis}</div>
                        <p style={{color:"#888",fontSize:"0.84rem",lineHeight:1.7,margin:0}}>{msg.parsed.explanation}</p>
                      </div>
                      <div style={{background:"rgba(255,255,255,0.02)",borderRadius:"8px",padding:"0.85rem",border:"1px solid #161616",marginBottom:"0.8rem"}}>
                        <div style={{fontSize:"0.65rem",color:"#444",letterSpacing:"2px",marginBottom:"0.4rem"}}>{L.whatToDo}</div>
                        <p style={{color:"#bbb",fontSize:"0.84rem",lineHeight:1.6,margin:0}}>{msg.parsed.action}</p>
                      </div>
                      {/* Feature 4: Report button */}
                      <div style={{borderTop:"1px solid #161616",paddingTop:"0.7rem"}}>
                        <button
                          onClick={()=>reportScam(msg)}
                          disabled={reported[msg.id] || reporting[msg.id]}
                          style={{fontSize:"0.72rem",color:reported[msg.id]?"#00e576":"#888",background:"none",border:`1px solid ${reported[msg.id]?"rgba(0,229,118,0.2)":"#1e1e1e"}`,borderRadius:"6px",padding:"0.3rem 0.8rem",cursor:reported[msg.id]||reporting[msg.id]?"default":"pointer",fontFamily:"inherit",transition:"all 0.2s"}}>
                          {reporting[msg.id] ? "Reporting..." : reported[msg.id] ? L.reportDone : reportErrors[msg.id] ? "Retry report" : L.reportBtn}
                        </button>
                        {reportErrors[msg.id] && <p role="alert" style={{color:"#ff6b6b",fontSize:"0.78rem",margin:"0.5rem 0 0"}}>{reportErrors[msg.id]}</p>}
                      </div>
                    </div>
                  );
                })()}
              </div>
            </div>
          ))}
          {loading&&(
            <div style={{display:"flex",gap:"0.8rem",alignItems:"flex-start"}}>
              <div style={{width:34,height:34,borderRadius:"10px",background:"linear-gradient(135deg,#00e576,#00b8d4)",display:"flex",alignItems:"center",justifyContent:"center"}}>🛡️</div>
              <div style={{background:"rgba(0,229,118,0.04)",border:"1px solid rgba(0,229,118,0.1)",borderRadius:"4px 12px 12px 12px",padding:"0.9rem 1.2rem"}}>
                <div style={{display:"flex",gap:"5px",alignItems:"center",marginBottom:"0.5rem"}}>
                  {[0,1,2].map(i=><div key={i} style={{width:5,height:5,borderRadius:"50%",background:"#00e576",animation:"pulse 1.2s ease-in-out infinite",animationDelay:`${i*0.2}s`}}/>)}
                </div>
                <p style={{color:"#00e576",fontSize:"0.78rem",margin:0}}>{L.analyzing}</p>
                <p style={{color:"#252525",fontSize:"0.66rem",margin:"0.3rem 0 0"}}>Messages go to the backend for local-model analysis and stored scan history.</p>
              </div>
            </div>
          )}
          <div ref={bottomRef}/>
        </div>
      </div>

      {/* Input bar */}
      <div style={{position:"sticky",bottom:0,zIndex:10,background:"rgba(10,10,15,0.98)",backdropFilter:"blur(20px)",borderTop:"1px solid rgba(0,229,118,0.06)",padding:"1rem 1.5rem"}}>
        <div style={{maxWidth:720,margin:"0 auto"}}>
          <div style={{display:"flex",gap:"0.4rem",marginBottom:"0.7rem",alignItems:"center"}}>
            <span style={{fontSize:"0.65rem",color:"#333",letterSpacing:"1px"}}>{L.channel}:</span>
            {CHANNELS.map(ch=>(
              <button key={ch} onClick={()=>setChannel(ch)} style={{padding:"0.2rem 0.6rem",fontSize:"0.7rem",background:channel===ch?"rgba(0,229,118,0.1)":"transparent",border:`1px solid ${channel===ch?"#00e576":"#1a1a1a"}`,borderRadius:"5px",color:channel===ch?"#00e576":"#383838",cursor:"pointer",fontFamily:"inherit"}}>{ch}</button>
            ))}
            {!userEmail&&<span style={{marginLeft:"auto",fontSize:"0.65rem",color:"#ffb300"}}>⚠️ Login required</span>}
          </div>
          <div style={{display:"flex",gap:"0.7rem"}}>
            <textarea ref={inputRef} value={input} onChange={e=>setInput(e.target.value)}
              onKeyDown={e=>{if(e.key==="Enter"&&!e.shiftKey&&!e.nativeEvent.isComposing){e.preventDefault();analyzeMessage();}}}
              placeholder={!userEmail?"Login first, then paste suspicious message here...":L.placeholder}
              style={{flex:1,background:"rgba(255,255,255,0.02)",border:`1px solid ${input?"rgba(0,229,118,0.2)":"#1a1a1a"}`,borderRadius:"10px",padding:"0.8rem 1rem",color:"#ccc",fontFamily:"inherit",fontSize:"0.9rem",resize:"none",minHeight:56,outline:"none",lineHeight:1.6}}
              rows={2}/>
            <button aria-label="Analyze message" onClick={()=>analyzeMessage()} disabled={loading||!input.trim()} style={{width:54,height:56,borderRadius:"10px",border:"none",background:loading||!input.trim()?"#131313":"linear-gradient(135deg,#00e576,#00b8d4)",color:loading||!input.trim()?"#2a2a2a":"#0a0a0f",cursor:loading||!input.trim()?"not-allowed":"pointer",fontSize:"1.2rem",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
              {loading?"⏳":"🔍"}
            </button>
          </div>
          <p style={{fontSize:"0.62rem",color:"#252525",textAlign:"center",marginTop:"0.5rem"}}>
            {userEmail?`✅ ${userEmail} · `:""}Press Enter to analyze · Shift+Enter for new line
          </p>
        </div>
      </div>
      <style>{`@keyframes pulse{0%,100%{opacity:0.3;transform:scale(0.8)}50%{opacity:1;transform:scale(1.2)}}*{box-sizing:border-box}::-webkit-scrollbar{width:3px}::-webkit-scrollbar-thumb{background:#1a1a1a;border-radius:2px}input:focus,textarea:focus{border-color:rgba(0,229,118,0.35)!important}`}</style>
    </div>
  );
}