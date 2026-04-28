import { useState, useRef } from "react";

const CLAUDE_MODEL = "claude-sonnet-4-20250514";

const FIELD_PRESETS = {
  "Generic Netflow": { src: "src_addr", dst: "dst_addr", port: "dst_port", proto: "proto", bytes: "in_bytes" },
  "Fortinet": { src: "srcip", dst: "dstip", port: "dstport", proto: "proto", bytes: "sentbyte" },
  "pfSense/OPNsense": { src: "src", dst: "dst", port: "dest_port", proto: "proto", bytes: "ipbytes" },
  "Cisco ASA": { src: "sourceAddress", dst: "destinationAddress", port: "destinationPort", proto: "protocol", bytes: "bytesIn" },
  "Custom": { src: "", dst: "", port: "", proto: "", bytes: "" },
};

const PROTO_MAP = { 1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 132: "SCTP" };
const PRIVATE = ["10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168."];

function isPrivate(ip) {
  return PRIVATE.some(p => ip.startsWith(p));
}

function toSubnet24(ip) {
  const parts = ip.split(".");
  if (parts.length < 3) return null;
  return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
}

function humanBytes(b) {
  b = Number(b) || 0;
  if (b < 1024) return `${b} B`;
  if (b < 1048576) return `${(b/1024).toFixed(1)} KB`;
  if (b < 1073741824) return `${(b/1048576).toFixed(1)} MB`;
  return `${(b/1073741824).toFixed(1)} GB`;
}

function parseCSV(text) {
  const lines = text.trim().split("\n");
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map(h => h.trim().replace(/^"|"$/g, "").toLowerCase());
  return lines.slice(1).map(line => {
    const vals = line.split(",").map(v => v.trim().replace(/^"|"$/g, ""));
    const obj = {};
    headers.forEach((h, i) => { obj[h] = vals[i] || ""; });
    return obj;
  });
}

function parseJSON(text) {
  try {
    const data = JSON.parse(text);
    if (Array.isArray(data)) return data;
    if (data.messages) return data.messages.map(m => m.message || m.fields || m);
    return [];
  } catch { return null; }
}

function aggregateRows(rows, fields) {
  const flows = {};
  let skipped = 0;
  for (const row of rows) {
    const srcIp = row[fields.src] || row[fields.src.toLowerCase()] || "";
    const dstIp = row[fields.dst] || row[fields.dst.toLowerCase()] || "";
    const port = row[fields.port] || "0";
    let proto = row[fields.proto] || "";
    const bytes = Number(row[fields.bytes] || 0);

    if (!srcIp || !dstIp || srcIp === "undefined") { skipped++; continue; }

    const protoNum = parseInt(proto);
    if (!isNaN(protoNum)) proto = PROTO_MAP[protoNum] || proto;
    proto = String(proto).toUpperCase();

    const srcSub = toSubnet24(srcIp);
    const dstSub = toSubnet24(dstIp);
    if (!srcSub || !dstSub) { skipped++; continue; }

    const key = `${srcSub}||${dstSub}||${port}||${proto}`;
    if (!flows[key]) flows[key] = { srcSub, dstSub, port, proto, bytes: 0, count: 0, srcIps: new Set(), dstIps: new Set() };
    flows[key].bytes += bytes;
    flows[key].count++;
    flows[key].srcIps.add(srcIp);
    flows[key].dstIps.add(dstIp);
  }
  return { flows: Object.values(flows), skipped };
}

function buildSummary(flows) {
  const internal = flows.filter(f => isPrivate(f.dstSub));
  const internet = flows.filter(f => !isPrivate(f.dstSub));

  const topInternal = [...internal].sort((a, b) => b.bytes - a.bytes).slice(0, 50);
  const topInternet = [...internet].sort((a, b) => b.bytes - a.bytes).slice(0, 50);

  const portCounts = {};
  for (const f of flows) {
    const k = `${f.port}/${f.proto}`;
    portCounts[k] = (portCounts[k] || 0) + f.count;
  }
  const topPorts = Object.entries(portCounts).sort((a, b) => b[1] - a[1]).slice(0, 25);

  let lines = [];
  lines.push(`NETFLOW TRAFFIC SUMMARY`);
  lines.push(`Total flow patterns: ${flows.length} | Internal: ${internal.length} | Internet-bound: ${internet.length}`);
  lines.push("");
  lines.push("=== TOP INTERNAL COMMUNICATIONS ===");
  lines.push("Source /24          Dest /24            Port/Proto   Volume       Flows  SrcIPs");
  for (const f of topInternal) {
    lines.push(`${f.srcSub.padEnd(20)} ${f.dstSub.padEnd(20)} ${`${f.port}/${f.proto}`.padEnd(13)} ${humanBytes(f.bytes).padStart(10)} ${String(f.count).padStart(6)} ${f.srcIps.size}`);
  }
  lines.push("");
  lines.push("=== TOP INTERNET-BOUND COMMUNICATIONS ===");
  lines.push("Source /24          Dest /24            Port/Proto   Volume       Flows");
  for (const f of topInternet) {
    lines.push(`${f.srcSub.padEnd(20)} ${f.dstSub.padEnd(20)} ${`${f.port}/${f.proto}`.padEnd(13)} ${humanBytes(f.bytes).padStart(10)} ${f.count}`);
  }
  lines.push("");
  lines.push("=== TOP PORTS/PROTOCOLS ===");
  for (const [pp, c] of topPorts) {
    lines.push(`  ${pp.padEnd(15)} ${c} flows`);
  }
  return lines.join("\n");
}

async function callClaude(summary, apiKey) {
  const systemPrompt = `You are a senior network security engineer. Analyze Netflow data and produce precise, actionable firewall rules. Think in terms of least privilege, zero-trust, and business justification. Format firewall rules as markdown tables.`;

  const userPrompt = `Analyze this Netflow traffic and recommend firewall rules:

${summary}

Provide:

## 1. TRAFFIC OVERVIEW
What patterns do you see? What services are running? Any segmentation issues?

## 2. SECURITY ZONES
Based on traffic, suggest zones (DMZ, Servers, Clients, Management, etc.). Which subnets belong to each?

## 3. FIREWALL RULES — INTERNAL TRAFFIC
| Priority | Source | Destination | Port/Protocol | Action | Justification |
|---|---|---|---|---|---|

## 4. FIREWALL RULES — INTERNET EGRESS
| Priority | Source | Destination | Port/Protocol | Action | Justification |
|---|---|---|---|---|---|

## 5. DEFAULT DENY BASELINE
What should be blocked by default?

## 6. SECURITY CONCERNS
Flag suspicious patterns, unnecessary lateral movement, anomalies.

## 7. TOP 5 QUICK WINS
Most impactful rules to implement first.

Use the actual subnet data from the traffic. Be specific.`;

  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(apiKey ? { "x-api-key": apiKey } : {})
    },
    body: JSON.stringify({
      model: CLAUDE_MODEL,
      max_tokens: 4096,
      system: systemPrompt,
      messages: [{ role: "user", content: userPrompt }]
    })
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message || `HTTP ${res.status}`);
  }
  const data = await res.json();
  return data.content?.[0]?.text || "";
}

// ── Markdown renderer ──────────────────────────────────────
function renderMd(text) {
  const lines = text.split("\n");
  const result = [];
  let tableBuffer = [];
  let inTable = false;

  const flushTable = () => {
    if (tableBuffer.length < 2) { tableBuffer.forEach(l => result.push(<p key={result.length} style={{margin:"4px 0"}}>{l}</p>)); tableBuffer = []; return; }
    const rows = tableBuffer.map(l => l.split("|").map(c => c.trim()).filter((_, i, a) => i > 0 && i < a.length - 1));
    result.push(
      <div key={result.length} style={{overflowX:"auto",margin:"12px 0"}}>
        <table style={{borderCollapse:"collapse",width:"100%",fontSize:"13px"}}>
          <thead>
            <tr>{rows[0].map((c,i) => <th key={i} style={{background:"#1e3a5f",color:"#7dd3fc",padding:"6px 10px",border:"1px solid #334155",textAlign:"left",whiteSpace:"nowrap"}}>{c}</th>)}</tr>
          </thead>
          <tbody>
            {rows.slice(2).map((row, ri) => (
              <tr key={ri} style={{background: ri%2===0?"#0f172a":"#111827"}}>
                {row.map((c,ci) => {
                  const isAllow = c === "ALLOW" || c === "PERMIT";
                  const isDeny = c === "DENY" || c === "DROP" || c === "BLOCK";
                  return <td key={ci} style={{padding:"5px 10px",border:"1px solid #1e293b",color: isAllow?"#4ade80":isDeny?"#f87171":"#cbd5e1"}}>{c}</td>;
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
    tableBuffer = [];
  };

  for (const line of lines) {
    if (line.startsWith("|")) {
      inTable = true;
      tableBuffer.push(line);
    } else {
      if (inTable) { flushTable(); inTable = false; }
      if (line.startsWith("## ")) {
        result.push(<h2 key={result.length} style={{color:"#7dd3fc",fontSize:"16px",fontWeight:700,margin:"20px 0 8px",borderBottom:"1px solid #1e3a5f",paddingBottom:"4px"}}>{line.slice(3)}</h2>);
      } else if (line.startsWith("### ")) {
        result.push(<h3 key={result.length} style={{color:"#93c5fd",fontSize:"14px",fontWeight:600,margin:"14px 0 6px"}}>{line.slice(4)}</h3>);
      } else if (line.startsWith("- ") || line.startsWith("* ")) {
        result.push(<div key={result.length} style={{color:"#94a3b8",padding:"2px 0 2px 16px",fontSize:"13px"}}>{"• "+line.slice(2)}</div>);
      } else if (line.trim() === "") {
        result.push(<div key={result.length} style={{height:"8px"}} />);
      } else if (line.startsWith("**") && line.endsWith("**")) {
        result.push(<p key={result.length} style={{color:"#e2e8f0",fontWeight:600,margin:"4px 0",fontSize:"13px"}}>{line.slice(2,-2)}</p>);
      } else {
        // Inline bold
        const parts = line.split(/(\*\*[^*]+\*\*)/g);
        const el = parts.map((p, i) => p.startsWith("**") ? <strong key={i} style={{color:"#e2e8f0"}}>{p.slice(2,-2)}</strong> : p);
        result.push(<p key={result.length} style={{color:"#94a3b8",margin:"3px 0",fontSize:"13px",lineHeight:"1.5"}}>{el}</p>);
      }
    }
  }
  if (inTable) flushTable();
  return result;
}

// ── Main App ───────────────────────────────────────────────
export default function App() {
  const [step, setStep] = useState(1);
  const [preset, setPreset] = useState("Generic Netflow");
  const [fields, setFields] = useState(FIELD_PRESETS["Generic Netflow"]);
  const [rawData, setRawData] = useState("");
  const [dataFormat, setDataFormat] = useState("csv");
  const [parsedRows, setParsedRows] = useState(null);
  const [summary, setSummary] = useState("");
  const [analysis, setAnalysis] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [parseError, setParseError] = useState("");
  const textRef = useRef();

  const handlePreset = (p) => {
    setPreset(p);
    setFields({ ...FIELD_PRESETS[p] });
  };

  const handleParse = () => {
    setParseError("");
    if (!rawData.trim()) { setParseError("Paste some data first."); return; }
    let rows;
    if (dataFormat === "json") {
      rows = parseJSON(rawData);
      if (!rows) { setParseError("Invalid JSON. Make sure it's an array or Graylog export."); return; }
    } else {
      rows = parseCSV(rawData);
    }
    if (rows.length === 0) { setParseError("No rows parsed. Check format and try again."); return; }
    setParsedRows(rows);
    setStep(3);
  };

  const handleAnalyze = async () => {
    setError(""); setLoading(true); setAnalysis("");
    try {
      const { flows, skipped } = aggregateRows(parsedRows, fields);
      if (flows.length === 0) {
        setError(`No flows could be extracted. Check field name mapping. Skipped ${skipped} rows.`);
        setLoading(false); return;
      }
      const sum = buildSummary(flows);
      setSummary(sum);
      const result = await callClaude(sum, apiKey);
      setAnalysis(result);
      setStep(4);
    } catch (e) {
      setError(`Error: ${e.message}`);
    }
    setLoading(false);
  };

  const downloadReport = () => {
    const content = `# Firewall Analysis Report\nGenerated: ${new Date().toISOString()}\n\n---\n\n## Traffic Summary\n\n\`\`\`\n${summary}\n\`\`\`\n\n---\n\n## AI Recommendations\n\n${analysis}`;
    const blob = new Blob([content], { type: "text/markdown" });
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob);
    a.download = `firewall_analysis_${Date.now()}.md`; a.click();
  };

  const steps = ["Konfig", "Data", "Fält", "Analys"];

  return (
    <div style={{minHeight:"100vh",background:"#020817",fontFamily:"'JetBrains Mono', 'Fira Code', monospace",color:"#e2e8f0"}}>
      {/* Header */}
      <div style={{background:"linear-gradient(135deg,#0f172a,#1e3a5f)",padding:"20px 28px",borderBottom:"1px solid #1e3a5f",display:"flex",alignItems:"center",gap:"14px"}}>
        <div style={{width:40,height:40,background:"linear-gradient(135deg,#0ea5e9,#6366f1)",borderRadius:10,display:"flex",alignItems:"center",justifyContent:"center",fontSize:20}}>🔥</div>
        <div>
          <div style={{fontSize:18,fontWeight:700,color:"#f1f5f9",letterSpacing:"-0.5px"}}>Firewall Analyzer</div>
          <div style={{fontSize:11,color:"#475569",marginTop:1}}>Graylog Netflow → Claude AI → Brandväggsregler</div>
        </div>
        {/* Steps */}
        <div style={{marginLeft:"auto",display:"flex",gap:6}}>
          {steps.map((s, i) => (
            <div key={i} style={{padding:"4px 12px",borderRadius:20,fontSize:11,fontWeight:600,
              background: step > i+1 ? "#0ea5e9" : step === i+1 ? "linear-gradient(135deg,#0ea5e9,#6366f1)" : "#1e293b",
              color: step >= i+1 ? "#fff" : "#475569",
              border: step === i+1 ? "1px solid #38bdf8" : "1px solid transparent",
              cursor: step > i+1 ? "pointer" : "default"
            }} onClick={() => step > i+1 && setStep(i+1)}>
              {i+1}. {s}
            </div>
          ))}
        </div>
      </div>

      <div style={{maxWidth:900,margin:"0 auto",padding:"28px 20px"}}>

        {/* ── Step 1: API Key ── */}
        {step === 1 && (
          <div>
            <h2 style={{color:"#7dd3fc",fontSize:20,marginBottom:6}}>Steg 1 — Anthropic API-nyckel</h2>
            <p style={{color:"#64748b",fontSize:13,marginBottom:20}}>
              Nyckeln används enbart för denna analys och skickas direkt till Anthropic. Den lagras inte.
            </p>
            <div style={{background:"#0f172a",border:"1px solid #1e3a5f",borderRadius:12,padding:20,marginBottom:16}}>
              <div style={{fontSize:12,color:"#64748b",marginBottom:8}}>Skaffa API-nyckel på:</div>
              <a href="https://console.anthropic.com" target="_blank" rel="noreferrer"
                style={{color:"#38bdf8",fontSize:13,textDecoration:"none",display:"flex",alignItems:"center",gap:6}}>
                🔗 console.anthropic.com → API Keys → Create Key
              </a>
              <div style={{marginTop:16}}>
                <div style={{fontSize:12,color:"#475569",marginBottom:6}}>Klistra in din API-nyckel:</div>
                <input
                  type="password"
                  placeholder="sk-ant-api03-..."
                  value={apiKey}
                  onChange={e => setApiKey(e.target.value)}
                  style={{width:"100%",background:"#020817",border:"1px solid #334155",borderRadius:8,padding:"10px 14px",color:"#e2e8f0",fontSize:13,outline:"none",boxSizing:"border-box"}}
                />
              </div>
              <div style={{marginTop:12,padding:"10px 14px",background:"#020817",borderRadius:8,border:"1px solid #1e3a5f",fontSize:12,color:"#475569"}}>
                💡 Alternativt: Lämna tomt om du kör Python-skriptet lokalt (det hanterar nyckeln via .env-filen).
                Denna webapp kräver nyckeln för att anropa Claude direkt från browsern.
              </div>
            </div>
            <button onClick={() => setStep(2)}
              style={{background:"linear-gradient(135deg,#0ea5e9,#6366f1)",color:"#fff",border:"none",borderRadius:8,padding:"10px 28px",fontSize:13,fontWeight:600,cursor:"pointer"}}>
              Nästa →
            </button>
          </div>
        )}

        {/* ── Step 2: Paste data ── */}
        {step === 2 && (
          <div>
            <h2 style={{color:"#7dd3fc",fontSize:20,marginBottom:6}}>Steg 2 — Exportera data från Graylog</h2>
            <div style={{background:"#0f172a",border:"1px solid #1e3a5f",borderRadius:12,padding:18,marginBottom:16,fontSize:13,color:"#64748b",lineHeight:1.7}}>
              <strong style={{color:"#93c5fd"}}>Hur du exporterar från Graylog:</strong><br />
              1. Öppna Graylog → Search<br />
              2. Sök: <code style={{background:"#020817",padding:"1px 6px",borderRadius:4,color:"#7dd3fc"}}>*</code> med önskat tidsintervall (t.ex. Last 24 hours)<br />
              3. Klicka <strong style={{color:"#e2e8f0"}}>▼ → Export → CSV</strong> (välj relevanta fält)<br />
              4. Klistra in CSV-innehållet nedan
            </div>
            <div style={{display:"flex",gap:10,marginBottom:12}}>
              {["csv","json"].map(f => (
                <button key={f} onClick={() => setDataFormat(f)}
                  style={{padding:"6px 16px",borderRadius:6,border:"1px solid",fontSize:12,cursor:"pointer",fontFamily:"inherit",
                    background: dataFormat===f ? "#0ea5e9" : "#0f172a",
                    borderColor: dataFormat===f ? "#0ea5e9" : "#334155",
                    color: dataFormat===f ? "#fff" : "#64748b"}}>
                  {f.toUpperCase()}
                </button>
              ))}
            </div>
            <textarea
              ref={textRef}
              value={rawData}
              onChange={e => setRawData(e.target.value)}
              placeholder={dataFormat === "csv"
                ? `timestamp,src_addr,dst_addr,dst_port,proto,in_bytes\n2024-01-15T10:00:00,10.0.1.5,10.0.2.10,443,6,15234\n...`
                : `[{"src_addr":"10.0.1.5","dst_addr":"10.0.2.10","dst_port":443,"proto":6}]`}
              style={{width:"100%",height:200,background:"#020817",border:"1px solid #334155",borderRadius:8,padding:14,color:"#94a3b8",fontSize:12,resize:"vertical",outline:"none",boxSizing:"border-box",fontFamily:"inherit"}}
            />
            {parseError && <div style={{color:"#f87171",fontSize:12,marginTop:8}}>⚠ {parseError}</div>}
            <div style={{display:"flex",gap:10,marginTop:14}}>
              <button onClick={() => setStep(1)} style={{background:"#1e293b",color:"#94a3b8",border:"1px solid #334155",borderRadius:8,padding:"10px 20px",fontSize:13,cursor:"pointer"}}>← Tillbaka</button>
              <button onClick={handleParse} style={{background:"linear-gradient(135deg,#0ea5e9,#6366f1)",color:"#fff",border:"none",borderRadius:8,padding:"10px 28px",fontSize:13,fontWeight:600,cursor:"pointer"}}>
                Parsa data →
              </button>
            </div>
          </div>
        )}

        {/* ── Step 3: Field mapping ── */}
        {step === 3 && (
          <div>
            <h2 style={{color:"#7dd3fc",fontSize:20,marginBottom:6}}>Steg 3 — Fältmappning</h2>
            <p style={{color:"#64748b",fontSize:13,marginBottom:16}}>
              {parsedRows?.length.toLocaleString()} rader parsade. Välj preset eller justera fältnamnen manuellt.
            </p>

            {/* Preset buttons */}
            <div style={{display:"flex",flexWrap:"wrap",gap:8,marginBottom:20}}>
              {Object.keys(FIELD_PRESETS).map(p => (
                <button key={p} onClick={() => handlePreset(p)}
                  style={{padding:"6px 14px",borderRadius:6,border:"1px solid",fontSize:12,cursor:"pointer",fontFamily:"inherit",
                    background: preset===p ? "#0ea5e9" : "#0f172a",
                    borderColor: preset===p ? "#0ea5e9" : "#334155",
                    color: preset===p ? "#fff" : "#94a3b8"}}>
                  {p}
                </button>
              ))}
            </div>

            {/* Field inputs */}
            <div style={{background:"#0f172a",border:"1px solid #1e3a5f",borderRadius:12,padding:18,marginBottom:16}}>
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:12}}>
                {[["src","Source IP-fält","Källans IP-adress"],["dst","Destination IP-fält","Destinationens IP"],["port","Destinationsport","TCP/UDP-port"],["proto","Protokollfält","6=TCP, 17=UDP..."],["bytes","Bytefält (valfritt)","Trafikvolym"]].map(([k, label, hint]) => (
                  <div key={k}>
                    <div style={{fontSize:11,color:"#475569",marginBottom:4}}>{label}</div>
                    <input
                      value={fields[k] || ""}
                      onChange={e => setFields(prev => ({...prev, [k]: e.target.value}))}
                      placeholder={hint}
                      style={{width:"100%",background:"#020817",border:"1px solid #334155",borderRadius:6,padding:"8px 12px",color:"#e2e8f0",fontSize:12,outline:"none",boxSizing:"border-box",fontFamily:"inherit"}}
                    />
                  </div>
                ))}
              </div>
              {/* Show available column names from data */}
              {parsedRows?.[0] && (
                <div style={{marginTop:14,padding:10,background:"#020817",borderRadius:8,border:"1px solid #1e293b"}}>
                  <div style={{fontSize:11,color:"#475569",marginBottom:6}}>Tillgängliga kolumnnamn i din data:</div>
                  <div style={{display:"flex",flexWrap:"wrap",gap:6}}>
                    {Object.keys(parsedRows[0]).map(k => (
                      <span key={k} style={{background:"#1e293b",padding:"2px 8px",borderRadius:4,fontSize:11,color:"#7dd3fc"}}>{k}</span>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {error && <div style={{color:"#f87171",fontSize:12,marginBottom:12}}>⚠ {error}</div>}

            <div style={{display:"flex",gap:10}}>
              <button onClick={() => setStep(2)} style={{background:"#1e293b",color:"#94a3b8",border:"1px solid #334155",borderRadius:8,padding:"10px 20px",fontSize:13,cursor:"pointer"}}>← Tillbaka</button>
              <button onClick={handleAnalyze} disabled={loading}
                style={{background: loading?"#1e293b":"linear-gradient(135deg,#0ea5e9,#6366f1)",color: loading?"#475569":"#fff",border:"none",borderRadius:8,padding:"10px 28px",fontSize:13,fontWeight:600,cursor: loading?"not-allowed":"pointer",display:"flex",alignItems:"center",gap:8}}>
                {loading ? (
                  <>
                    <span style={{display:"inline-block",width:14,height:14,border:"2px solid #475569",borderTopColor:"#7dd3fc",borderRadius:"50%",animation:"spin 0.8s linear infinite"}} />
                    Analyserar...
                  </>
                ) : "🔍 Analysera med Claude →"}
              </button>
            </div>
            <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
          </div>
        )}

        {/* ── Step 4: Results ── */}
        {step === 4 && analysis && (
          <div>
            <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:20}}>
              <h2 style={{color:"#7dd3fc",fontSize:20,margin:0}}>Brandväggsrekommendationer</h2>
              <div style={{display:"flex",gap:8}}>
                <button onClick={() => { setStep(2); setAnalysis(""); setParsedRows(null); setRawData(""); }}
                  style={{background:"#1e293b",color:"#94a3b8",border:"1px solid #334155",borderRadius:8,padding:"8px 16px",fontSize:12,cursor:"pointer"}}>
                  ↺ Ny analys
                </button>
                <button onClick={downloadReport}
                  style={{background:"linear-gradient(135deg,#0ea5e9,#6366f1)",color:"#fff",border:"none",borderRadius:8,padding:"8px 16px",fontSize:12,fontWeight:600,cursor:"pointer"}}>
                  ⬇ Ladda ner rapport (.md)
                </button>
              </div>
            </div>
            <div style={{background:"#0f172a",border:"1px solid #1e3a5f",borderRadius:12,padding:24}}>
              {renderMd(analysis)}
            </div>
            <div style={{marginTop:16,padding:12,background:"#0f172a",borderRadius:8,border:"1px solid #1e293b",fontSize:12,color:"#475569"}}>
              ⚠ Granska alltid AI-genererade regler manuellt innan implementation. Testa i stagingmiljö först.
            </div>
          </div>
        )}

      </div>
    </div>
  );
}
