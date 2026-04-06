import { useState, useEffect, useRef } from "react";

const SAMPLE_DATA = [
  {
    id: "TC-001",
    scenario: "C2 Beacon",
    verdict: "malicious",
    severity: "critical",
    rationale: "Regular 60s beacon interval to known malicious IP, confirmed by both Zeek and Suricata CobaltStrike signature",
    input: {
      zeek: `1743900000.000000 CBeacon1 192.168.1.105 49832 185.220.101.45 80 tcp http 320.451823 512 98304 SF T T 0 ShADadfFr 8 1024 6 99328
1743900060.000000 CBeacon2 192.168.1.105 49833 185.220.101.45 80 tcp http 319.887432 498 97856 SF T T 0 ShADadfFr 8 1024 6 99072
1743900120.000000 CBeacon3 192.168.1.105 49901 185.220.101.45 80 tcp http 318.992341 501 98100 SF T T 0 ShADadfFr 8 1024 6 99200
1743900180.000000 CBeacon4 192.168.1.105 49950 185.220.101.45 80 tcp http 320.112233 499 98050 SF T T 0 ShADadfFr 8 1024 6 99150
1743900240.000000 CBeacon5 192.168.1.105 50001 185.220.101.45 80 tcp http 319.654321 503 98200 SF T T 0 ShADadfFr 8 1024 6 99300`,
      suricata: `[1:2025901:3] ET MALWARE Win32/CobaltStrike Beacon [Priority: 1] 2026-04-05T12:00:00 192.168.1.105:49832 -> 185.220.101.45:80 TCP
[1:2025901:3] ET MALWARE Win32/CobaltStrike Beacon [Priority: 1] 2026-04-05T12:01:00 192.168.1.105:49833 -> 185.220.101.45:80 TCP
[1:2025901:3] ET MALWARE Win32/CobaltStrike Beacon [Priority: 1] 2026-04-05T12:02:00 192.168.1.105:49901 -> 185.220.101.45:80 TCP`
    },
    src_ip: "192.168.1.105",
    dst_ip: "185.220.101.45",
    src_port: 49832,
    dst_port: 80,
    timestamp: "2026-04-05T12:00:00Z",
    report: `🚨 INCIDENT REPORT — INC-TC-001
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity : Critical
Verdict  : Malicious
Confidence: 98%

📋 Summary
A CobaltStrike C2 beacon was detected from 192.168.1.105 connecting to known malicious infrastructure at 185.220.101.45:80 at regular 60-second intervals. Both Zeek connection logs and Suricata IDS signatures confirm the CobaltStrike beacon pattern, providing high-confidence attribution.

🔍 Indicators of Compromise
• Source IP: 192.168.1.105 (internal host)
• Destination IP: 185.220.101.45:80 (known C2 server)
• Beacon interval: ~60 seconds (5 connections over 4 minutes)
• Suricata rule [1:2025901:3] ET MALWARE Win32/CobaltStrike Beacon
• Protocol: TCP/HTTP
• Large response bodies (~98KB per beacon)

📅 Correlated Timeline
• 12:00:00 — CBeacon1: Initial beacon connection established (512B sent, 98304B received)
• 12:01:00 — CBeacon2: Second beacon, Suricata alert fired
• 12:02:00 — CBeacon3: Third beacon confirmed, pattern established
• 12:03:00 — CBeacon4: Continued C2 communication
• 12:04:00 — CBeacon5: Fifth beacon — active implant confirmed

✅ Recommended Actions
• Immediately isolate 192.168.1.105 from the network.
• Block 185.220.101.45 at perimeter firewall and DNS sinkhole.
• Initiate incident response — full memory forensic of the compromised host.
• Search for lateral movement from 192.168.1.105 in the same time window.
• Review EDR telemetry for process injection or persistence mechanisms.
• Hunt for additional hosts beaconing to the same C2 infrastructure.

🧠 Justification
Dual-source confirmation (Zeek + Suricata) with precise 60-second beacon intervals and large symmetric response bodies (~98KB) are definitive indicators of CobaltStrike implant activity. The regularity and volume of traffic rule out legitimate HTTP browsing.`
  },
  {
    id: "TC-002",
    scenario: "Tomcat Exploitation",
    verdict: "malicious",
    severity: "medium",
    rationale: "Nmap scan followed by successful web shell deployment via Tomcat manager — single-source Zeek only",
    input: {
      zeek: `1743901000.000000 CReconEx1 10.0.0.50 54100 10.0.0.20 8080 tcp http 0.023145 1024 512 SF T F 0 ShAdFr 3 200 2 600
1743901010.000000 CReconEx2 10.0.0.50 54101 10.0.0.20 8080 tcp http 0.018922 980 488 SF T F 0 ShAdFr 3 200 2 580
1743901020.000000 CExploit 10.0.0.50 54200 10.0.0.20 8080 tcp http 1.234567 8192 256 SF T T 0 ShADadfFr 12 9000 4 1200`,
      suricata: ""
    },
    src_ip: "10.0.0.50",
    dst_ip: "10.0.0.20",
    src_port: 54200,
    dst_port: 8080,
    timestamp: "2026-04-05T13:17:00Z",
    report: `🚨 INCIDENT REPORT — INC-TC-002
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity : Medium
Verdict  : Malicious
Confidence: 87%

📋 Summary
Initial reconnaissance activities, including Nmap scanning, were detected targeting an Apache Tomcat Manager interface. This was followed by a successful exploitation attempt, resulting in the deployment of a web shell on the server, confirmed solely by Zeek logs.

🔍 Indicators of Compromise
• Zeek custom event 'CReconEx1' and 'CReconEx2'
• Nmap user agent detected ('Nmap/7.94')
• Access to Apache Tomcat Manager interface ('uri=/manager/html')
• Zeek custom event 'CExploit'
• Successful POST request to '/manager/text/deploy'
• Request body 'war_file=shell.war'
• HTTP status '200' for web shell deployment
• Explicit 'Tomcat exploitation' tag in http.log

📅 Correlated Timeline
• 13:17:00 — CReconEx1: Nmap user agent accessing /manager/html
• 13:17:10 — CReconEx2: Second recon probe to Tomcat interface
• 13:17:20 — CExploit: POST /manager/text/deploy with war_file=shell.war → HTTP 200

✅ Recommended Actions
• Isolate the compromised Apache Tomcat server immediately.
• Perform full forensic analysis to identify persistence mechanisms.
• Identify and remove the deployed web shell.
• Review and rotate all Tomcat Manager credentials.
• Patch Apache Tomcat to the latest secure version.
• Block source IP 10.0.0.50 at perimeter firewall.

🧠 Justification
Zeek logs provide high-confidence evidence of a successful web server compromise. Despite confirmed active compromise, Suricata provided no corroborating findings. Per strict severity classification rules, CRITICAL requires corroboration from BOTH sources — this incident is classified MEDIUM (single-source confirmation only).`
  },
  {
    id: "TC-003",
    scenario: "DNS Tunneling",
    verdict: "suspicious",
    severity: "high",
    rationale: "High-frequency DNS queries with long encoded subdomains suggest DNS tunneling exfiltration attempt",
    input: {
      zeek: `1743902000.000000 CDnsTun1 172.16.5.22 53201 8.8.8.8 53 udp dns 0.001234 128 256 SF F F 0 Dd 1 156 1 284
1743902001.000000 CDnsTun2 172.16.5.22 53202 8.8.8.8 53 udp dns 0.001198 132 260 SF F F 0 Dd 1 160 1 288
1743902002.000000 CDnsTun3 172.16.5.22 53203 8.8.8.8 53 udp dns 0.001312 129 258 SF F F 0 Dd 1 157 1 286`,
      suricata: `[1:2027501:2] ET DNS Query for Suspicious Long Subdomain [Priority: 2] 2026-04-05T14:00:00 172.16.5.22:53201 -> 8.8.8.8:53 UDP
[1:2027501:2] ET DNS Query for Suspicious Long Subdomain [Priority: 2] 2026-04-05T14:00:01 172.16.5.22:53202 -> 8.8.8.8:53 UDP`
    },
    src_ip: "172.16.5.22",
    dst_ip: "8.8.8.8",
    src_port: 53201,
    dst_port: 53,
    timestamp: "2026-04-05T14:00:00Z",
    report: `⚠️ INCIDENT REPORT — INC-TC-003
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity : High
Verdict  : Suspicious
Confidence: 74%

📋 Summary
Host 172.16.5.22 issued a high volume of DNS queries with unusually long base64-encoded subdomains at approximately 1-second intervals. Both Zeek and Suricata flagged the pattern as consistent with DNS tunneling for data exfiltration.

🔍 Indicators of Compromise
• Source IP: 172.16.5.22
• Destination resolver: 8.8.8.8:53 (external)
• Query interval: ~1 second (high frequency)
• Long encoded subdomain labels (>63 chars)
• Suricata rule [1:2027501:2] ET DNS Suspicious Long Subdomain

📅 Correlated Timeline
• 14:00:00 — CDnsTun1: First high-entropy DNS query
• 14:00:01 — CDnsTun2: Second query, Suricata fires
• 14:00:02 — CDnsTun3: Pattern established — ongoing exfiltration suspected

✅ Recommended Actions
• Block 172.16.5.22 from direct external DNS resolution. Route through internal resolver.
• Capture and decode subdomain payloads to determine exfiltrated data.
• Investigate processes on 172.16.5.22 that are making DNS calls.
• Implement DNS query rate limiting and max label length policies.
• Review for additional hosts exhibiting similar patterns.

🧠 Justification
The combination of 1-second query intervals, unusually long subdomain labels, and dual-source confirmation (Zeek + Suricata) strongly suggests DNS tunneling. Classified SUSPICIOUS rather than MALICIOUS pending payload decoding to confirm exfiltration content.`
  },
  {
    id: "TC-004",
    scenario: "Port Scan",
    verdict: "suspicious",
    severity: "medium",
    rationale: "Sequential port sweep from single source detected by Zeek, no Suricata confirmation",
    input: {
      zeek: `1743903000.000000 CScan1 10.10.1.99 60001 10.10.2.5 22 tcp - 0 0 0 S0 F F 0 S 1 44 0 0
1743903001.000000 CScan2 10.10.1.99 60002 10.10.2.5 23 tcp - 0 0 0 S0 F F 0 S 1 44 0 0
1743903002.000000 CScan3 10.10.1.99 60003 10.10.2.5 25 tcp - 0 0 0 S0 F F 0 S 1 44 0 0
1743903003.000000 CScan4 10.10.1.99 60004 10.10.2.5 80 tcp - 0 0 0 S0 F F 0 S 1 44 0 0`,
      suricata: ""
    },
    src_ip: "10.10.1.99",
    dst_ip: "10.10.2.5",
    src_port: 60001,
    dst_port: 22,
    timestamp: "2026-04-05T14:30:00Z",
    report: `⚠️ INCIDENT REPORT — INC-TC-004
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity : Medium
Verdict  : Suspicious
Confidence: 65%

📋 Summary
Host 10.10.1.99 performed a sequential TCP SYN sweep across multiple ports (22, 23, 25, 80) on target 10.10.2.5 at 1-second intervals. All connections resulted in S0 state (SYN sent, no response), consistent with a closed-port scan.

🔍 Indicators of Compromise
• Source IP: 10.10.1.99 (internal)
• Target: 10.10.2.5
• Ports scanned: 22, 23, 25, 80
• All connections: S0 state (no response from target)
• Sequential source port increment pattern

📅 Correlated Timeline
• 14:30:00 — CScan1: SYN to port 22 (SSH)
• 14:30:01 — CScan2: SYN to port 23 (Telnet)
• 14:30:02 — CScan3: SYN to port 25 (SMTP)
• 14:30:03 — CScan4: SYN to port 80 (HTTP)

✅ Recommended Actions
• Investigate 10.10.1.99 for scanning tools or unauthorized processes.
• Review whether this is authorized penetration testing activity.
• Monitor 10.10.1.99 for follow-up exploitation attempts against open ports.
• Enable rate-limit rules on the perimeter for SYN floods.

🧠 Justification
Sequential port sweep with S0 states is a classic reconnaissance pattern. Classified MEDIUM/SUSPICIOUS due to single-source detection (Zeek only) and lack of confirmed exploitation attempt.`
  },
  {
    id: "TC-005",
    scenario: "Normal HTTPS Traffic",
    verdict: "benign",
    severity: "low",
    rationale: "Standard HTTPS browsing to CDN infrastructure, no suspicious indicators",
    input: {
      zeek: `1743904000.000000 CBenign1 192.168.1.200 55001 104.18.25.243 443 tcp ssl 1.234567 2048 15360 SF T T 0 ShADadfFr 12 2500 8 16000`,
      suricata: ""
    },
    src_ip: "192.168.1.200",
    dst_ip: "104.18.25.243",
    src_port: 55001,
    dst_port: 443,
    timestamp: "2026-04-05T15:00:00Z",
    report: `✅ INCIDENT REPORT — INC-TC-005
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Severity : Low
Verdict  : Benign
Confidence: 95%

📋 Summary
Standard HTTPS connection to Cloudflare CDN infrastructure. Traffic volume and timing consistent with normal user browsing. No suspicious indicators detected.

🔍 Indicators
• Source: 192.168.1.200 → Cloudflare CDN 104.18.25.243:443
• Connection state: SF (normal completion)
• Protocol: TLS/HTTPS
• No Suricata alerts

✅ Recommended Actions
• No action required. Archive for baseline traffic profiling.`
  }
];

const SEVERITY_CONFIG = {
  critical: { label: "Critical", bg: "#500000", color: "#ffb3b3", border: "#a32d2d" },
  high: { label: "High", bg: "#3d2000", color: "#ffcf7a", border: "#854f0b" },
  medium: { label: "Medium", bg: "#1a2a3d", color: "#85b7eb", border: "#185fa5" },
  low: { label: "Low", bg: "#1a2e1a", color: "#97c459", border: "#3b6d11" },
};

const VERDICT_CONFIG = {
  malicious: { label: "Malicious", color: "#f09595", bg: "#501313", border: "#a32d2d" },
  suspicious: { label: "Suspicious", color: "#ef9f27", bg: "#412402", border: "#854f0b" },
  benign: { label: "Benign", color: "#5dcaa5", bg: "#04342c", border: "#0f6e56" },
};

function Badge({ type, value }) {
  const cfg = type === "severity" ? SEVERITY_CONFIG[value] : VERDICT_CONFIG[value];
  if (!cfg) return null;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 10px", borderRadius: 6,
      background: cfg.bg, color: cfg.color,
      border: `1px solid ${cfg.border}`,
      fontSize: 11, fontWeight: 500, letterSpacing: "0.04em",
      textTransform: "uppercase", whiteSpace: "nowrap"
    }}>
      {cfg.label}
    </span>
  );
}

function MetricCard({ label, value, accent }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.04)", border: "0.5px solid rgba(255,255,255,0.1)",
      borderRadius: 10, padding: "16px 20px", flex: 1, minWidth: 120
    }}>
      <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", marginBottom: 8, letterSpacing: "0.06em", textTransform: "uppercase" }}>{label}</div>
      <div style={{ fontSize: 28, fontWeight: 600, color: accent || "rgba(255,255,255,0.9)", fontVariantNumeric: "tabular-nums" }}>{value}</div>
    </div>
  );
}

function BarChart({ data }) {
  const max = Math.max(...data.map(d => d.value), 1);
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
      {data.map(d => (
        <div key={d.label} style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div style={{ width: 80, fontSize: 12, color: "rgba(255,255,255,0.5)", textAlign: "right", flexShrink: 0 }}>{d.label}</div>
          <div style={{ flex: 1, background: "rgba(255,255,255,0.07)", borderRadius: 4, height: 20, overflow: "hidden" }}>
            <div style={{
              height: "100%", width: `${(d.value / max) * 100}%`,
              background: d.color, borderRadius: 4,
              transition: "width 0.8s cubic-bezier(0.4,0,0.2,1)"
            }} />
          </div>
          <div style={{ width: 24, fontSize: 13, fontWeight: 600, color: d.color, fontVariantNumeric: "tabular-nums" }}>{d.value}</div>
        </div>
      ))}
    </div>
  );
}

function Overview({ incidents, onNav }) {
  const total_raw = incidents.reduce((s, i) => {
    const zLines = i.input.zeek.trim() ? i.input.zeek.trim().split("\n").length : 0;
    const sLines = i.input.suricata.trim() ? i.input.suricata.trim().split("\n").length : 0;
    return s + zLines + sLines;
  }, 0);
  const malicious = incidents.filter(i => i.verdict === "malicious").length;
  const suspicious = incidents.filter(i => i.verdict === "suspicious").length;
  const benign = incidents.filter(i => i.verdict === "benign").length;
  const critical = incidents.filter(i => i.severity === "critical").length;
  const reduction = Math.round(((total_raw - incidents.length) / total_raw) * 100);

  return (
    <div>
      <div style={{ marginBottom: 28 }}>
        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.1em", textTransform: "uppercase", marginBottom: 6 }}>Traffic Overview</div>
        <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
          <MetricCard label="Raw Log Lines" value={total_raw} />
          <MetricCard label="Incidents" value={incidents.length} />
          <MetricCard label="Alert Reduction" value={`${reduction}%`} accent="#5dcaa5" />
          <MetricCard label="Critical" value={critical} accent="#f09595" />
        </div>
      </div>

      <div style={{
        background: "rgba(255,255,255,0.04)", border: "0.5px solid rgba(255,255,255,0.1)",
        borderRadius: 10, padding: "20px 24px", marginBottom: 20
      }}>
        <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 16 }}>Verdict Distribution</div>
        <BarChart data={[
          { label: "Malicious", value: malicious, color: "#e24b4a" },
          { label: "Suspicious", value: suspicious, color: "#ef9f27" },
          { label: "Benign", value: benign, color: "#1d9e75" },
        ]} />
      </div>

      <div style={{
        background: "rgba(255,255,255,0.04)", border: "0.5px solid rgba(255,255,255,0.1)",
        borderRadius: 10, padding: "20px 24px"
      }}>
        <div style={{ fontSize: 12, color: "rgba(255,255,255,0.4)", letterSpacing: "0.06em", textTransform: "uppercase", marginBottom: 16 }}>Severity Breakdown</div>
        <BarChart data={[
          { label: "Critical", value: critical, color: "#e24b4a" },
          { label: "High", value: incidents.filter(i => i.severity === "high").length, color: "#ef9f27" },
          { label: "Medium", value: incidents.filter(i => i.severity === "medium").length, color: "#378add" },
          { label: "Low", value: incidents.filter(i => i.severity === "low").length, color: "#639922" },
        ]} />
      </div>

      <button onClick={() => onNav("discover")} style={{
        marginTop: 20, padding: "10px 20px", background: "rgba(55,138,221,0.15)",
        border: "0.5px solid #185fa5", borderRadius: 8, color: "#85b7eb",
        fontSize: 13, cursor: "pointer", letterSpacing: "0.04em"
      }}>
        View all incidents →
      </button>
    </div>
  );
}

function IncidentRow({ incident, onClick }) {
  return (
    <div onClick={onClick} style={{
      display: "grid", gridTemplateColumns: "130px 110px 100px 100px 90px 90px 1fr",
      gap: 12, padding: "12px 16px",
      background: "rgba(255,255,255,0.02)", border: "0.5px solid rgba(255,255,255,0.07)",
      borderRadius: 8, cursor: "pointer", alignItems: "center",
      transition: "background 0.15s",
    }}
      onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.06)"}
      onMouseLeave={e => e.currentTarget.style.background = "rgba(255,255,255,0.02)"}
    >
      <div style={{ fontFamily: "monospace", fontSize: 12, color: "rgba(255,255,255,0.6)" }}>{incident.id}</div>
      <Badge type="severity" value={incident.severity} />
      <Badge type="verdict" value={incident.verdict} />
      <div style={{ fontFamily: "monospace", fontSize: 11, color: "rgba(255,255,255,0.55)" }}>{incident.src_ip}</div>
      <div style={{ fontFamily: "monospace", fontSize: 11, color: "rgba(255,255,255,0.4)" }}>{incident.src_port}</div>
      <div style={{ fontFamily: "monospace", fontSize: 11, color: "rgba(255,255,255,0.55)" }}>{incident.dst_ip}</div>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ fontFamily: "monospace", fontSize: 11, color: "rgba(255,255,255,0.4)" }}>:{incident.dst_port}</span>
        <span style={{ fontSize: 12, color: "rgba(255,255,255,0.5)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{incident.scenario}</span>
      </div>
    </div>
  );
}

function Discover({ incidents, onSelect, filters, setFilters }) {
  const filtered = incidents.filter(i => {
    if (filters.verdict !== "all" && i.verdict !== filters.verdict) return false;
    if (filters.severity !== "all" && i.severity !== filters.severity) return false;
    return true;
  });

  return (
    <div>
      <div style={{ display: "flex", gap: 10, marginBottom: 20, flexWrap: "wrap" }}>
        {["all", "malicious", "suspicious", "benign"].map(v => (
          <button key={v} onClick={() => setFilters(f => ({ ...f, verdict: v }))} style={{
            padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: "pointer", letterSpacing: "0.04em",
            background: filters.verdict === v ? "rgba(255,255,255,0.12)" : "transparent",
            border: `0.5px solid ${filters.verdict === v ? "rgba(255,255,255,0.3)" : "rgba(255,255,255,0.12)"}`,
            color: filters.verdict === v ? "rgba(255,255,255,0.9)" : "rgba(255,255,255,0.4)",
          }}>{v === "all" ? "All verdicts" : v}</button>
        ))}
        <div style={{ width: 1, background: "rgba(255,255,255,0.1)", margin: "0 4px" }} />
        {["all", "critical", "high", "medium", "low"].map(s => (
          <button key={s} onClick={() => setFilters(f => ({ ...f, severity: s }))} style={{
            padding: "6px 14px", borderRadius: 6, fontSize: 12, cursor: "pointer", letterSpacing: "0.04em",
            background: filters.severity === s ? "rgba(255,255,255,0.12)" : "transparent",
            border: `0.5px solid ${filters.severity === s ? "rgba(255,255,255,0.3)" : "rgba(255,255,255,0.12)"}`,
            color: filters.severity === s ? "rgba(255,255,255,0.9)" : "rgba(255,255,255,0.4)",
          }}>{s === "all" ? "All severity" : s}</button>
        ))}
      </div>

      <div style={{
        display: "grid", gridTemplateColumns: "130px 110px 100px 100px 90px 90px 1fr",
        gap: 12, padding: "8px 16px", marginBottom: 8
      }}>
        {["ID", "Severity", "Verdict", "Src IP", "Src Port", "Dst IP", "Dst Port / Scenario"].map(h => (
          <div key={h} style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", letterSpacing: "0.08em", textTransform: "uppercase" }}>{h}</div>
        ))}
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        {filtered.map(i => (
          <IncidentRow key={i.id} incident={i} onClick={() => onSelect(i)} />
        ))}
        {filtered.length === 0 && (
          <div style={{ padding: "32px 16px", textAlign: "center", color: "rgba(255,255,255,0.3)", fontSize: 13 }}>
            No incidents match the selected filters
          </div>
        )}
      </div>
    </div>
  );
}

const ZEEK_CONN_FIELDS = [
  { key: "ts", label: "Timestamp" },
  { key: "uid", label: "UID" },
  { key: "src_ip", label: "Src IP" },
  { key: "src_port", label: "Src Port" },
  { key: "dst_ip", label: "Dst IP" },
  { key: "dst_port", label: "Dst Port" },
  { key: "proto", label: "Proto" },
  { key: "service", label: "Service" },
  { key: "duration", label: "Duration (s)" },
  { key: "orig_bytes", label: "Orig Bytes" },
  { key: "resp_bytes", label: "Resp Bytes" },
  { key: "conn_state", label: "Conn State" },
  { key: "local_orig", label: "Local Orig" },
  { key: "local_resp", label: "Local Resp" },
  { key: "missed_bytes", label: "Missed Bytes" },
  { key: "history", label: "History" },
  { key: "orig_pkts", label: "Orig Pkts" },
  { key: "orig_ip_bytes", label: "Orig IP Bytes" },
  { key: "resp_pkts", label: "Resp Pkts" },
  { key: "resp_ip_bytes", label: "Resp IP Bytes" },
];

function parseZeekConnLine(line) {
  const parts = line.trim().split(/\s+/);
  const obj = {};
  ZEEK_CONN_FIELDS.forEach((f, i) => { obj[f.key] = parts[i] ?? "-"; });
  return obj;
}

function parseSuricataLine(line) {
  const m = line.match(/^\[(\d+:\d+:\d+)\]\s+(.*?)\s+\[Priority:\s*(\d+)\]\s+(\S+)\s+(\S+)\s+->\s+(\S+)\s+(\S+)$/);
  if (!m) return null;
  const [, sig_id, msg, priority, timestamp, src, dst, proto] = m;
  const [src_ip, src_port] = src.split(":");
  const [dst_ip, dst_port] = dst.split(":");
  return { sig_id, msg, priority, timestamp, src_ip, src_port: src_port || "-", dst_ip, dst_port: dst_port || "-", proto };
}

const CONN_STATE_DESC = {
  SF: "Normal established", S0: "SYN no reply", S1: "Established, not closed",
  REJ: "Rejected", RSTO: "Orig reset", RSTR: "Resp reset", RSTOS0: "Orig sent SYN, resp reset",
  RSTRH: "Resp sent SYN+ACK, orig reset", SH: "Orig sent SYN+FIN", SHR: "Resp sent SYN+FIN",
  OTH: "No SYN seen",
};

function FieldBadge({ value, color }) {
  return (
    <span style={{
      fontFamily: "monospace", fontSize: 11, padding: "2px 7px",
      background: color ? `${color}22` : "rgba(255,255,255,0.06)",
      border: `0.5px solid ${color ? `${color}55` : "rgba(255,255,255,0.12)"}`,
      borderRadius: 4, color: color || "rgba(255,255,255,0.75)", whiteSpace: "nowrap"
    }}>{value}</span>
  );
}

function ZeekTable({ content }) {
  const [expanded, setExpanded] = useState(false);
  if (!content.trim()) return (
    <div style={{ padding: "10px 14px", background: "rgba(255,255,255,0.02)", borderRadius: 6, border: "0.5px solid rgba(255,255,255,0.07)" }}>
      <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)", fontFamily: "monospace" }}>No Zeek data</div>
    </div>
  );

  const lines = content.trim().split("\n").filter(Boolean);
  const rows = lines.map(parseZeekConnLine);
  const shown = expanded ? rows : rows.slice(0, 3);

  const highlight = { src_ip: "#5dcaa5", dst_ip: "#85b7eb", src_port: "#5dcaa5", dst_port: "#85b7eb", proto: "#ef9f27", service: "#ef9f27", conn_state: "#e24b4a" };

  return (
    <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: 8, border: "0.5px solid rgba(100,220,180,0.15)", overflow: "hidden" }}>
      <div style={{ padding: "8px 14px", background: "rgba(100,220,180,0.06)", borderBottom: "0.5px solid rgba(100,220,180,0.12)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 11, color: "rgba(100,220,180,0.7)", letterSpacing: "0.08em", textTransform: "uppercase" }}>Zeek conn.log</span>
        <span style={{ fontSize: 11, color: "rgba(255,255,255,0.25)" }}>{lines.length} events</span>
      </div>
      <div style={{ overflowX: "auto" }}>
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
          <thead>
            <tr style={{ background: "rgba(255,255,255,0.04)" }}>
              {ZEEK_CONN_FIELDS.map(f => (
                <th key={f.key} style={{
                  padding: "6px 10px", textAlign: "left", fontWeight: 500,
                  color: highlight[f.key] ? highlight[f.key] : "rgba(255,255,255,0.35)",
                  fontSize: 10, letterSpacing: "0.06em", textTransform: "uppercase",
                  borderBottom: "0.5px solid rgba(255,255,255,0.07)", whiteSpace: "nowrap"
                }}>{f.label}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((row, i) => (
              <tr key={i} style={{ borderBottom: "0.5px solid rgba(255,255,255,0.04)" }}
                onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                onMouseLeave={e => e.currentTarget.style.background = "transparent"}
              >
                {ZEEK_CONN_FIELDS.map(f => {
                  const val = row[f.key];
                  const isConn = f.key === "conn_state";
                  const color = highlight[f.key];
                  return (
                    <td key={f.key} style={{ padding: "7px 10px", whiteSpace: "nowrap", verticalAlign: "middle" }}>
                      {isConn ? (
                        <span title={CONN_STATE_DESC[val] || val}>
                          <FieldBadge value={val} color={val === "SF" ? "#1d9e75" : val === "S0" ? "#e24b4a" : "#ef9f27"} />
                        </span>
                      ) : (
                        <span style={{ fontFamily: "monospace", color: color || "rgba(255,255,255,0.6)", fontSize: 11 }}>{val}</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length > 3 && (
        <div style={{ padding: "8px 14px", borderTop: "0.5px solid rgba(255,255,255,0.06)" }}>
          <button onClick={() => setExpanded(e => !e)} style={{
            background: "none", border: "none", color: "rgba(100,220,180,0.5)",
            fontSize: 11, cursor: "pointer", padding: 0
          }}>
            {expanded ? "▲ show less" : `▼ ${rows.length - 3} more rows`}
          </button>
        </div>
      )}
    </div>
  );
}

const SURICATA_FIELDS = [
  { key: "sig_id", label: "Signature ID" },
  { key: "msg", label: "Message" },
  { key: "priority", label: "Priority" },
  { key: "timestamp", label: "Timestamp" },
  { key: "src_ip", label: "Src IP" },
  { key: "src_port", label: "Src Port" },
  { key: "dst_ip", label: "Dst IP" },
  { key: "dst_port", label: "Dst Port" },
  { key: "proto", label: "Proto" },
];

function SuricataTable({ content }) {
  const [expanded, setExpanded] = useState(false);
  if (!content.trim()) return (
    <div style={{ padding: "10px 14px", background: "rgba(255,255,255,0.02)", borderRadius: 6, border: "0.5px solid rgba(255,255,255,0.07)" }}>
      <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)", fontFamily: "monospace" }}>No Suricata data</div>
    </div>
  );

  const lines = content.trim().split("\n").filter(Boolean);
  const rows = lines.map(parseSuricataLine).filter(Boolean);
  const shown = expanded ? rows : rows.slice(0, 3);

  const highlight = { sig_id: "#ef9f27", msg: null, priority: "#e24b4a", src_ip: "#5dcaa5", dst_ip: "#85b7eb", src_port: "#5dcaa5", dst_port: "#85b7eb", proto: "#ef9f27", timestamp: null };

  return (
    <div style={{ background: "rgba(0,0,0,0.3)", borderRadius: 8, border: "0.5px solid rgba(255,180,100,0.15)", overflow: "hidden" }}>
      <div style={{ padding: "8px 14px", background: "rgba(255,180,100,0.06)", borderBottom: "0.5px solid rgba(255,180,100,0.12)", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <span style={{ fontSize: 11, color: "rgba(255,180,100,0.7)", letterSpacing: "0.08em", textTransform: "uppercase" }}>Suricata alerts</span>
        <span style={{ fontSize: 11, color: "rgba(255,255,255,0.25)" }}>{lines.length} alerts</span>
      </div>
      {rows.length === 0 ? (
        <div style={{ padding: "10px 14px" }}>
          <div style={{ fontSize: 11, color: "rgba(255,255,255,0.25)", fontFamily: "monospace" }}>Could not parse alert format</div>
        </div>
      ) : (
        <>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
              <thead>
                <tr style={{ background: "rgba(255,255,255,0.04)" }}>
                  {SURICATA_FIELDS.map(f => (
                    <th key={f.key} style={{
                      padding: "6px 10px", textAlign: "left", fontWeight: 500,
                      color: highlight[f.key] || "rgba(255,255,255,0.35)",
                      fontSize: 10, letterSpacing: "0.06em", textTransform: "uppercase",
                      borderBottom: "0.5px solid rgba(255,255,255,0.07)", whiteSpace: "nowrap"
                    }}>{f.label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {shown.map((row, i) => (
                  <tr key={i} style={{ borderBottom: "0.5px solid rgba(255,255,255,0.04)" }}
                    onMouseEnter={e => e.currentTarget.style.background = "rgba(255,255,255,0.04)"}
                    onMouseLeave={e => e.currentTarget.style.background = "transparent"}
                  >
                    {SURICATA_FIELDS.map(f => {
                      const val = row[f.key];
                      const color = highlight[f.key];
                      const isMsg = f.key === "msg";
                      const isPri = f.key === "priority";
                      return (
                        <td key={f.key} style={{ padding: "7px 10px", verticalAlign: "middle", whiteSpace: isMsg ? "normal" : "nowrap", maxWidth: isMsg ? 260 : "none" }}>
                          {isPri ? (
                            <FieldBadge value={`P${val}`} color={val === "1" ? "#e24b4a" : val === "2" ? "#ef9f27" : "#378add"} />
                          ) : (
                            <span style={{ fontFamily: "monospace", color: color || "rgba(255,255,255,0.6)", fontSize: 11 }}>{val}</span>
                          )}
                        </td>
                      );
                    })}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {rows.length > 3 && (
            <div style={{ padding: "8px 14px", borderTop: "0.5px solid rgba(255,255,255,0.06)" }}>
              <button onClick={() => setExpanded(e => !e)} style={{
                background: "none", border: "none", color: "rgba(255,180,100,0.5)",
                fontSize: 11, cursor: "pointer", padding: 0
              }}>
                {expanded ? "▲ show less" : `▼ ${rows.length - 3} more rows`}
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

function IncidentDetail({ incident, onBack }) {
  const vcfg = VERDICT_CONFIG[incident.verdict] || {};
  const scfg = SEVERITY_CONFIG[incident.severity] || {};

  return (
    <div>
      <button onClick={onBack} style={{
        background: "none", border: "none", color: "rgba(255,255,255,0.4)",
        fontSize: 13, cursor: "pointer", padding: 0, marginBottom: 20, display: "flex", alignItems: "center", gap: 6
      }}>← Back to incidents</button>

      <div style={{ display: "flex", alignItems: "flex-start", gap: 16, marginBottom: 24, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 18, fontWeight: 500, color: "rgba(255,255,255,0.9)", marginBottom: 6 }}>{incident.scenario}</div>
          <div style={{ fontFamily: "monospace", fontSize: 12, color: "rgba(255,255,255,0.3)" }}>{incident.id} · {incident.timestamp}</div>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginLeft: "auto" }}>
          <Badge type="severity" value={incident.severity} />
          <Badge type="verdict" value={incident.verdict} />
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))", gap: 10, marginBottom: 24 }}>
        {[
          { l: "Src IP", v: incident.src_ip },
          { l: "Src Port", v: incident.src_port },
          { l: "Dst IP", v: incident.dst_ip },
          { l: "Dst Port", v: incident.dst_port },
        ].map(({ l, v }) => (
          <div key={l} style={{ background: "rgba(255,255,255,0.04)", border: "0.5px solid rgba(255,255,255,0.08)", borderRadius: 8, padding: "10px 14px" }}>
            <div style={{ fontSize: 10, color: "rgba(255,255,255,0.3)", textTransform: "uppercase", letterSpacing: "0.07em", marginBottom: 4 }}>{l}</div>
            <div style={{ fontFamily: "monospace", fontSize: 13, color: "rgba(255,255,255,0.8)" }}>{v}</div>
          </div>
        ))}
      </div>

      <div style={{
        background: "rgba(255,255,255,0.03)", border: `0.5px solid ${vcfg.border || "rgba(255,255,255,0.1)"}`,
        borderRadius: 10, padding: "20px 24px", marginBottom: 20
      }}>
        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 12 }}>Incident Report</div>
        <pre style={{
          fontFamily: "monospace", fontSize: 12, lineHeight: 1.8,
          color: "rgba(255,255,255,0.75)", whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0
        }}>{incident.report}</pre>
      </div>

      <div style={{ marginBottom: 20 }}>
        <div style={{ fontSize: 11, color: "rgba(255,255,255,0.35)", letterSpacing: "0.08em", textTransform: "uppercase", marginBottom: 12 }}>Raw Log Evidence</div>
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <ZeekTable content={incident.input.zeek} />
          <SuricataTable content={incident.input.suricata} />
        </div>
      </div>
    </div>
  );
}

const NAV = [
  { id: "overview", label: "Overview" },
  { id: "discover", label: "Discover" },
];

export default function App() {
  const [page, setPage] = useState("overview");
  const [selected, setSelected] = useState(null);
  const [filters, setFilters] = useState({ verdict: "all", severity: "all" });

  function handleSelect(incident) {
    setSelected(incident);
    setPage("detail");
  }

  function handleBack() {
    setSelected(null);
    setPage("discover");
  }

  return (
    <div style={{
      background: "#0e1117", minHeight: "100vh", color: "rgba(255,255,255,0.85)",
      fontFamily: "'IBM Plex Mono', 'Fira Code', monospace",
      padding: 0
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: rgba(255,255,255,0.03); }
        ::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.12); border-radius: 3px; }
      `}</style>

      <div style={{
        borderBottom: "0.5px solid rgba(255,255,255,0.08)",
        padding: "0 28px",
        display: "flex", alignItems: "center", gap: 32, height: 52
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 22, height: 22, borderRadius: 5,
            background: "linear-gradient(135deg, #e24b4a 0%, #854f0b 100%)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 11, color: "white", fontWeight: 600
          }}>V</div>
          <span style={{ fontSize: 14, fontWeight: 500, color: "rgba(255,255,255,0.9)", letterSpacing: "0.12em" }}>ViGYL</span>
          <span style={{ fontSize: 11, color: "rgba(255,255,255,0.25)", letterSpacing: "0.06em" }}>/ TRIAGE</span>
        </div>

        <div style={{ display: "flex", gap: 4 }}>
          {NAV.map(n => (
            <button key={n.id} onClick={() => { setPage(n.id); setSelected(null); }} style={{
              padding: "6px 14px", background: "none", border: "none",
              borderRadius: 6, cursor: "pointer", fontSize: 12, letterSpacing: "0.05em",
              color: page === n.id || (n.id === "discover" && page === "detail") ? "rgba(255,255,255,0.9)" : "rgba(255,255,255,0.35)",
              background: page === n.id || (n.id === "discover" && page === "detail") ? "rgba(255,255,255,0.08)" : "transparent",
            }}>{n.label}</button>
          ))}
        </div>

        <div style={{ marginLeft: "auto", display: "flex", gap: 8, alignItems: "center" }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: "#1d9e75", boxShadow: "0 0 6px #1d9e75" }} />
          <span style={{ fontSize: 11, color: "rgba(255,255,255,0.3)", letterSpacing: "0.05em" }}>LIVE</span>
        </div>
      </div>

      <div style={{ maxWidth: 1100, margin: "0 auto", padding: "28px 28px" }}>
        {page === "overview" && <Overview incidents={SAMPLE_DATA} onNav={setPage} />}
        {page === "discover" && (
          <Discover
            incidents={SAMPLE_DATA}
            onSelect={handleSelect}
            filters={filters}
            setFilters={setFilters}
          />
        )}
        {page === "detail" && selected && (
          <IncidentDetail incident={selected} onBack={handleBack} />
        )}
      </div>
    </div>
  );
}
