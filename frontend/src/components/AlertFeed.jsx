const SEVERITY_COLORS = {
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

const THREAT_LABELS = {
  PORT_SCAN: "Port scan",
  C2_BEACONING: "C2 beaconing",
  SYN_FLOOD: "SYN flood",
  DATA_EXFILTRATION: "Data exfiltration",
  DGA_DNS_TUNNELING: "DGA / DNS tunneling",
  MALICIOUS_TLS: "Malicious TLS",
};

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString("en-GB");
  } catch {
    return iso;
  }
}

function formatThreatClass(value) {
  return THREAT_LABELS[value] ?? value?.toLowerCase().replaceAll("_", " ") ?? "Unknown detection";
}

function formatPercent(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${(numeric * 100).toFixed(0)}%` : "—";
}

export function AlertFeed({ alerts }) {
  if (alerts.length === 0) {
    return (
      <div className="alert-empty">
        <span className="empty-marker" aria-hidden="true" />
        <div>
          <strong>NO DETECTIONS IN SESSION</strong>
          <span>Start a scenario to stream live detections from the sensor.</span>
        </div>
      </div>
    );
  }

  return (
    <div className="alert-feed">
      {alerts.map((alert, index) => (
        <article
          key={alert.alert_id}
          className={`alert-row ${index === 0 ? "fresh" : ""}`}
        >
          <div className="alert-row-head">
            <span className="alert-timestamp">{formatTime(alert.timestamp)}</span>

            <div className="alert-identity">
              <span className="alert-class">
                {formatThreatClass(alert.threat_class)}
              </span>
              <span className="alert-id">{alert.alert_id}</span>
            </div>

            <span
              className="severity-tag"
              style={{
                color: SEVERITY_COLORS[alert.severity] ?? "var(--text-dim)",
              }}
            >
              {alert.severity}
            </span>
          </div>

          <div className="alert-meta">
            <span>
              <b>FLOW</b> {alert.flow_id}
            </span>
            <span>
              <b>CONFIDENCE</b> {formatPercent(alert.confidence)}
            </span>
            <span>
              <b>ANOMALY</b> {formatPercent(alert.anomaly_score)}
            </span>
          </div>

          <div className="alert-evidence">
            <Evidence label="TRAFFIC" value={alert.evidence?.traffic} />
            <Evidence label="TEMPORAL" value={alert.evidence?.temporal} />
            <Evidence label="ML SIGNAL" value={alert.evidence?.ml} />
            <Evidence label="RULE" value={alert.evidence?.rule} />
          </div>
        </article>
      ))}
    </div>
  );
}

function Evidence({ label, value }) {
  return (
    <div className="evidence-item">
      <span className="evidence-label">{label}</span>
      <span className="evidence-value">{value ?? "No evidence reported"}</span>
    </div>
  );
}
