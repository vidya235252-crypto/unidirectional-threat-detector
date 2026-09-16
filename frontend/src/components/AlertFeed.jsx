const SEVERITY_COLORS = {
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString("en-GB");
  } catch {
    return iso;
  }
}

export function AlertFeed({ alerts }) {
  if (alerts.length === 0) {
    return <p className="alert-empty">No alerts yet. Start a scenario to see live detections.</p>;
  }

  return (
    <div>
      {alerts.map((alert, index) => (
        <div key={alert.alert_id} className={`alert-row ${index === 0 ? "fresh" : ""}`}>
          <div className="alert-row-head">
            <span className="alert-timestamp">{formatTime(alert.timestamp)}</span>
            <span className="alert-class">{alert.threat_class}</span>
            <span
              className="severity-tag"
              style={{ color: SEVERITY_COLORS[alert.severity] ?? "var(--text-dim)" }}
            >
              {alert.severity}
            </span>
          </div>
          <div className="alert-meta">
            <span>{alert.flow_id}</span>
            <span>confidence {(alert.confidence * 100).toFixed(0)}%</span>
            <span>anomaly {(alert.anomaly_score * 100).toFixed(0)}%</span>
          </div>
          <div className="alert-evidence">
            <div>{alert.evidence.traffic}</div>
            <div>{alert.evidence.temporal}</div>
            <div>{alert.evidence.ml}</div>
            <div>{alert.evidence.rule}</div>
          </div>
        </div>
      ))}
    </div>
  );
}