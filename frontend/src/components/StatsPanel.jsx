import { useEffect, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

const CLASS_LABELS = {
  PORT_SCAN: "Port scan",
  C2_BEACONING: "C2 beaconing",
  SYN_FLOOD: "SYN flood",
  DATA_EXFILTRATION: "Data exfiltration",
  DGA_DNS_TUNNELING: "DGA / DNS tunneling",
  MALICIOUS_TLS: "Malicious TLS",
};

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const numberFormatter = new Intl.NumberFormat("en-IN");

export function StatsPanel({ refreshKey }) {
  const [stats, setStats] = useState(null);

  useEffect(() => {
    let cancelled = false;

    async function fetchStats() {
      try {
        const res = await fetch(`${API_BASE}/api/stats`);
        const data = await res.json();
        if (!cancelled) setStats(data);
      } catch {
        // backend unreachable, leave previous stats displayed
      }
    }

    fetchStats();
    const interval = setInterval(fetchStats, 2000);

    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [refreshKey]);

  if (!stats) {
    return <p className="alert-empty">Loading telemetry snapshot…</p>;
  }

  const scenarioClasses = [
    "PORT_SCAN",
    "C2_BEACONING",
    "SYN_FLOOD",
    "DATA_EXFILTRATION",
    "DGA_DNS_TUNNELING",
    "MALICIOUS_TLS",
  ];

  const totalClassAlerts = scenarioClasses.reduce(
    (total, cls) => total + Number(stats.alerts_by_class?.[cls] ?? 0),
    0
  );

  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];

  function classSeverity(cls) {
    const observed = stats.alerts_by_class_severity?.[cls] ?? {};
    return severityOrder.find((level) => Number(observed[level] ?? 0) > 0) ?? "LOW";
  }

  return (
    <div className="stats-panel">
      <div className="stats-strip">
        <div className="stats-primary-row">
          <Stat label="Flows observed" value={stats.total_flows} variant="primary" detail="Total flow records" />
          <Stat label="Threat alerts" value={stats.total_alerts} variant="alert" detail="Detections raised" />
          <Stat label="Throughput" value={stats.throughput_fps} suffix=" /s" variant="runtime" detail="5s rolling rate" />
          <Stat label="Detection latency" value={stats.detection_latency_ms} suffix=" ms" variant="runtime" detail="Mean processing time" />

          <div className="stat severity-breakdown">
            <div className="stat-topline">
              <span className="stat-label">Severity</span>
              <span className="stat-index">LIVE</span>
            </div>
            <div className="severity-bars">
              {SEVERITIES.map((level) => (
                <div key={level} className={`severity-bar-row severity-${level.toLowerCase()}`}>
                  <span>{level}</span>
                  <i>
                    <b style={{ width: `${Math.min(100, ((stats.alerts_by_severity?.[level] ?? 0) / Math.max(1, stats.total_alerts)) * 100)}%` }} />
                  </i>
                  <strong>{stats.alerts_by_severity?.[level] ?? 0}</strong>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div className="stats-scenario-row">
          {scenarioClasses.map((cls) => {
            const count = Number(stats.alerts_by_class?.[cls] ?? 0);
            const share = totalClassAlerts > 0 ? count / totalClassAlerts : 0;

            return (
              <Stat
                key={cls}
                label={CLASS_LABELS[cls]}
                value={count}
                variant="threat"
                severity={classSeverity(cls)}
                detail="Share of alerts"
                barValue={share}
              />
            );
          })}
        </div>
      </div>
      <div className="stats-caption">
        <span><i /> LIVE TELEMETRY SNAPSHOT</span>
        <span>THROUGHPUT / 5S · LATENCY / MEAN</span>
      </div>
    </div>
  );
}

function Stat({ label, value, variant = "", severity, detail, barValue, suffix = "" }) {
  return (
    <div className={`stat ${variant ? `stat-${variant}` : ""} ${severity ? `stat-severity-${severity.toLowerCase()}` : ""}`}>
      <div className="stat-topline">
        <span className="stat-label">{label}</span>
        {severity && (
          <span className={`stat-severity-label severity-${severity.toLowerCase()}`}>
            {severity}
          </span>
        )}
        {variant === "primary" && <span className="stat-index">01</span>}
        {variant === "alert" && <span className="stat-index">02</span>}
      </div>

      <div className="stat-value">{numberFormatter.format(Number(value) || 0)}<small>{suffix}</small></div>

      <div className="stat-footer">
        <span>{detail}</span>
        {typeof barValue === "number" && <span>{Math.round(barValue * 100)}%</span>}
      </div>

      {typeof barValue === "number" && (
        <div className="stat-bar" aria-hidden="true">
          <span style={{ width: `${Math.max(0, Math.min(1, barValue)) * 100}%` }} />
        </div>
      )}
    </div>
  );
}
