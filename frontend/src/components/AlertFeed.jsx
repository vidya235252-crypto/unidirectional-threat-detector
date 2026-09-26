import { useMemo, useState } from "react";

const THREAT_LABELS = {
  PORT_SCAN: "Port scan",
  C2_BEACONING: "C2 beaconing",
  SYN_FLOOD: "SYN flood",
  DATA_EXFILTRATION: "Data exfiltration",
  DGA_DNS_TUNNELING: "DGA / DNS tunneling",
  MALICIOUS_TLS: "Malicious TLS",
};

const THREAT_OPTIONS = [
  ["ALL", "All classes"],
  ...Object.entries(THREAT_LABELS),
];

const SCENARIO_BY_THREAT = {
  PORT_SCAN: "port_scan",
  C2_BEACONING: "c2_beaconing",
  SYN_FLOOD: "syn_flood",
  DATA_EXFILTRATION: "data_exfiltration",
  DGA_DNS_TUNNELING: "dga_dns_tunneling",
  MALICIOUS_TLS: "malicious_tls",
};

function formatTime(iso) {
  if (!iso) return "—";
  const value = String(iso);

  // Scenario timestamps are ISO-8601. Format the clock explicitly so
  // timezone offsets never render as part of the visible time.
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    const match = value.match(/T(\d{2}:\d{2}:\d{2})/);
    return match?.[1] ?? value;
  }

  return parsed.toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  });
}

function formatThreatClass(value) {
  return THREAT_LABELS[value] ?? value?.toLowerCase().replaceAll("_", " ") ?? "Unknown detection";
}

function formatPercent(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? `${(numeric * 100).toFixed(0)}%` : "—";
}

function isBehavioralSignal(alert) {
  return String(alert?.model_version ?? "").startsWith("behavioral-exfil-");
}

function normalize(value) {
  return String(value ?? "").toLowerCase();
}

export function AlertFeed({ alerts, currentScenario }) {
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [threatFilter, setThreatFilter] = useState("ALL");
  const [query, setQuery] = useState("");
  const [expandedId, setExpandedId] = useState(null);

  const scenarioAlerts = useMemo(() => {
    if (!currentScenario) return [];

    return alerts.filter((alert) => {
      const scenario = alert.scenario ?? SCENARIO_BY_THREAT[alert.threat_class];
      return scenario === currentScenario;
    });
  }, [alerts, currentScenario]);

  const filteredAlerts = useMemo(() => {
    const needle = normalize(query).trim();
    return scenarioAlerts.filter((alert) => {
      const severityMatch =
        severityFilter === "ALL" || alert.severity === severityFilter;
      const threatMatch =
        threatFilter === "ALL" || alert.threat_class === threatFilter;

      if (!severityMatch || !threatMatch) return false;
      if (!needle) return true;

      const haystack = [
        alert.alert_id,
        alert.flow_id,
        alert.threat_class,
        alert.severity,
        alert.src_ip,
        alert.dst_ip,
        alert.protocol,
        alert.evidence?.traffic,
        alert.evidence?.temporal,
        alert.evidence?.ml,
        alert.evidence?.rule,
      ].map(normalize).join(" ");

      return haystack.includes(needle);
    });
  }, [scenarioAlerts, severityFilter, threatFilter, query]);

  const severityCounts = scenarioAlerts.reduce((acc, alert) => {
    const key = alert.severity ?? "UNKNOWN";
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});

  function toggleAlert(alertId) {
    setExpandedId((current) => (current === alertId ? null : alertId));
  }

  if (scenarioAlerts.length === 0) {
    return (
      <>
        <FeedToolbar
          severityFilter={severityFilter}
          setSeverityFilter={setSeverityFilter}
          threatFilter={threatFilter}
          setThreatFilter={setThreatFilter}
          query={query}
          setQuery={setQuery}
          count={0}
          total={0}
          severityCounts={severityCounts}
        />
        <div className="alert-empty">
          <span className="empty-marker" aria-hidden="true" />
          <div>
            <strong>NO DETECTIONS IN SESSION</strong>
            <span>Select and run a scenario above to stream only that scenario’s detections into this console.</span>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <FeedToolbar
        severityFilter={severityFilter}
        setSeverityFilter={setSeverityFilter}
        threatFilter={threatFilter}
        setThreatFilter={setThreatFilter}
        query={query}
        setQuery={setQuery}
        count={filteredAlerts.length}
        total={scenarioAlerts.length}
        severityCounts={severityCounts}
      />

      <div className="alert-feed">
        {filteredAlerts.map((alert, index) => {
          const expanded = expandedId === alert.alert_id;
          const severity = String(alert.severity ?? "LOW").toLowerCase();

          return (
            <article
              key={alert.alert_id}
              className={`alert-row alert-row-compact severity-row-${severity} ${index === 0 ? "fresh" : ""} ${expanded ? "expanded" : ""}`}
            >
              <button
                type="button"
                className="alert-summary"
                onClick={() => toggleAlert(alert.alert_id)}
                aria-expanded={expanded}
              >
                <span className="alert-expand" aria-hidden="true">{expanded ? "−" : "+"}</span>
                <span className="alert-timestamp">{formatTime(alert.timestamp)}</span>
                <span className="alert-class">{formatThreatClass(alert.threat_class)}</span>
                <span className="alert-route">
                  {alert.src_ip ?? "—"} <i>→</i> {alert.dst_ip ?? "—"}
                </span>
                <span className={`severity-tag severity-${severity}`}>
                  <span className="severity-dot" />
                  {alert.severity ?? "LOW"}
                </span>
                <span className="alert-confidence">
                  <b>{isBehavioralSignal(alert) ? "SIGNAL" : "CONF"}</b>{" "}
                  {isBehavioralSignal(alert) ? "RULE HIT" : formatPercent(alert.confidence)}
                </span>
                <span className="alert-row-id">{alert.alert_id}</span>
                <span className="alert-chevron" aria-hidden="true">{expanded ? "⌃" : "⌄"}</span>
              </button>

              {expanded && (
                <div className="alert-detail">
                  <div className="alert-detail-meta">
                    <span><b>FLOW</b> {alert.flow_id ?? "—"}</span>
                    <span><b>PROTOCOL</b> {alert.protocol ?? "—"}</span>
                    <span><b>SRC PORT</b> {alert.src_port ?? "—"}</span>
                    <span><b>DST PORT</b> {alert.dst_port ?? "—"}</span>
                    <span><b>ANOMALY</b> {formatPercent(alert.anomaly_score)}</span>
                    <span><b>DETECTION</b> {isBehavioralSignal(alert) ? "BEHAVIORAL RULE" : "MODEL"}</span>
                    <span><b>MODEL</b> {alert.model_version ?? "—"}</span>
                  </div>

                  <div className="evidence-heading">SUPPORTING SIGNALS / MODEL EVIDENCE</div>
                  <div className="alert-evidence">
                    <Evidence label="TRAFFIC" value={alert.evidence?.traffic} />
                    <Evidence label="TEMPORAL" value={alert.evidence?.temporal} />
                    <Evidence label="ML SIGNAL" value={alert.evidence?.ml} />
                    <Evidence label="RULE" value={alert.evidence?.rule} />
                  </div>
                </div>
              )}
            </article>
          );
        })}

        {filteredAlerts.length === 0 && scenarioAlerts.length > 0 && (
          <div className="alert-filter-empty">No events match the current filters.</div>
        )}
      </div>
    </>
  );
}

function FeedToolbar({
  severityFilter,
  setSeverityFilter,
  threatFilter,
  setThreatFilter,
  query,
  setQuery,
  count,
  total,
  severityCounts,
}) {
  return (
    <div className="feed-toolbar">
      <div className="feed-toolbar-count">
        <strong>{count}</strong>
        <span>/ {total} EVENTS</span>
      </div>


      <label className="feed-filter">
        <span>SEVERITY</span>
        <select value={severityFilter} onChange={(event) => setSeverityFilter(event.target.value)}>
          <option value="ALL">All severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
      </label>

      <label className="feed-filter">
        <span>THREAT CLASS</span>
        <select value={threatFilter} onChange={(event) => setThreatFilter(event.target.value)}>
          {THREAT_OPTIONS.map(([value, label]) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>
      </label>

      <label className="feed-search">
        <span>SEARCH</span>
        <input
          value={query}
          onChange={(event) => setQuery(event.target.value)}
          placeholder="IP, flow, alert ID…"
          type="search"
        />
      </label>

      <div className="feed-severity-summary" aria-label="Severity counts">
        {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((level) => (
          <span key={level} className={`severity-summary severity-${level.toLowerCase()}`}>
            <i /> {level} {severityCounts[level] ?? 0}
          </span>
        ))}
      </div>

    </div>
  );
}

function Evidence({ label, value }) {
  if (value === undefined || value === null || String(value).trim() === "") {
    return null;
  }

  return (
    <div className="evidence-item">
      <span className="evidence-label">{label}</span>
      <span className="evidence-value">{String(value)}</span>
    </div>
  );
}
