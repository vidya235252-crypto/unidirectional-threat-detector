import { useEffect, useState } from "react";

const API_BASE = "http://127.0.0.1:8000";

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
    return <p className="alert-empty">Loading stats…</p>;
  }

  return (
    <div className="stats-strip">
      <Stat label="Total flows" value={stats.total_flows} />
      <Stat label="Total alerts" value={stats.total_alerts} />
      {Object.entries(stats.alerts_by_class).map(([cls, count]) => (
        <Stat key={cls} label={cls.toLowerCase().replaceAll("_", " ")} value={count} />
      ))}
    </div>
  );
}

function Stat({ label, value }) {
  return (
    <div className="stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}