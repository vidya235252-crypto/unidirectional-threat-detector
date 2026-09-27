import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Search,
  Radio,
  Zap,
  UploadCloud,
  Globe2,
  Lock,
  ShieldCheck,
  BarChart3,
} from "lucide-react";

const API_BASE = "http://127.0.0.1:8000";

const ICONS = {
  total_flows: Activity,
  total_alerts: AlertTriangle,
  port_scan: Search,
  c2_beaconing: Radio,
  syn_flood: Zap,
  data_exfiltration: UploadCloud,
  dga_dns_tunneling: Globe2,
  malicious_tls: Lock,
  benign: ShieldCheck,
};

const ACCENTS = {
  total_flows: "text-sky-400",
  total_alerts: "text-amber-400",
  port_scan: "text-sky-400",
  c2_beaconing: "text-fuchsia-400",
  syn_flood: "text-orange-400",
  data_exfiltration: "text-rose-400",
  dga_dns_tunneling: "text-violet-400",
  malicious_tls: "text-rose-400",
  benign: "text-emerald-400",
};

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
    return (
      <p className="rounded-2xl border border-slate-800 bg-slate-900/60 px-4 py-3 text-sm text-slate-500">
        Loading stats…
      </p>
    );
  }

  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
      <Stat statKey="total_flows" label="Total flows" value={stats.total_flows} />
      <Stat statKey="total_alerts" label="Total alerts" value={stats.total_alerts} />
      {Object.entries(stats.alerts_by_class).map(([cls, count]) => (
        <Stat
          key={cls}
          statKey={cls.toLowerCase()}
          label={cls.toLowerCase().replaceAll("_", " ")}
          value={count}
        />
      ))}
    </div>
  );
}

function Stat({ statKey, label, value }) {
  const Icon = ICONS[statKey] ?? BarChart3;
  const accent = ACCENTS[statKey] ?? "text-slate-300";

  return (
    <div className="rounded-2xl border border-slate-800 bg-slate-900 p-4 transition-colors hover:border-slate-700">
      <div className="mb-3 flex items-center justify-between">
        <span className="rounded-lg bg-slate-800/80 p-1.5">
          <Icon className={`h-4 w-4 ${accent}`} strokeWidth={2} />
        </span>
      </div>
      <div className={`font-mono text-2xl font-bold tabular-nums ${accent}`}>{value}</div>
      <div className="mt-1 text-xs capitalize text-slate-500">{label}</div>
    </div>
  );
}
