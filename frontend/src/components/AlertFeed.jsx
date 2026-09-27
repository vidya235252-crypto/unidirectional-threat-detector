import { ShieldAlert } from "lucide-react";

const SEVERITY_STYLES = {
  HIGH: {
    border: "border-l-rose-500",
    badge: "border-rose-500/40 bg-rose-500/10 text-rose-300",
    icon: "text-rose-400",
  },
  MEDIUM: {
    border: "border-l-amber-400",
    badge: "border-amber-400/40 bg-amber-400/10 text-amber-300",
    icon: "text-amber-400",
  },
  LOW: {
    border: "border-l-sky-400",
    badge: "border-sky-400/40 bg-sky-400/10 text-sky-300",
    icon: "text-sky-400",
  },
};

const FALLBACK_STYLE = {
  border: "border-l-slate-600",
  badge: "border-slate-600/40 bg-slate-600/10 text-slate-300",
  icon: "text-slate-400",
};

const EVIDENCE_LABELS = {
  traffic: "Traffic",
  temporal: "Temporal",
  ml: "Model",
  rule: "Rule",
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
    return (
      <p className="rounded-2xl border border-dashed border-slate-800 bg-slate-900/40 px-4 py-8 text-center text-sm text-slate-500">
        No alerts yet. Start a scenario to see live detections.
      </p>
    );
  }

  return (
    <div className="custom-scrollbar max-h-[700px] overflow-y-auto pr-1 [mask-image:linear-gradient(to_bottom,transparent,black_12px,black_calc(100%-12px),transparent)]">
      <div className="flex flex-col gap-3">
        {alerts.map((alert, index) => {
          const style = SEVERITY_STYLES[alert.severity] ?? FALLBACK_STYLE;

          return (
            <div
              key={alert.alert_id}
              className={`rounded-xl border border-slate-800 border-l-4 bg-slate-900 p-5 ${style.border} ${
                index === 0 ? "animate-flashIn" : ""
              }`}
            >
              <div className="flex flex-wrap items-center gap-3">
                <span className="font-mono text-xs text-slate-500">
                  {formatTime(alert.timestamp)}
                </span>
                <ShieldAlert className={`h-4 w-4 ${style.icon}`} />
                <span className="text-sm font-semibold tracking-tight text-slate-100">
                  {alert.threat_class}
                </span>
                <span
                  className={`ml-auto rounded-full border px-2.5 py-0.5 font-mono text-[0.7rem] font-semibold tracking-wide ${style.badge}`}
                >
                  {alert.severity}
                </span>
              </div>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <span className="rounded-full border border-slate-700 bg-slate-800/70 px-2.5 py-0.5 font-mono text-xs text-slate-400">
                  {alert.flow_id}
                </span>
                <span className="rounded-full border border-slate-700 bg-slate-800/70 px-2.5 py-0.5 font-mono text-xs text-slate-400">
                  confidence {(alert.confidence * 100).toFixed(0)}%
                </span>
                <span className="rounded-full border border-slate-700 bg-slate-800/70 px-2.5 py-0.5 font-mono text-xs text-slate-400">
                  anomaly {(alert.anomaly_score * 100).toFixed(0)}%
                </span>
              </div>

              <dl className="mt-4 grid grid-cols-1 gap-x-6 gap-y-1.5 border-t border-slate-800/80 pt-3 sm:grid-cols-2">
                {Object.entries(EVIDENCE_LABELS).map(([field, label]) => (
                  <div key={field} className="flex gap-2 text-sm">
                    <dt className="w-20 shrink-0 text-slate-500">{label}</dt>
                    <dd className="text-slate-300">{alert.evidence[field]}</dd>
                  </div>
                ))}
              </dl>
            </div>
          );
        })}
      </div>
    </div>
  );
}
