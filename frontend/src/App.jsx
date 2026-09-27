import { ShieldHalf, Radio } from "lucide-react";
import { useEvents } from "./ws/useEvents";
import { ScenarioControls } from "./components/ScenarioControls";
import { AlertFeed } from "./components/AlertFeed";
import { StatsPanel } from "./components/StatsPanel";

const STATUS_STYLES = {
  connected: {
    dot: "bg-emerald-400",
    ring: "bg-emerald-400/30",
    text: "text-emerald-300",
    pill: "bg-emerald-500/10 border-emerald-500/30",
  },
  disconnected: {
    dot: "bg-rose-400",
    ring: "bg-rose-400/30",
    text: "text-rose-300",
    pill: "bg-rose-500/10 border-rose-500/30",
  },
  error: {
    dot: "bg-rose-400",
    ring: "bg-rose-400/30",
    text: "text-rose-300",
    pill: "bg-rose-500/10 border-rose-500/30",
  },
};

function App() {
  const { alerts, status, currentScenario } = useEvents();
  const style = STATUS_STYLES[status] ?? STATUS_STYLES.disconnected;

  return (
    <div className="min-h-full bg-slate-950 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,rgba(16,185,129,0.08),transparent)]">
      <div className="mx-auto max-w-6xl px-6 py-10">
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 pb-6">
          <div className="flex items-center gap-3">
            <span className="flex h-10 w-10 items-center justify-center rounded-xl border border-slate-800 bg-slate-900">
              <ShieldHalf className="h-5 w-5 text-emerald-400" strokeWidth={2} />
            </span>
            <div>
              <h1 className="text-xl font-semibold tracking-tight text-slate-50">
                Unidirectional Threat Detector
              </h1>
              <p className="text-sm text-slate-500">
                Live network telemetry &amp; anomaly classification
              </p>
            </div>
          </div>

          <div
            className={`flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-sm font-medium ${style.pill} ${style.text}`}
          >
            <span className="relative flex h-2.5 w-2.5">
              {status === "connected" && (
                <span
                  className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${style.ring}`}
                />
              )}
              <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${style.dot}`} />
            </span>
            <span className="capitalize">{status}</span>
            {currentScenario && (
              <span className="flex items-center gap-1 border-l border-current/30 pl-2 text-current/90">
                <Radio className="h-3.5 w-3.5" />
                running {currentScenario}
              </span>
            )}
          </div>
        </header>

        <div className="mt-8">
          <ScenarioControls currentScenario={currentScenario} />
        </div>

        <div className="mt-8">
          <StatsPanel refreshKey={currentScenario} />
        </div>

        <section className="mt-10">
          <div className="mb-4 flex items-center gap-2">
            <h2 className="text-base font-semibold text-slate-100">Live alerts</h2>
            <span className="rounded-full bg-slate-800 px-2 py-0.5 text-xs font-medium text-slate-400">
              {alerts.length}
            </span>
          </div>
          <AlertFeed alerts={alerts} />
        </section>
      </div>
    </div>
  );
}

export default App;
