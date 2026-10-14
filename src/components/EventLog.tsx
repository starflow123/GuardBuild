import { useEffect, useRef, useState } from "react";
import type { UiEvent } from "../bridge";

const SEVERITIES = ["all", "info", "success", "warn", "error"] as const;

function fmtTime(ts: number): string {
  const d = new Date(ts);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}:${String(
    d.getSeconds()
  ).padStart(2, "0")}`;
}

export function EventLog({ events }: { events: UiEvent[] }) {
  const [filter, setFilter] = useState<(typeof SEVERITIES)[number]>("all");
  const boxRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = boxRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [events.length, filter]);

  const shown = events.filter((e) => filter === "all" || e.severity === filter);

  return (
    <div className="panel" style={{ flex: 1, minHeight: 0 }}>
      <div className="panel-title">
        事件流
        <span className="count">{events.length}</span>
      </div>
      <div style={{ display: "flex", gap: 4, padding: "7px 10px 0", flexWrap: "wrap" }}>
        {SEVERITIES.map((s) => (
          <button
            key={s}
            className={`btn small ${filter === s ? "primary" : ""}`}
            style={{ padding: "2px 9px" }}
            onClick={() => setFilter(s)}
          >
            {s === "all" ? "全部" : s}
          </button>
        ))}
      </div>
      <div className="panel-body" ref={boxRef} style={{ padding: "8px 12px" }}>
        <div className="log-list">
          {shown.map((e) => (
            <div key={e.id} className={`log-row sev-${e.severity}`}>
              <span className="time">{fmtTime(e.ts)}</span>
              <span className={`sev ${e.severity}`} />
              <span className="msg">{e.message}</span>
            </div>
          ))}
          {shown.length === 0 && <div className="empty">暂无事件</div>}
        </div>
      </div>
    </div>
  );
}
