import { useCallback, useEffect, useRef, useState } from "react";
import type { ConsentRequest } from "../shared/protocol";
import { bridge, isTauri, type UiEvent, type View } from "./bridge";
import { WorkflowStepper } from "./components/WorkflowStepper";
import { ConsentDialog } from "./components/ConsentDialog";
import { TokenPanel } from "./components/TokenPanel";
import { ScoutPanel } from "./components/ScoutPanel";
import { FindingsList } from "./components/FindingsList";
import { EventLog } from "./components/EventLog";
import { EvidenceViewer } from "./components/EvidenceViewer";
import { DiffViewer } from "./components/DiffViewer";
import { AcceptancePanel } from "./components/AcceptancePanel";

const ACTIVE_STATES = new Set([
  "starting",
  "analyzing",
  "probing",
  "evidenced",
  "patching",
  "verifying",
  "applying",
]);
const WAIT_STATES = new Set(["patch_review", "writeback_pending"]);
const TERMINAL_STATES = new Set(["idle", "applied", "rolled_back", "error", "aborted", "verify_failed"]);

function stateChipClass(state: string): string {
  if (ACTIVE_STATES.has(state)) return "state-running";
  if (state === "applied") return "state-ok";
  if (state === "patch_review" || state === "writeback_pending" || state === "verify_failed" || state === "rolled_back")
    return "state-warn";
  if (state === "error" || state === "aborted") return "state-err";
  return "";
}

type Tab = "findings" | "evidence" | "patch" | "acceptance";

export function App() {
  const [view, setView] = useState<View | null>(null);
  const [events, setEvents] = useState<UiEvent[]>([]);
  const [consent, setConsent] = useState<ConsentRequest | null>(null);
  const [tab, setTab] = useState<Tab>("findings");
  const [evFilter, setEvFilter] = useState("all");
  const [busy, setBusy] = useState(false);
  const [toast, setToast] = useState<string | null>(null);
  const [hostInfo, setHostInfo] = useState<{
    protocolVersion: string;
    appVersion: string;
    dataDir: string;
    sidecarReady: boolean;
  } | null>(null);
  const toastTimer = useRef<number | null>(null);

  const showToast = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimer.current !== null) window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 4600);
  }, []);

  useEffect(() => {
    let alive = true;
    const unlisteners: (() => void)[] = [];
    const track = (u: () => void) => {
      if (alive) unlisteners.push(u);
      else u();
    };
    (async () => {
      try {
        const [st, evs, hi] = await Promise.all([
          bridge.getState(),
          bridge.getEvents(300),
          bridge.getHostInfo(),
        ]);
        if (alive) {
          if (st) setView(st);
          setEvents(evs);
          setHostInfo(hi);
        }
      } catch (e) {
        showToast(`初始化失败：${String(e)}`);
      }
      track(await bridge.onState((v) => setView(v)));
      track(
        await bridge.onEvent((ev) =>
          setEvents((prev) => {
            if (prev.some((x) => x.id === ev.id)) return prev;
            const next = [...prev, ev];
            return next.length > 600 ? next.slice(-500) : next;
          })
        )
      );
      track(await bridge.onConsent((c) => setConsent(c)));
      track(await bridge.onLog(() => {}));
    })();
    return () => {
      alive = false;
      for (const u of unlisteners) u();
    };
  }, [showToast]);

  const state = view?.state ?? "idle";
  const activeConsent = consent ?? view?.pendingConsent ?? null;

  useEffect(() => {
    if (!view) return;
    if (view.state === "evidenced") setTab("evidence");
    else if (view.state === "patch_review") setTab("patch");
    else if (view.state === "verifying" || view.state === "writeback_pending") setTab("acceptance");
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view?.state]);

  const run = async (fn: () => Promise<unknown>, errPrefix: string) => {
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      showToast(`${errPrefix}：${typeof e === "string" ? e : String((e as Error)?.message ?? e)}`);
    } finally {
      setBusy(false);
    }
  };

  const canStart = TERMINAL_STATES.has(state) && !busy;
  const canAbort = (ACTIVE_STATES.has(state) || WAIT_STATES.has(state) || state === "verify_failed") && !busy;
  const rollbackAvailable = !!view?.rollback?.available && state !== "rolled_back" && !busy;
  const canApprovePatch = state === "patch_review" && view?.patch?.status === "pending_review";
  const canWriteback = state === "writeback_pending" && !!view?.patch;

  const startSession = () =>
    run(async () => {
      const dir = await bridge.pickProjectDir();
      if (!dir) return;
      setTab("findings");
      setEvFilter("all");
      await bridge.startSession(dir);
    }, "启动失败");

  const resolveConsent = async (approved: boolean) => {
    const c = activeConsent;
    if (!c) return;
    setConsent(null);
    await run(() => bridge.resolveConsent(c.consentId, approved), "授权回应失败");
  };

  const findingsCount = view?.findings?.length ?? 0;
  const evidenceCount = view?.evidence?.length ?? 0;
  const patchBadge = view?.patch ? (view.patch.status === "written_back" ? "已写回" : "待审查") : "";
  const acceptanceBadge = view?.acceptance ? (view.acceptance.pass ? "通过" : "未通过") : "";

  return (
    <div className="app">
      <header className="app-header">
        <div className="app-logo">
          <span className="shield">⛨</span>
          <span>
            GuardBuild
            <span className="muted small" style={{ marginLeft: 8, fontWeight: 400 }}>
              桌面安全 Agent
            </span>
          </span>
        </div>
        <span className="project-path" title={view?.projectRoot ?? ""}>
          {view?.projectRoot ?? "尚未选择项目目录"}
        </span>
        <span className={`chip ${stateChipClass(state)}`}>
          <span className="dot" />
          {view?.stateLabel ?? "空闲"}
        </span>
        <span className="spacer" />
        {!isTauri && (
          <span className="chip state-warn" title="未检测到 Tauri 宿主：当前为浏览器模拟数据">
            <span className="dot" />
            浏览器模拟模式
          </span>
        )}
        <span className="chip" title={hostInfo ? `数据目录：${hostInfo.dataDir}` : ""}>
          <span className="dot" style={{ background: hostInfo?.sidecarReady ? "var(--ok)" : "var(--warn)" }} />
          Host {hostInfo?.appVersion ?? "-"}
          {hostInfo && <span className="muted small">{hostInfo.sidecarReady ? "· Sidecar 就绪" : "· Sidecar 未就绪"}</span>}
        </span>
        <button className="btn" onClick={() => run(() => bridge.requestRollback(), "回滚失败")} disabled={!rollbackAvailable} title="回滚写回，恢复原工作区文件">
          回滚写回
        </button>
        <button className="btn danger" onClick={() => run(() => bridge.cancelSession(), "中止失败")} disabled={!canAbort}>
          中止
        </button>
        <button className="btn primary" onClick={startSession} disabled={!canStart}>
          选择项目并诊断
        </button>
      </header>

      <div className="app-main">
        <div className="col">
          <div className="panel">
            <div className="panel-title">修复工作流</div>
            <div className="panel-body" style={{ padding: "8px 9px" }}>
              <WorkflowStepper view={view} />
            </div>
          </div>
          <TokenPanel view={view} />
          <ScoutPanel view={view} />
          <div className="panel">
            <div className="panel-title">隔离与留痕</div>
            <div className="panel-body small muted" style={{ padding: "8px 13px" }}>
              <div>修复在独立 Git worktree 中生成，经 Diff 审查与用户授权后才写回。</div>
              <div>请求、响应与服务端权限判断三方关联，证据与事件留存于 SQLite。</div>
              {view?.rollback?.available && (
                <div style={{ color: "var(--warn)", marginTop: 5 }}>
                  可回滚：写回前已备份 {view.rollback.files?.length ?? 0} 个原文件
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="col">
          {view?.error && (
            <div className="banner err">
              <b>会话错误</b>（{view.error.code}）：{view.error.message}
              {view.error.hint && <div className="small" style={{ marginTop: 3 }}>建议：{view.error.hint}</div>}
            </div>
          )}
          <div className="tabs">
            <div className={`tab ${tab === "findings" ? "active" : ""}`} onClick={() => setTab("findings")}>
              漏洞发现
              <span className="n">{findingsCount}</span>
            </div>
            <div className={`tab ${tab === "evidence" ? "active" : ""}`} onClick={() => setTab("evidence")}>
              复现证据
              <span className="n">{evidenceCount}</span>
            </div>
            <div className={`tab ${tab === "patch" ? "active" : ""}`} onClick={() => setTab("patch")}>
              修复补丁
              {patchBadge && <span className="n">{patchBadge}</span>}
            </div>
            <div className={`tab ${tab === "acceptance" ? "active" : ""}`} onClick={() => setTab("acceptance")}>
              双重验收
              {acceptanceBadge && <span className="n">{acceptanceBadge}</span>}
            </div>
          </div>

          {tab === "findings" && (
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-title">
                对象级越权候选（静态线索，需动态证据确认）
                <span className="count">{findingsCount}</span>
              </div>
              <div className="panel-body">
                <FindingsList findings={view?.findings ?? []} />
              </div>
            </div>
          )}
          {tab === "evidence" && (
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-title">
                证据库（请求 × 响应 × 权限判断）
                <span className="count">{evidenceCount}</span>
              </div>
              <div className="panel-body">
                <EvidenceViewer evidence={view?.evidence ?? []} filter={evFilter} onFilter={setEvFilter} />
              </div>
            </div>
          )}
          {tab === "patch" && (
            <DiffViewer
              patch={view?.patch ?? null}
              canApprove={canApprovePatch}
              onApprove={() => run(() => bridge.approvePatch(view?.patch?.hash), "批准补丁失败")}
            />
          )}
          {tab === "acceptance" && (
            <div className="panel" style={{ flex: 1, minHeight: 0 }}>
              <div className="panel-body" style={{ padding: 0 }}>
                <AcceptancePanel
                  view={view}
                  canWriteback={canWriteback}
                  onWriteback={() => run(() => bridge.approveWriteback(view?.patch?.hash ?? ""), "写回失败")}
                />
              </div>
            </div>
          )}
        </div>

        <div className="col">
          <EventLog events={events} />
        </div>
      </div>

      <ConsentDialog consent={activeConsent} onResolve={resolveConsent} />
      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}
