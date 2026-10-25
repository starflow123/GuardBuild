/**
 * 前端桥接层：封装 Tauri 命令与事件通道。
 * 在非 Tauri 环境（纯浏览器 `npm run dev`）下回退到内置 mock，
 * 用同一份脚本化数据驱动完整界面（便于离线调试 UI）。
 */
import type { ConsentRequest } from "../shared/protocol";

export interface TokenItem {
  id: string;
  scopes: string[];
  kinds?: string[];
  expiresAt: number;
  via: string;
}

export interface EvidenceItem {
  id: string;
  phase: string;
  caseId: string;
  category: "attack" | "business";
  name: string;
  identity: string;
  method: string;
  endpoint: string;
  expectation: string;
  actual: string;
  verdict: "vulnerable" | "blocked" | "passed" | "regressed" | "inconclusive";
  impact?: string | null;
  request: { url: string; headers: Record<string, string>; body?: string | null };
  response: { status: number; statusText?: string; body: string; redacted: boolean; durationMs?: number | null };
  decision?: {
    routeKey?: string;
    checks?: string[];
    decision?: string;
    note?: string;
    resourceOwner?: string | null;
    requesterId?: string | null;
  } | null;
  createdAt: number;
}

export interface FindingItem {
  id: string;
  method: string;
  path: string;
  file: string;
  startLine: number;
  resource: string;
  kind: string;
  sinkCalls: string[];
  reason: string;
  /** 模型线索来源的路由经运行期真实请求确认过 */
  liveVerified?: boolean;
}

export interface BlackboxFinding {
  type: string;
  method: string;
  path: string;
  severity: string;
  detail: string;
  evidenceId: string;
  evidenceGrade: string;
  curl: string;
}

export interface BlackboxPlanPick {
  id: number;
  method: string;
  path: string;
}

export interface BlackboxAttackPlanRound {
  round: number;
  asked: boolean;
  menuSize: number;
  coveredCount: number;
  picks: BlackboxPlanPick[];
  ignored: string[];
  invalid: (string | number)[];
  fallback: string | null;
  rejected: string | null;
  durationMs?: number | null;
  usage?: { prompt_tokens?: number; completion_tokens?: number; total_tokens?: number } | null;
}

/** 攻击规划代理（M2）：模型只挑路由编号，载荷与判据由引擎生成 */
export interface BlackboxAttackPlan {
  enabled: boolean;
  model?: string | null;
  llmCalls: number;
  probeCap?: number | null;
  rounds: BlackboxAttackPlanRound[];
  appliedPicks: BlackboxPlanPick[];
  ignoredFields: string[];
}

export interface BlackboxView {
  mode: string;
  url: string;
  routeCount: number;
  routes?: { method: string; path: string; source?: string | null }[];
  openapiFound?: boolean;
  openapiRouteCount?: number;
  findings: BlackboxFinding[];
  evidenceCount?: number;
  login?: {
    attempted: boolean;
    ok: boolean;
    path?: string | null;
    identities?: { name: string; role?: string; id?: string | null }[];
  } | null;
  rateLimited?: boolean;
  allowMutation?: boolean;
  allowDestructive?: boolean;
  coverage?: string[] | null;
  attackPlan?: BlackboxAttackPlan | null;
  probeCap?: number | null;
  maxRoutes?: number | null;
  reachable?: boolean | null;
  outcome?: string | null;
  exitCode?: number | null;
}

export interface ViewLlmPatch {
  enabled: boolean;
  model?: string | null;
  requestedFiles?: { file: string; candidates: string[] }[];
  appliedFiles?: { file: string; ops: number }[];
  appliedOps?: number;
  rejected?: { file: string; candidate?: string | null; reason: string }[];
  failures?: { file: string; reason: string }[];
  usage?: { file: string; prompt_tokens?: number; completion_tokens?: number; total_tokens?: number }[];
  /** 只读自查：轮数与逐次调用留痕（读到的内容不回传界面） */
  toolRounds?: number;
  toolCalls?: { file?: string | null; tool?: string | null; path?: string | null; ok?: boolean; chars?: number | null; entries?: number | null; reason?: string | null }[];
  /** 跨文件/新建文件写权限（S2-full）：是否生效、候选外的已有文件、本次新建的文件 */
  crossFile?: boolean;
  crossFileFiles?: { from: string; to: string; role?: string | null; ops?: number }[];
  createdFiles?: string[];
}

export interface ViewFixRound {
  round: number;
  patchHash: string | null;
  pass: boolean;
  verdict?: {
    attackBlocked?: number;
    attackTotal?: number;
    attackRegressed?: number;
    businessPassed?: number;
    businessTotal?: number;
    businessRegressed?: number;
  } | null;
  failed?: string[];
  llm?: { model: string | null; appliedOps: number; rejected: number } | null;
}

export interface ViewFixLoop {
  maxRounds: number;
  attempts: number;
  resolvedRound?: number | null;
  rounds: ViewFixRound[];
}

export interface ViewPatchScopeFile {
  file: string;
  role?: string | null;
  created?: boolean;
  /** 候选（漏洞）文件本身未被改动，修复落在依赖闭包里 */
  untouched?: boolean;
  insertions?: number;
  deletions?: number;
  /** 被多少处 import；越高影响面越大 */
  inDegree?: number | null;
}

export interface ViewPatchScope {
  crossFile?: boolean;
  files?: ViewPatchScopeFile[];
  candidateFiles?: string[];
  closureFiles?: string[];
  newFiles?: string[];
  sharedFiles?: { file: string; inDegree?: number | null }[];
  rejectedCount?: number;
}

export interface ViewPatch {
  hash: string;
  diff: string;
  files: { path: string; insertions: number; deletions: number; status?: string }[];
  worktree: string;
  status: string;
  lineCount: number;
  strategy?: string;
  autoVerify?: boolean;
  llm?: ViewLlmPatch | null;
  fixes?: { file: string; appliedOps: number; fixes: { candidate: string; strategy: string; reason?: string | null }[] }[];
  skipped?: { file: string; candidate?: string; reason: string; llm?: string }[];
  fixLoop?: ViewFixLoop | null;
  /** 风险画像：改动范围、角色、共享文件影响面 */
  scope?: ViewPatchScope | null;
}

export interface AcceptanceView {
  pass: boolean;
  attackBlocked: number;
  attackTotal: number;
  businessPassed: number;
  businessTotal: number;
  counts: Record<string, number>;
  phase?: string;
  at?: number;
  writebackRecheck?: AcceptanceView;
}

export interface SessionError {
  code: string;
  message: string;
  hint?: string | null;
  details?: unknown;
  /** 终态语义：coverage/clean 属正常结束（exit 0），blocked 为门禁阻断，failed 为真实执行失败 */
  kind?: "coverage" | "clean" | "blocked" | "failed" | null;
  outcome?: string | null;
  title?: string | null;
  semanticHint?: string | null;
}

export interface LlmView {
  used: boolean;
  model?: string | null;
  source?: string | null;
  routes?: number;
  applied?: { start: boolean; login: boolean; routes: number };
  notes?: string[];
  warnings?: string[];
  cached?: boolean;
  cacheSource?: "memory" | "disk" | null;
  cachedAt?: number | null;
  durationMs?: number | null;
  evidenceFiles?: string[];
  evidenceChars?: number;
  usage?: {
    prompt_tokens?: number;
    completion_tokens?: number;
    total_tokens?: number;
  } | null;
  verified?: { start: boolean; login: boolean };
  rejectedStart?: { cmd?: string; args?: string[] } | null;
  startAttempts?: {
    index?: number | null;
    total?: number | null;
    cmd?: string | null;
    args?: string[];
    cwd?: string | null;
    ok?: boolean;
    skipped?: boolean;
    code?: string | null;
    diagnosisCode?: string | null;
    exitCode?: number | null;
    hint?: string | null;
    durationMs?: number | null;
  }[];
  /** 模型路由的运行期实测：存在性、匿名鉴权、两身份归属过滤（判定只来自真实响应） */
  routeVerification?: {
    checked: number;
    kept: number;
    dropped?: { key: string; reason?: string | null; detail?: string | null }[];
    detail?: {
      key: string;
      method?: string | null;
      declaredPath?: string | null;
      auth?: string | null;
      ownerFilter?: boolean | null;
      status?: number | null;
    }[];
    requestsUsed?: number | null;
    baselineStatus?: number | null;
  } | null;
}

export interface BootstrapAction {
  step?: number | null;
  action?: string | null;
  subject?: string | null;
  ok?: boolean;
  exitCode?: number | null;
  durationMs?: number | null;
  note?: string | null;
}

/** 有界启动代理（S3-full）：动作序列由引擎拼装并实跑，界面只呈现事实不呈现模型原文 */
export interface BootstrapView {
  enabled?: boolean;
  reason?: string | null;
  model?: string | null;
  outcome?: string | null;
  stepsUsed?: number;
  maxSteps?: number;
  rejected?: number;
  durationMs?: number | null;
  remainingMs?: number | null;
  budgetStop?: string | null;
  error?: string | null;
  note?: string | null;
  url?: string | null;
  menuSize?: number;
  startCandidateSize?: number;
  budget?: { maxSteps?: number; stepTimeoutMs?: number; totalBudgetMs?: number; maxOutputChars?: number } | null;
  start?: { cmd?: string; args?: string[]; cwd?: string | null } | null;
  actions?: BootstrapAction[];
}

export interface View {
  sessionId?: string;
  projectRoot?: string;
  projectName?: string;
  state: string;
  stateLabel: string;
  startedAt?: number;
  updatedAt?: number;
  findings?: FindingItem[];
  plan?: {
    loginPath: string;
    resource: string;
    readPath: string | null;
    cancelPath: string | null;
    unauthReadPath?: string | null;
    traversalPath?: string | null;
    sqliPath?: string | null;
    cmdiPath?: string | null;
    ssrfPath?: string | null;
    uploadPath?: string | null;
    listPath: string | null;
  };
  evidence?: EvidenceItem[];
  phases?: Record<string, unknown>;
  targets?: Record<string, { pid: number; port: number; url: string; role?: string }> & {
    docker?: { enabled: boolean; image: string | null; containerPort: number; workdir: string };
  };
  blackbox?: BlackboxView | null;
  blackboxUrl?: string | null;
  patch?: ViewPatch | null;
  acceptance?: AcceptanceView | null;
  llm?: LlmView | null;
  bootstrap?: BootstrapView | null;
  error?: SessionError | null;
  tokens?: TokenItem[];
  pendingConsent?: ConsentRequest | null;
  rollback?: { available: boolean; backupId?: string; files?: string[] } | null;
  writebackAuthorized?: boolean;
  hostDataDir?: string;
  sidecarReady?: boolean;
}

export interface UiEvent {
  id: string;
  ts: number;
  kind: string;
  phase: string;
  severity: "info" | "warn" | "error" | "success";
  message: string;
  data?: unknown;
}

export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

type Unlisten = () => void;

interface Bridge {
  getState(): Promise<View | null>;
  getEvents(limit?: number): Promise<UiEvent[]>;
  getHostInfo(): Promise<{ protocolVersion: string; appVersion: string; dataDir: string; sidecarReady: boolean }>;
  pickProjectDir(): Promise<string | null>;
  startSession(projectRoot: string | null, targetUrl?: string | null): Promise<{ sessionId: string }>;
  resolveConsent(consentId: string, approved: boolean): Promise<unknown>;
  approvePatch(patchHash?: string): Promise<unknown>;
  approveWriteback(patchHash: string): Promise<unknown>;
  requestRollback(): Promise<unknown>;
  cancelSession(): Promise<unknown>;
  onState(cb: (v: View) => void): Promise<Unlisten>;
  onEvent(cb: (ev: UiEvent) => void): Promise<Unlisten>;
  onConsent(cb: (c: ConsentRequest) => void): Promise<Unlisten>;
  onLog(cb: (line: { ts: number; level: string; message: string }) => void): Promise<Unlisten>;
}

// ---------- 真实 Tauri 实现 ----------

const tauriBridge: Bridge = {
  async getState() {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<View>("get_state");
  },
  async getEvents(limit = 300) {
    const { invoke } = await import("@tauri-apps/api/core");
    const r = await invoke<{ events: UiEvent[] }>("get_events", { limit });
    return r.events ?? [];
  },
  async getHostInfo() {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("get_host_info");
  },
  async pickProjectDir() {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke<string | null>("pick_project_dir");
  },
  async startSession(projectRoot, targetUrl) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("start_session", { projectRoot: projectRoot ?? null, targetUrl: targetUrl ?? null });
  },
  async resolveConsent(consentId, approved) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("resolve_consent", { consentId, approved });
  },
  async approvePatch(patchHash) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("approve_patch", { patchHash: patchHash ?? null });
  },
  async approveWriteback(patchHash) {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("approve_writeback", { patchHash });
  },
  async requestRollback() {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("request_rollback");
  },
  async cancelSession() {
    const { invoke } = await import("@tauri-apps/api/core");
    return invoke("cancel_session");
  },
  async onState(cb) {
    const { listen } = await import("@tauri-apps/api/event");
    return listen<View>("guard://state", (e) => cb(e.payload));
  },
  async onEvent(cb) {
    const { listen } = await import("@tauri-apps/api/event");
    return listen<UiEvent>("guard://event", (e) => cb(e.payload));
  },
  async onConsent(cb) {
    const { listen } = await import("@tauri-apps/api/event");
    return listen<ConsentRequest>("guard://consent", (e) => cb(e.payload));
  },
  async onLog(cb) {
    const { listen } = await import("@tauri-apps/api/event");
    return listen<{ ts: number; level: string; message: string }>("guard://log", (e) => cb(e.payload));
  },
};

// ---------- 浏览器 Mock 实现（离线 UI 调试） ----------

function createMockBridge(): Bridge {
  const listeners = {
    state: [] as ((v: View) => void)[],
    event: [] as ((ev: UiEvent) => void)[],
    consent: [] as ((c: ConsentRequest) => void)[],
    log: [] as ((l: { ts: number; level: string; message: string }) => void)[],
  };
  let view: View = {
    state: "idle",
    stateLabel: "空闲",
    findings: [],
    evidence: [],
    tokens: [],
    sidecarReady: true,
    hostDataDir: "（浏览器模拟模式）",
  };
  const events: UiEvent[] = [];
  let seq = 0;

  const push = () => {
    for (const cb of listeners.state) cb({ ...view });
  };
  const ev = (partial: Omit<UiEvent, "id" | "ts">) => {
    const e: UiEvent = { id: `mock_${++seq}`, ts: Date.now(), ...partial };
    events.push(e);
    for (const cb of listeners.event) cb(e);
  };
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  const sampleEvidence = (phase: string): EvidenceItem[] => [
    {
      id: `${phase}_a1`,
      phase,
      caseId: "attack-read-foreign",
      category: "attack",
      name: `alice 读取 bob 的订单 #5002`,
      identity: "alice",
      method: "GET",
      endpoint: "/api/orders/5002",
      expectation: "越权读取他人订单应被拒绝（401/403/404）",
      actual: phase === "pre" ? "HTTP 200，越权请求被放行。证据：返回订单 #5002（归属 u_1002）" : "HTTP 403，越权请求被拒绝",
      verdict: phase === "pre" ? "vulnerable" : "blocked",
      impact: phase === "pre" ? "可读取他人订单详情及字段（id/userId/amount/address 等）" : null,
      request: { url: `http://127.0.0.1:49321/api/orders/5002`, headers: { Authorization: "Bearer ***vault:alice***" } },
      response: {
        status: phase === "pre" ? 200 : 403,
        body: phase === "pre" ? '{"order":{"id":5002,"userId":"u_1002","title":"人体工学椅"}}' : '{"error":"无权访问该订单"}',
        redacted: false,
      },
      decision: {
        routeKey: "orders.get",
        checks: phase === "pre" ? ["authenticated"] : ["authenticated", "order-owner"],
        decision: phase === "pre" ? "no-check" : "deny",
        note: phase === "pre" ? "查询订单后直接返回，未校验订单归属" : "订单归属校验未通过，拒绝访问",
        resourceOwner: "u_1002",
      },
      createdAt: Date.now(),
    },
  ];

  const script = async () => {
    const root = "D:\\demo\\vibeshop";
    view = {
      sessionId: "s_mock",
      projectRoot: root,
      projectName: "vibeshop",
      state: "starting",
      stateLabel: "初始化会话",
      findings: [],
      evidence: [],
      tokens: [],
      sidecarReady: true,
    };
    push();
    const states: [string, string, number][] = [
      ["analyzing", "静态分析项目", 900],
      ["probing", "动态复现与取证", 1200],
      ["evidenced", "证据固化完成", 800],
      ["patching", "生成隔离补丁", 1400],
      ["patch_review", "等待 Diff 审查", 0],
    ];
    ev({ kind: "session", phase: "starting", severity: "info", message: "浏览器模拟模式：完整流程请使用 Tauri 桌面端运行" });
    for (const [st, label, wait] of states) {
      view = { ...view, state: st, stateLabel: label };
      ev({ kind: "state", phase: st, severity: "info", message: `状态: → ${label}` });
      if (st === "analyzing") {
        view.findings = [
          {
            id: "f1",
            method: "GET",
            path: "/api/orders/:id",
            file: "src/app.js",
            startLine: 89,
            resource: "order",
            kind: "idor-suspect",
            sinkCalls: ["findOrderById"],
            reason: "按对象 ID 取资源但未见归属校验（IDOR 静态线索）",
          },
          {
            id: "f2",
            method: "POST",
            path: "/api/orders/:id/cancel",
            file: "src/app.js",
            startLine: 114,
            resource: "order",
            kind: "idor-suspect",
            sinkCalls: ["findOrderById"],
            reason: "按对象 ID 取资源但未见归属校验（IDOR 静态线索）",
          },
        ];
        view.llm = {
          used: true,
          model: "deepseek-chat",
          source: "llm-scout",
          routes: 3,
          applied: { start: true, login: true, routes: 3 },
          notes: ["浏览器模拟：DeepSeek 从自定义路由表推断接入契约"],
          warnings: [],
          cached: true,
          cacheSource: "disk",
          cachedAt: Date.now() - 60_000,
          durationMs: 12,
          evidenceFiles: ["lib/app.mjs", "boot.mjs"],
          evidenceChars: 3412,
          usage: { prompt_tokens: 1200, completion_tokens: 240, total_tokens: 1440 },
          verified: { start: true, login: true },
          rejectedStart: null,
          startAttempts: [
            {
              index: 1,
              total: 2,
              cmd: "node",
              args: ["server.js"],
              ok: false,
              code: "target_not_ready",
              diagnosisCode: "missing_dependency",
              exitCode: 1,
              durationMs: 640,
            },
            { index: 2, total: 2, cmd: "node", args: ["boot.mjs"], ok: true, durationMs: 420 },
          ],
        };
        ev({ kind: "analyze", phase: st, severity: "warn", message: "发现 2 个对象级越权候选" });
        ev({ kind: "scout", phase: st, severity: "success", message: "LLM 接入侦察：启动/登录契约已验证（磁盘缓存复用）" });
      }
      if (st === "evidenced") {
        view.evidence = [...(view.evidence ?? []), ...sampleEvidence("pre")];
        ev({ kind: "evidence", phase: "pre", severity: "error", message: "复现漏洞：alice 可读取 bob 的订单" });
      }
      if (st === "patch_review") {
        view.patch = {
          hash: "e3b0c44298fc1c149afbf4c8996fb924",
          worktree: "D:\\guardbuild-data\\worktrees\\s_mock\\fix",
          status: "pending_review",
          lineCount: 14,
          files: [{ path: "src/app.js", insertions: 11, deletions: 3 }],
          diff: [
            "diff --git a/src/app.js b/src/app.js",
            "--- a/src/app.js",
            "+++ b/src/app.js",
            "@@ -96,7 +96,15 @@",
            "   const orderId = Number(orderDetailMatch[1]);",
            "   const order = findOrderById(orderId);",
            "   if (!order) return json(res, 404, { error: \"订单不存在\" });",
            "+  if (order && order.userId !== auth.user.id) {",
            "+    recordDecision({",
            "+      checks: [\"authenticated\", \"order-owner\"], decision: \"deny\",",
            "+    });",
            "+    return json(res, 403, { error: \"无权访问该订单\" });",
            "+  }",
            "   recordDecision({",
            "-    checks: [\"authenticated\"], decision: \"no-check\",",
            "+    checks: [\"authenticated\", \"order-owner\"], decision: \"allow\",",
          ].join("\n"),
        };
        view.tokens = [
          { id: "tok_mock1", scopes: ["project.read"], kinds: ["project.read"], expiresAt: Date.now() + 7200000, via: "user-selected-project" },
          { id: "tok_mock2", scopes: ["worktree.write"], kinds: ["worktree.write"], expiresAt: Date.now() + 2700000, via: "auto-consent" },
          { id: "tok_mock3", scopes: ["proc.spawn"], kinds: ["proc.spawn"], expiresAt: Date.now() + 2700000, via: "auto-consent" },
          { id: "tok_mock4", scopes: ["net.probe"], kinds: ["net.probe"], expiresAt: Date.now() + 2700000, via: "auto-consent" },
        ];
      }
      push();
      if (wait) await sleep(wait);
    }
  };

  return {
    async getState() {
      return { ...view };
    },
    async getEvents() {
      return [...events];
    },
    async getHostInfo() {
      return { protocolVersion: "guardbuild.rpc/1", appVersion: "0.1.0 (mock)", dataDir: "（浏览器模拟模式）", sidecarReady: true };
    },
    async pickProjectDir() {
      return "D:\\demo\\vibeshop";
    },
    async startSession() {
      script();
      return { sessionId: "s_mock" };
    },
    async resolveConsent() {
      return { ok: true };
    },
    async approvePatch() {
      view = { ...view, state: "verifying", stateLabel: "双重验收（攻击阻断 + 业务回归）" };
      ev({ kind: "state", phase: "verifying", severity: "info", message: "模拟：开始修复后验收" });
      push();
      await sleep(1200);
      view = { ...view, state: "writeback_pending", stateLabel: "等待授权写回" };
      view.evidence = [...(view.evidence ?? []), ...sampleEvidence("post")];
      view.acceptance = {
        pass: true,
        attackBlocked: 2,
        attackTotal: 2,
        businessPassed: 7,
        businessTotal: 7,
        counts: { vulnerable: 0, blocked: 2, passed: 7, regressed: 0, inconclusive: 0 },
        phase: "post",
      };
      ev({ kind: "verify", phase: "post", severity: "success", message: "模拟：双重验收通过（攻击阻断 2/2，业务保持 7/7）" });
      push();
      return { ok: true };
    },
    async approveWriteback() {
      view = { ...view, state: "applied", stateLabel: "已修复并写回", rollback: { available: true, backupId: "bk_mock", files: ["src/app.js"] }, writebackAuthorized: true };
      ev({ kind: "writeback", phase: "applied", severity: "success", message: "模拟：补丁已写回（原文件已备份）" });
      push();
      return { ok: true };
    },
    async requestRollback() {
      view = { ...view, state: "rolled_back", stateLabel: "已回滚" };
      ev({ kind: "rollback", phase: "rolled_back", severity: "success", message: "模拟：已回滚" });
      push();
      return { ok: true };
    },
    async cancelSession() {
      view = { ...view, state: "aborted", stateLabel: "已中止" };
      push();
      return { ok: true };
    },
    async onState(cb) {
      listeners.state.push(cb);
      return () => {
        listeners.state = listeners.state.filter((x) => x !== cb);
      };
    },
    async onEvent(cb) {
      listeners.event.push(cb);
      return () => {
        listeners.event = listeners.event.filter((x) => x !== cb);
      };
    },
    async onConsent(cb) {
      listeners.consent.push(cb);
      return () => {
        listeners.consent = listeners.consent.filter((x) => x !== cb);
      };
    },
    async onLog(cb) {
      listeners.log.push(cb);
      return () => {
        listeners.log = listeners.log.filter((x) => x !== cb);
      };
    },
  };
}

export const bridge: Bridge = isTauri ? tauriBridge : createMockBridge();
