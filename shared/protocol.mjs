/**
 * GuardBuild 协议定义（运行时部分）
 *
 * 该模块是三方的唯一事实来源：
 *  - Node.js Sidecar：编排器，调用 Host 能力（client）
 *  - Rust Host：权限宿主，托管文件/进程/网络/git 能力（server）
 *  - React 前端：通过 Tauri invoke/event 与 Host 交互
 *
 * Sidecar <-> Host 之间采用「按行分隔的 JSON-RPC 2.0」：
 *   stdin/stdout 各为一条 NDJSON 流，双向均可发起请求。
 *   约定：Sidecar 发起的请求 id 从 1 开始；Host 发起的请求 id 从 10_000_000 开始。
 */

export const PROTOCOL_VERSION = "guardbuild.rpc/1";

/** Sidecar -> Host：能力调用（需要作用域令牌） */
export const RPC_TO_HOST = {
  AUTH_REQUEST_SCOPE: "auth.requestScope",
  AUTH_REVOKE: "auth.revoke",
  AUTH_LIST: "auth.listScopes",

  FS_LIST: "fs.list",
  FS_READ: "fs.read",
  FS_WRITE: "fs.write",
  FS_STAT: "fs.stat",
  FS_LINK_DIR: "fs.linkDir",

  GIT_STATUS: "git.status",
  GIT_WORKTREE_ADD: "git.worktreeAdd",
  GIT_WORKTREE_REMOVE: "git.worktreeRemove",
  GIT_DIFF: "git.diff",
  GIT_WRITEBACK: "git.writeback",
  GIT_ROLLBACK: "git.rollback",

  PROC_SPAWN: "proc.spawn",
  PROC_ALLOC_PORT: "proc.allocPort",
  PROC_WAIT_OUTPUT: "proc.waitForOutput",
  PROC_WAIT_EXIT: "proc.waitExit",
  PROC_LOGS: "proc.logs",
  PROC_KILL: "proc.kill",
  PROC_LIST: "proc.list",

  HTTP_REQUEST: "http.request",
  CREDENTIAL_LIST: "credential.list",
  CREDENTIAL_REVOKE: "credential.revoke",

  REPORT_EMIT: "report.emit",
};

/** Sidecar -> Host：通知（无需响应） */
export const NOTIFY_TO_HOST = {
  READY: "sidecar.ready",
  UI_EVENT: "ui.event",
  UI_STATE: "ui.state",
};

/** Host -> Sidecar：编排指令（Host 请求，Sidecar 响应） */
export const RPC_TO_SIDECAR = {
  SESSION_START: "session.start",
  SESSION_CANCEL: "session.cancel",
  PATCH_APPROVED: "patch.approved",
  WRITEBACK_APPROVED: "writeback.approved",
  ROLLBACK_APPROVED: "rollback.approved",
};

/** Host -> Sidecar：通知 */
export const NOTIFY_TO_SIDECAR = {
  HELLO: "host.hello",
};

/** 作用域种类。workspace.write / workspace.rollback 不可由 Sidecar 申请，只能由用户在 UI 批准后由 Host 下发。 */
export const SCOPE_KINDS = {
  PROJECT_READ: "project.read",
  WORKTREE_WRITE: "worktree.write",
  PROC_SPAWN: "proc.spawn",
  NET_PROBE: "net.probe",
  NET_EGRESS: "net.egress",
  WORKSPACE_WRITE: "workspace.write",
  WORKSPACE_ROLLBACK: "workspace.rollback",
};

export const CONSENT_CLASS = {
  AUTO: "auto",
  CONFIRM: "confirm",
  USER_ONLY: "user_only", // 不可被 Sidecar 申请
};

/** 各作用域的授权策略 */
export const SCOPE_POLICY = {
  "project.read": { consent: CONSENT_CLASS.AUTO, desc: "读取所选项目目录（只读，敏感信息自动脱敏）" },
  "worktree.write": { consent: CONSENT_CLASS.CONFIRM, desc: "在隔离的 Git worktree 中生成修复补丁" },
  "proc.spawn": { consent: CONSENT_CLASS.CONFIRM, desc: "启动目标项目进程与 Node 运行时（仅限项目目录内）" },
  "net.probe": { consent: CONSENT_CLASS.CONFIRM, desc: "向本机回环地址发送诊断探测请求" },
  "net.egress": {
    consent: CONSENT_CLASS.CONFIRM,
    desc: "向显式声明的主机发送 HTTPS 请求（Supabase/PostgREST 数据暴露探测；gate 需在 guardbuild.json 声明 net.egress:<host>）",
  },
  "workspace.write": { consent: CONSENT_CLASS.USER_ONLY, desc: "将用户批准的补丁写回原工作区（需展示 Diff 后手动授权）" },
  "workspace.rollback": { consent: CONSENT_CLASS.USER_ONLY, desc: "回滚写回操作，恢复原工作区文件" },
};

/** 工作流状态机 */
export const STATE = {
  IDLE: "idle",
  STARTING: "starting",
  ANALYZING: "analyzing",
  PROBING: "probing",
  EVIDENCED: "evidenced",
  PATCHING: "patching",
  PATCH_REVIEW: "patch_review",
  VERIFYING: "verifying",
  WRITEBACK_PENDING: "writeback_pending",
  APPLYING: "applying",
  APPLIED: "applied",
  ROLLED_BACK: "rolled_back",
  VERIFY_FAILED: "verify_failed",
  COMPLETED: "completed",
  ABORTED: "aborted",
  ERROR: "error",
};

export const STATE_LABELS = {
  idle: "空闲",
  starting: "初始化会话",
  analyzing: "静态分析项目",
  probing: "动态复现与取证",
  evidenced: "证据固化完成",
  patching: "生成隔离补丁",
  patch_review: "等待 Diff 审查",
  verifying: "双重验收（攻击阻断 + 业务回归）",
  writeback_pending: "等待授权写回",
  applying: "写回工作区",
  applied: "已修复并写回",
  rolled_back: "已回滚",
  verify_failed: "验收未通过",
  completed: "扫描完成",
  aborted: "已中止",
  error: "执行出错",
};

/** 状态机合法迁移表（Sidecar 与 Host/UI 共同遵守） */
export const TRANSITIONS = {
  idle: ["starting"],
  starting: ["analyzing", "probing", "error", "aborted"],
  analyzing: ["probing", "error", "aborted"],
  probing: ["evidenced", "error", "aborted"],
  evidenced: ["patching", "completed", "error", "aborted"],
  patching: ["patch_review", "error", "aborted"],
  patch_review: ["verifying", "aborted", "error"],
  verifying: ["writeback_pending", "verify_failed", "aborted", "error"],
  verify_failed: ["patching", "aborted", "error"],
  writeback_pending: ["applying", "aborted", "error"],
  applying: ["applied", "error"],
  applied: ["rolled_back", "error"],
  rolled_back: [],
  completed: [],
  error: [],
  aborted: [],
};

/** 有效状态迁移判定 */
export function canTransition(from, to) {
  const allowed = TRANSITIONS[from];
  return Array.isArray(allowed) && allowed.includes(to);
}

/** 事件严重级别 */
export const SEVERITY = { INFO: "info", WARN: "warn", ERROR: "error", SUCCESS: "success" };

/** 验收用例类别 */
export const CASE_CATEGORY = {
  ATTACK: "attack",     // 原攻击必须被阻断
  BUSINESS: "business", // 合法业务必须保持可用
};

/** 证据判定 */
export const VERDICT = {
  VULNERABLE: "vulnerable",
  BLOCKED: "blocked",
  PASSED: "passed",
  REGRESSED: "regressed",
  INCONCLUSIVE: "inconclusive",
};

/** Tauri 事件通道名（Host -> 前端） */
export const UI_EVENTS = {
  STATE: "guard://state",
  EVENT: "guard://event",
  CONSENT: "guard://consent",
  LOG: "guard://log",
};

/** 生成一个紧凑 id */
export function shortId(prefix = "id") {
  const t = Date.now().toString(36);
  const r = Math.random().toString(36).slice(2, 8);
  return `${prefix}_${t}${r}`;
}

/** JSON-RPC 请求构造（Sidecar 侧使用） */
export function rpcRequest(id, method, params) {
  return { jsonrpc: "2.0", id, method, params: params ?? {} };
}

export function rpcNotification(method, params) {
  return { jsonrpc: "2.0", method, params: params ?? {} };
}

export function rpcResult(id, result) {
  return { jsonrpc: "2.0", id, result };
}

export function rpcError(id, code, message, data) {
  return { jsonrpc: "2.0", id, error: { code, message, data } };
}
