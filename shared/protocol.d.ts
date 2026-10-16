/** GuardBuild 协议类型定义（TS 侧） */

export type ScopeKind =
  | "project.read"
  | "worktree.write"
  | "proc.spawn"
  | "net.probe"
  | "net.egress"
  | "workspace.write"
  | "workspace.rollback";

export interface ScopeRequest {
  kind: ScopeKind;
  root?: string;
  host?: string;
  hosts?: string[];
  note?: string;
}

export interface ScopeGrant {
  token: string;
  scopes: ScopeRequest[];
  expiresAt: number;
  via: string;
}

export interface ConsentRequest {
  consentId: string;
  sessionId: string;
  scope: ScopeRequest;
  reason: string;
  consentClass: "confirm" | "user_only";
  requestedAt: number;
}

export interface RpcErrorShape {
  code: number;
  message: string;
  data?: unknown;
}

export interface FsEntry {
  name: string;
  path: string;
  kind: "file" | "dir" | "symlink" | "other";
  size: number;
}

export interface RedactionReport {
  pattern: string;
  count: number;
}

export interface FsReadResult {
  path: string;
  content: string;
  sha256: string;
  size: number;
  redacted: boolean;
  redactions: RedactionReport[];
}

export interface GitFileChange {
  path: string;
  insertions: number;
  deletions: number;
  status: string;
}

export interface GitDiffResult {
  diff: string;
  files: GitFileChange[];
  patchHash: string;
}

export interface ProcSpawnResult {
  pid: number;
  cmd: string;
  cwd: string;
}

export interface ProcLogLine {
  stream: "stdout" | "stderr";
  line: string;
}

export interface HttpRequestParams {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
  identityRef?: string;
  storeCredentialAs?: string;
  credentialPath?: string;
  credentialHeader?: string;
  redact?: boolean;
}

export interface HttpResponseResult {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: string;
  redacted: boolean;
  redactions: RedactionReport[];
  durationMs: number;
}

export interface DecisionTrace {
  routeKey: string;
  authzChecks: string[];
  resourceOwner?: string;
  requesterId?: string;
  decision: "allow" | "deny" | "no-check";
  note?: string;
}

/** 单条漏洞证据（请求 + 响应 + 权限判断三方关联） */
export interface EvidenceRecord {
  id: string;
  sessionId: string;
  phase: "pre" | "post";
  identity: string;
  method: string;
  endpoint: string;
  request: {
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    status: number;
    body: string;
    headers?: Record<string, string>;
  };
  decision?: DecisionTrace | null;
  expectation: string;
  verdict: "vulnerable" | "blocked" | "passed" | "regressed" | "inconclusive";
  createdAt: number;
}

export interface Finding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  category: string;
  endpoint: string;
  method: string;
  description: string;
  policy: string;
  evidenceIds: string[];
  file?: string;
}

export interface PatchInfo {
  hash: string;
  diff: string;
  files: GitFileChange[];
  worktree: string;
  branch: string;
  strategy: string;
  status: "draft" | "approved" | "rejected" | "applied" | "rolled_back";
}

export interface AcceptanceCase {
  id: string;
  category: "attack" | "business";
  name: string;
  expected: string;
  actual: string;
  pass: boolean;
  evidenceId?: string;
}

export interface AcceptanceSummary {
  total: number;
  passed: number;
  failed: number;
  attackBlocked: number;
  attackTotal: number;
  businessOk: number;
  businessTotal: number;
  cases: AcceptanceCase[];
}

export interface TokenView {
  id: string;
  scopes: string[];
  expiresAt: number;
  via: string;
}

export interface TargetInfo {
  baseUrl: string;
  pid: number;
  worktreeDir?: string;
  worktreePid?: number;
  worktreeBaseUrl?: string;
}

export interface RollbackInfo {
  available: boolean;
  backupId?: string;
  files?: string[];
}

export interface SessionView {
  sessionId: string;
  projectRoot: string;
  projectName: string;
  state: string;
  stateLabel: string;
  startedAt: number;
  updatedAt: number;
  target?: TargetInfo | null;
  findings: Finding[];
  evidence: EvidenceRecord[];
  patch?: PatchInfo | null;
  acceptance?: AcceptanceSummary | null;
  preSummary?: { total: number; vulnerable: number; blocked: number } | null;
  tokens?: TokenView[];
  pendingConsent?: ConsentRequest | null;
  rollback?: RollbackInfo | null;
  error?: string | null;
  writebackAuthorized?: boolean;
  patchApproved?: boolean;
}

export interface UiEvent {
  id: string;
  sessionId: string;
  ts: number;
  kind: string;
  phase: string;
  severity: "info" | "warn" | "error" | "success";
  message: string;
  data?: unknown;
}

export interface SidecarHello {
  protocolVersion: string;
  appVersion: string;
  node: string;
  platform: string;
}
