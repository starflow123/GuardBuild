/**
 * SQLite 证据库（node:sqlite，零依赖）。
 * 留存：结构化事件、修复前/后证据、补丁、用户授权、验收结果。
 */
import { DatabaseSync } from "node:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

export class EvidenceStore {
  constructor(dbPath) {
    mkdirSync(dirname(dbPath), { recursive: true });
    this.db = new DatabaseSync(dbPath);
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.#migrate();
  }

  #migrate() {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY, root TEXT NOT NULL, name TEXT, created_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY, project_id TEXT, root TEXT, state TEXT,
        started_at INTEGER, updated_at INTEGER, meta_json TEXT
      );
      CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY, session_id TEXT, ts INTEGER, kind TEXT, phase TEXT,
        severity TEXT, message TEXT, data_json TEXT
      );
      CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY, session_id TEXT, phase TEXT, identity TEXT,
        method TEXT, endpoint TEXT, request_json TEXT, response_json TEXT,
        decision_json TEXT, expectation TEXT, verdict TEXT, created_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS patches (
        id TEXT PRIMARY KEY, session_id TEXT, worktree TEXT, strategy TEXT,
        diff TEXT, files_json TEXT, patch_hash TEXT, status TEXT, created_at INTEGER
      );
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY, session_id TEXT, action TEXT, subject TEXT,
        patch_hash TEXT, approved_at INTEGER, via TEXT
      );
      CREATE TABLE IF NOT EXISTS acceptance (
        id TEXT PRIMARY KEY, session_id TEXT, case_id TEXT, category TEXT, name TEXT,
        expected TEXT, actual TEXT, pass INTEGER, evidence_id TEXT, created_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id, phase);
      CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, ts);
    `);
    // 存量库补列（CREATE IF NOT EXISTS 不会更新既有表结构）
    const cols = this.db.prepare(`PRAGMA table_info(evidence)`).all().map((c) => c.name);
    if (!cols.includes("evidence_grade")) {
      this.db.exec(`ALTER TABLE evidence ADD COLUMN evidence_grade TEXT`);
    }
    if (!cols.includes("cross_proof")) {
      this.db.exec(`ALTER TABLE evidence ADD COLUMN cross_proof TEXT`);
    }
  }

  ensureProject(id, root, name) {
    this.db
      .prepare(`INSERT INTO projects (id, root, name, created_at) VALUES (?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET root = excluded.root, name = excluded.name`)
      .run(id, root, name, Date.now());
  }

  ensureSession(id, root, projectId) {
    this.db
      .prepare(`INSERT INTO sessions (id, project_id, root, state, started_at, updated_at)
                VALUES (?, ?, ?, 'starting', ?, ?)
                ON CONFLICT(id) DO UPDATE SET state = excluded.state, updated_at = excluded.updated_at`)
      .run(id, projectId, root, Date.now(), Date.now());
  }

  updateSessionState(id, state) {
    this.db
      .prepare(`UPDATE sessions SET state = ?, updated_at = ? WHERE id = ?`)
      .run(state, Date.now(), id);
  }

  insertEvent(ev) {
    this.db
      .prepare(`INSERT INTO events (id, session_id, ts, kind, phase, severity, message, data_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(ev.id, ev.sessionId, ev.ts, ev.kind, ev.phase, ev.severity, ev.message, JSON.stringify(ev.data ?? null));
  }

  insertEvidence(rec) {
    this.db
      .prepare(`INSERT INTO evidence (id, session_id, phase, identity, method, endpoint,
                request_json, response_json, decision_json, expectation, verdict, created_at,
                evidence_grade, cross_proof)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(
        rec.id,
        rec.sessionId,
        rec.phase,
        rec.identity,
        rec.method,
        rec.endpoint,
        JSON.stringify(rec.request),
        JSON.stringify(rec.response),
        JSON.stringify(rec.decision ?? null),
        rec.expectation,
        rec.verdict,
        rec.createdAt,
        rec.evidenceGrade ?? null,
        rec.crossProof ?? null
      );
  }

  insertPatch(p) {
    this.db
      .prepare(`INSERT INTO patches (id, session_id, worktree, strategy, diff, files_json, patch_hash, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(p.id, p.sessionId, p.worktree, p.strategy, p.diff, JSON.stringify(p.files), p.patchHash, p.status, p.createdAt);
  }

  updatePatchStatus(sessionId, patchHash, status) {
    this.db
      .prepare(`UPDATE patches SET status = ? WHERE session_id = ? AND patch_hash = ?`)
      .run(status, sessionId, patchHash);
  }

  insertApproval(a) {
    this.db
      .prepare(`INSERT INTO approvals (id, session_id, action, subject, patch_hash, approved_at, via)
                VALUES (?, ?, ?, ?, ?, ?, ?)`)
      .run(a.id, a.sessionId, a.action, a.subject ?? null, a.patchHash ?? null, a.approvedAt, a.via);
  }

  insertAcceptance(a) {
    this.db
      .prepare(`INSERT INTO acceptance (id, session_id, case_id, category, name, expected, actual, pass, evidence_id, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
      .run(a.id, a.sessionId, a.caseId, a.category, a.name, a.expected, a.actual, a.pass ? 1 : 0, a.evidenceId ?? null, a.createdAt);
  }

  queryEvidence(sessionId, phase = null) {
    const sql = phase
      ? `SELECT * FROM evidence WHERE session_id = ? AND phase = ? ORDER BY created_at`
      : `SELECT * FROM evidence WHERE session_id = ? ORDER BY created_at`;
    const rows = phase ? this.db.prepare(sql).all(sessionId, phase) : this.db.prepare(sql).all(sessionId);
    return rows.map((r) => ({
      id: r.id,
      sessionId: r.session_id,
      phase: r.phase,
      identity: r.identity,
      method: r.method,
      endpoint: r.endpoint,
      request: JSON.parse(r.request_json),
      response: JSON.parse(r.response_json),
      decision: r.decision_json ? JSON.parse(r.decision_json) : null,
      expectation: r.expectation,
      verdict: r.verdict,
      evidenceGrade: r.evidence_grade ?? null,
      crossProof: r.cross_proof ?? null,
      createdAt: r.created_at,
    }));
  }

  queryAcceptance(sessionId) {
    return this.db
      .prepare(`SELECT * FROM acceptance WHERE session_id = ? ORDER BY created_at`)
      .all(sessionId)
      .map((r) => ({
        caseId: r.case_id,
        category: r.category,
        name: r.name,
        expected: r.expected,
        actual: r.actual,
        pass: !!r.pass,
        evidenceId: r.evidence_id,
      }));
  }

  countEvidence(sessionId, phase) {
    const row = this.db
      .prepare(`SELECT COUNT(*) AS n FROM evidence WHERE session_id = ? AND phase = ?`)
      .get(sessionId, phase);
    return row?.n ?? 0;
  }

  close() {
    try {
      this.db.close();
    } catch {
      /* ignore */
    }
  }
}
