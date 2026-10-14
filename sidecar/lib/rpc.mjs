/**
 * 与 Rust Host 的 JSON-RPC 2.0 双向连接（NDJSON over stdio）。
 * Sidecar 请求 id 从 1 开始；Host 请求 id >= 10_000_000，天然区分。
 */
import { createInterface } from "node:readline";

export class RpcPeerError extends Error {
  constructor(code, message, data) {
    super(`[${code}] ${message}`);
    this.code = code;
    this.message = message;
    this.data = data;
  }
}

export class RpcPeer {
  constructor({ input, output }) {
    this.input = input;
    this.output = output;
    this.nextId = 1;
    this.pending = new Map();
    this.requestHandlers = new Map();
    this.notifyHandlers = new Map();
    this.closed = false;
    this.onClose = null;

    this.rl = createInterface({ input, terminal: false });
    this.rl.on("line", (line) => this.#onLine(line));
    this.rl.on("close", () => {
      this.closed = true;
      for (const [, p] of this.pending) {
        p.reject(new RpcPeerError(1014, "Host 连接已关闭"));
      }
      this.pending.clear();
      if (this.onClose) this.onClose();
    });
  }

  onRequest(method, handler) {
    this.requestHandlers.set(method, handler);
  }

  onNotification(method, handler) {
    this.notifyHandlers.set(method, handler);
  }

  #onLine(line) {
    const trimmed = line.trim();
    if (!trimmed) return;
    let msg;
    try {
      msg = JSON.parse(trimmed);
    } catch (e) {
      process.stderr.write(`[rpc] 非法 JSON: ${e.message}\n`);
      return;
    }
    const hasMethod = typeof msg.method === "string";
    if (hasMethod && msg.id !== undefined) {
      // Host -> Sidecar 请求
      const handler = this.requestHandlers.get(msg.method);
      Promise.resolve()
        .then(() => (handler ? handler(msg.params ?? {}) : Promise.reject(new RpcPeerError(-32601, `未知方法 ${msg.method}`))))
        .then(
          (result) => this.#write({ jsonrpc: "2.0", id: msg.id, result: result ?? null }),
          (err) =>
            this.#write({
              jsonrpc: "2.0",
              id: msg.id,
              error: {
                code: err.code ?? -32000,
                message: err.message ?? String(err),
                data: err.data ?? null,
              },
            })
        );
    } else if (hasMethod) {
      // Host -> Sidecar 通知
      const handler = this.notifyHandlers.get(msg.method);
      if (handler) Promise.resolve().then(() => handler(msg.params ?? {})).catch(() => {});
    } else if (msg.id !== undefined) {
      // 对 Sidecar 请求的响应
      const p = this.pending.get(msg.id);
      if (!p) return;
      this.pending.delete(msg.id);
      // 延迟响应，避免与工作流共用调用栈
      setTimeout(() => {
        if (msg.error) {
          p.reject(new RpcPeerError(msg.error.code, msg.error.message, msg.error.data));
        } else {
          p.resolve(msg.result);
        }
      }, 0);
    }
  }

  #write(obj) {
    if (this.closed) return;
    this.output.write(JSON.stringify(obj) + "\n");
  }

  request(method, params = {}, { timeoutMs = 60_000 } = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new RpcPeerError(408, `调用 ${method} 超时（${timeoutMs}ms）`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (v) => {
          clearTimeout(timer);
          resolve(v);
        },
        reject: (e) => {
          clearTimeout(timer);
          reject(e);
        },
      });
      this.#write({ jsonrpc: "2.0", id, method, params });
    });
  }

  notify(method, params = {}) {
    this.#write({ jsonrpc: "2.0", method, params });
  }
}
