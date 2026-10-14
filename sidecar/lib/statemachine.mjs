/** 工作流状态机：与 shared/protocol.mjs 的迁移表保持一致，非法迁移直接抛错。 */
import { TRANSITIONS, STATE_LABELS, canTransition } from "../../shared/protocol.mjs";

export class StateMachine {
  constructor(initial, onTransition) {
    this.state = initial;
    this.onTransition = onTransition ?? null;
    this.history = [];
  }

  can(to) {
    return canTransition(this.state, to);
  }

  transition(to, note = "") {
    if (this.state === to) return to;
    if (!this.can(to)) {
      throw new Error(`非法状态迁移: ${this.state} -> ${to}`);
    }
    const from = this.state;
    this.state = to;
    this.history.push({ from, to, note, ts: Date.now() });
    if (this.onTransition) this.onTransition(from, to, note);
    return to;
  }

  label() {
    return STATE_LABELS[this.state] ?? this.state;
  }
}
