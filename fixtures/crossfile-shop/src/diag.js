// 权限判断决策日志：每次请求记录服务端实际执行了哪些授权检查、依据什么放行/拒绝。
// 守卫模块与业务处理器共用这里，便于安全测试工具对照「代码里写的检查」与「实际响应」。

const decisionLog = [];
let decisionSeq = 0;

export function recordDecision(entry) {
  decisionSeq += 1;
  decisionLog.push({ seq: decisionSeq, ts: Date.now(), ...entry });
  if (decisionLog.length > 500) decisionLog.shift();
}

export function decisions() {
  return decisionLog;
}
