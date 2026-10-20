import type { View } from "../bridge";

const STEPS: { key: string; label: string }[] = [
  { key: "starting", label: "初始化会话" },
  { key: "analyzing", label: "静态分析项目" },
  { key: "probing", label: "动态复现与取证" },
  { key: "evidenced", label: "证据固化" },
  { key: "patching", label: "生成隔离补丁" },
  { key: "patch_review", label: "Diff 审查" },
  { key: "verifying", label: "双重验收" },
  { key: "writeback_pending", label: "授权写回" },
  { key: "applying", label: "写回工作区" },
  { key: "applied", label: "修复完成" },
];

const BLACKBOX_STEPS: { key: string; label: string }[] = [
  { key: "starting", label: "初始化会话" },
  { key: "probing", label: "外部探测取证" },
  { key: "evidenced", label: "证据固化" },
  { key: "completed", label: "扫描完成" },
];

const FAIL_STATES: Record<string, string> = {
  error: "执行出错",
  aborted: "已中止",
  verify_failed: "验收未通过",
  rolled_back: "已回滚",
};

export function WorkflowStepper({ view }: { view: View | null }) {
  const state = view?.state ?? "idle";
  const isBlackbox = !!view?.blackbox;
  const steps = isBlackbox ? BLACKBOX_STEPS : STEPS;
  const isFail = state in FAIL_STATES;
  const doneState = isBlackbox ? "completed" : "applied";
  let currentIdx = steps.findIndex((s) => s.key === state);
  if (state === "verify_failed") currentIdx = steps.findIndex((s) => s.key === "verifying");
  if (state === "rolled_back" || state === "error" || state === "aborted") {
    const h = view?.phases ?? {};
    if (state === "error" && isBlackbox) currentIdx = 0;
    else if (h.post) currentIdx = steps.findIndex((s) => s.key === "writeback_pending");
    else if (h.pre) currentIdx = steps.findIndex((s) => s.key === "patching");
    else if (view?.findings?.length) currentIdx = steps.findIndex((s) => s.key === "probing");
    else currentIdx = 0;
  }

  return (
    <div className="stepper">
      {steps.map((s, i) => {
        let cls = "step";
        if (isFail && i === currentIdx) cls += " fail";
        else if (currentIdx === -1) {
          if (state === "idle") cls += "";
        } else if (i < currentIdx) cls += " done";
        else if (i === currentIdx) cls += state === doneState ? " done" : " current";
        return (
          <div key={s.key} className={cls}>
            <div className="bullet">{i < currentIdx || (i === currentIdx && state === doneState) ? "✓" : i + 1}</div>
            <div>
              <div className="label">{s.label}</div>
              {isFail && i === currentIdx && <div className="sub">{FAIL_STATES[state]}</div>}
              {!isFail && i === currentIdx && state !== "idle" && state !== doneState && (
                <div className="sub">进行中…</div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
