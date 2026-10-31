/**
 * 归属策略单独成文件——真实项目里很常见（把「谁能看什么」抽成 policy helper）。
 * 也正因为这行比较不在路由块里，静态分析在 /notes/:id 的块内看不到归属校验，
 * 候选会保留到运行期：修复是否真的生效必须由实测给出（blocked＝确实挡住了）。
 */
export function canReadNote(auth, note) {
  return note.userId === auth.id;
}
