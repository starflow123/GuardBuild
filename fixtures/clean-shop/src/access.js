// 归属校验封装在辅助函数中：静态分析只看到一次调用，运行时会真实拒绝越权。
export function canAccessOrder(user, order) {
  return !!user && !!order && order.userId === user.id;
}
