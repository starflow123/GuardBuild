export const users = [
  { id: 1, username: "ning", password: "ning123", name: "王宁", role: "user" },
  { id: 2, username: "qi", password: "qi123", name: "李七", role: "user" },
  { id: 3, username: "hr-admin", password: "hr123", name: "人力资源部", role: "admin" },
];

/** 报表条目：ownerId 是归属列，检索接口按 SQL 文本取数（这一份靶子里检索语句没有参数绑定，是埋好的注入点） */
export const reports = [
  { id: 501, ownerId: 1, title: "华东区季度巡检", body: "巡检 12 个站点，2 处待整改", dept: "ops" },
  { id: 502, ownerId: 1, title: "设备折旧核算", body: "按五年直线法", dept: "finance" },
  { id: 503, ownerId: 2, title: "仓储损耗复盘", body: "Q3 损耗率 0.7%", dept: "ops" },
  { id: 504, ownerId: 2, title: "夜班排班调整", body: "两班改三班", dept: "hr" },
  { id: 505, ownerId: 3, title: "全员调薪方案", body: "分两批执行，先技术序列", dept: "hr" },
  { id: 506, ownerId: 3, title: "供应商对账差异", body: "三家存在金额差异", dept: "finance" },
  { id: 507, ownerId: 1, title: "车辆维保台账", body: "到期 4 台", dept: "ops" },
  { id: 508, ownerId: 2, title: "盘点差异说明", body: "差异集中在耗材", dept: "finance" },
];

export const tables = { reports };

export const sessions = new Map();

export function findUserByUsername(username) {
  return users.find((u) => u.username === username) ?? null;
}
