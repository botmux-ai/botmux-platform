/** 机器卡片上的版本标签：版本号能比较时才提示升级。
 *
 * daemon 在读不到自己的版本时会上报占位值：源码运行没打 tag、桌面版内置 runtime
 * 没盖版本戳时是 `0.0.0`，平台缺省是 `unknown`。这类值不代表真的落后，以前却按
 * 「≠ 最新版」显示成「建议升级」并给出一键升级按钮，误导用户（见 Botmux 交流群反馈）。 */
export interface MachineVersionStatus {
  /** 标签上显示的文字 */
  label: string;
  /** 版本号无法识别（占位值或非 semver） */
  unknown: boolean;
  /** 确实低于最新发布版本，才提示升级 */
  outdated: boolean;
}

const SEMVER = /^v?(\d+)\.(\d+)\.(\d+)/;
const PLACEHOLDERS = new Set(['', 'unknown', '0.0.0']);

function parse(version: string): [number, number, number] | null {
  const match = SEMVER.exec(version.trim());
  return match ? [Number(match[1]), Number(match[2]), Number(match[3])] : null;
}

function less(a: [number, number, number], b: [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false;
}

export function machineVersionStatus(version: string | undefined | null, latestVersion: string | undefined | null): MachineVersionStatus {
  const raw = (version ?? '').trim();
  const current = PLACEHOLDERS.has(raw.replace(/^v/, '')) ? null : parse(raw);
  if (!current) return { label: '版本未知', unknown: true, outdated: false };
  const latest = latestVersion ? parse(latestVersion) : null;
  return { label: raw, unknown: false, outdated: !!latest && less(current, latest) };
}
