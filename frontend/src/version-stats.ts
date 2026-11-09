import type { VersionStats, VersionWindow } from './api';

/** 大盘按什么计数：machines=机器台数（页面口径，一台机器算一次），users=去重用户。 */
export type VersionMetric = 'users' | 'machines';

export interface VersionRow {
  version: string;
  count: number;
  /** 另一个口径的计数（按用户看时给出机器数，反之亦然），行内副文案用。 */
  otherCount: number;
  /** 本版本占比（0~1） */
  share: number;
  /** 本版本及更新版本的累计占比（0~1）——「已升级到这个版本以上的有多少」。
   *  用后端按并集去重的累计值，不能前端逐行相加（一人新旧版本各一台会被重复计数）。
   *  null = 无法比较新旧的版本（unknown / 自编译），不展示累计升级率。 */
  cumulativeShare: number | null;
  isLatest: boolean;
  /** 当前窗口 + 口径下计数最多的版本（并列取更新的那个） */
  isTop: boolean;
}

/**
 * 把后端聚合结果投影成某个窗口 + 口径下的展示行。stats.versions 已按版本从新到旧排好，
 * 这里保持该顺序，并剔除本窗口下计数为 0 的版本。
 */
export function buildVersionRows(stats: VersionStats, window: VersionWindow, metric: VersionMetric): VersionRow[] {
  const other: VersionMetric = metric === 'users' ? 'machines' : 'users';
  const total = stats.totals[window][metric];
  const present = stats.versions.filter((v) => v[window][metric] > 0);

  let topVersion: string | null = null;
  let topCount = 0;
  for (const v of present) {
    // 严格大于：并列时保留先遇到的（更新的）版本
    if (v[window][metric] > topCount) {
      topCount = v[window][metric];
      topVersion = v.version;
    }
  }

  return present.map((v) => {
    const count = v[window][metric];
    const cumulative = v.atOrAbove ? v.atOrAbove[window][metric] : null;
    return {
      version: v.version,
      count,
      otherCount: v[window][other],
      share: total > 0 ? count / total : 0,
      cumulativeShare: cumulative === null ? null : total > 0 ? cumulative / total : 0,
      isLatest: v.version === stats.latestVersion,
      isTop: v.version === topVersion,
    };
  });
}

export function formatPercent(x: number): string {
  if (x <= 0) return '0%';
  if (x >= 1) return '100%';
  const p = x * 100;
  return p < 1 ? '<1%' : `${p.toFixed(p < 10 ? 1 : 0)}%`;
}
