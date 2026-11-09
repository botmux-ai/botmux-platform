import { useCallback, useEffect, useMemo, useState } from 'react';
import { Card, Empty, Radio, Spin, Tag, Typography, Button } from '@arco-design/web-react';
import { IconRefresh } from '@arco-design/web-react/icon';
import type { VersionStats, VersionWindow } from '../api';
import { getVersionStats } from '../api';
import { buildVersionRows, formatPercent, type VersionMetric } from '../version-stats';

const WINDOW_OPTIONS: { label: string; value: VersionWindow }[] = [
  { label: '近 7 天活跃', value: 'active7d' },
  { label: '当前在线', value: 'online' },
  { label: '全部', value: 'all' },
];

// 按机器计数：一台机器算一次（用户数只作辅助信息展示）
const METRIC: VersionMetric = 'machines';

/**
 * 版本大盘：全平台 botmux 版本分布（只有聚合计数）。帮用户判断「升哪个版本」——
 * 装的机器越多的版本，踩过的坑越多、相对越稳。按机器计数，默认看「近 7 天活跃」：
 * 排除长期离线的僵尸机器。
 */
export default function VersionDashboard({ active }: { active: boolean }) {
  const [stats, setStats] = useState<VersionStats | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [win, setWin] = useState<VersionWindow>('active7d');

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setStats(await getVersionStats());
      setError(false);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  }, []);

  // 只在 tab 可见时拉取 + 每分钟刷新（后端 60s 缓存，再频繁也没有新数据）
  useEffect(() => {
    if (!active) return;
    void refresh();
    const t = setInterval(() => void refresh(), 60_000);
    return () => clearInterval(t);
  }, [active, refresh]);

  const rows = useMemo(() => (stats ? buildVersionRows(stats, win, METRIC) : []), [stats, win]);
  const top = rows.find((r) => r.isTop);
  const latest = rows.find((r) => r.isLatest);
  const total = stats ? stats.totals[win] : null;

  return (
    <>
      <div className="section-head">
        <h2>版本大盘</h2>
        <div className="version-controls">
          <Radio.Group type="button" size="small" options={WINDOW_OPTIONS} value={win} onChange={setWin} />
          <Button
            size="small"
            shape="circle"
            type="text"
            aria-label="刷新"
            icon={<IconRefresh />}
            loading={loading}
            onClick={() => void refresh()}
          />
        </div>
      </div>

      {!stats ? (
        error ? (
          <Card>
            <Empty description="版本数据暂时不可用，请稍后刷新" />
          </Card>
        ) : (
          <div style={{ textAlign: 'center', padding: 48 }}>
            <Spin />
          </div>
        )
      ) : (
        <>
          <div className="version-summary">
            <Card className="version-stat">
              <div className="version-stat-label">机器数</div>
              <div className="version-stat-value">{total ? total.machines : 0}</div>
              <div className="version-stat-sub">属于 {total?.users ?? 0} 位用户</div>
            </Card>
            <Card className="version-stat">
              <div className="version-stat-label">装机最多</div>
              <div className="version-stat-value mono">{top ? top.version : '—'}</div>
              <div className="version-stat-sub">
                {top ? `${top.count} 台 · 占 ${formatPercent(top.share)}` : '暂无数据'}
              </div>
            </Card>
            <Card className="version-stat">
              <div className="version-stat-label">最新版本（npm 官方发布）</div>
              <div className="version-stat-value mono">{stats.latestVersion ?? '—'}</div>
              <div className="version-stat-sub">
                {!stats.latestVersion
                  ? '暂时查不到官方最新版本'
                  : latest
                    ? `${latest.count} 台已升级 · 占 ${formatPercent(latest.share)}`
                    : '当前窗口内暂无机器使用'}
              </div>
            </Card>
          </div>

          <Typography.Paragraph type="secondary" className="version-hint">
            装的机器越多、跑得越久的版本通常越稳定；新版本刚发布时样本少，可参考采用率再决定是否升级。
            「≥ 该版本」表示已升级到该版本或更新版本的占比。
          </Typography.Paragraph>

          {rows.length === 0 ? (
            <Card>
              <Empty description="当前窗口内没有机器" />
            </Card>
          ) : (
            <Card className="version-list">
              {rows.map((r) => (
                <div key={r.version} className="version-row">
                  <div className="version-row-head">
                    <span className="version-name mono">{r.version}</span>
                    {r.isLatest && <Tag color="green" size="small">最新</Tag>}
                    {r.isTop && <Tag color="arcoblue" size="small">装机最多</Tag>}
                    <span className="version-row-count">
                      <strong>{r.count}</strong> 台
                      <span className="version-row-other"> · {r.otherCount} 人</span>
                    </span>
                  </div>
                  <div className="version-bar-track" title={formatPercent(r.share)}>
                    <div
                      className={'version-bar' + (r.isTop ? ' top' : '')}
                      style={{ width: `${Math.max(r.share * 100, r.count > 0 ? 0.8 : 0)}%` }}
                    />
                  </div>
                  <div className="version-row-foot">
                    <span>占 {formatPercent(r.share)}</span>
                    {r.cumulativeShare !== null && <span>≥ 该版本 {formatPercent(r.cumulativeShare)}</span>}
                  </div>
                </div>
              ))}
            </Card>
          )}

          <Typography.Text type="secondary" className="version-updated">
            数据更新于 {new Date(stats.generatedAt).toLocaleString()}（约每分钟刷新）
          </Typography.Text>
        </>
      )}
    </>
  );
}
