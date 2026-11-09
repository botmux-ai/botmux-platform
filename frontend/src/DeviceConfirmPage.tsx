import { useCallback, useEffect, useMemo, useState } from 'react';
import '@arco-design/web-react/dist/css/arco.css';
import { Alert, Button, Card, Message, Space, Spin, Tag, Typography } from '@arco-design/web-react';
import { DeviceApiError, deviceApi, freshLoginHref, type DeviceGrantView, type DeviceScope } from './device-api';
import DevicePageShell from './components/DevicePageShell';

const SCOPE_LABELS: Record<DeviceScope, string> = {
  'machines:read': '查看我的机器',
  'sessions:open': '查看并打开会话',
  'terminal:control': '操作终端',
  'dashboard:manage': '管理 Dashboard',
  'self:refresh': '刷新本设备凭证',
};

function decisionError(e: unknown): string {
  if (!(e instanceof DeviceApiError)) return '操作失败，请稍后重试';
  if (e.code === 'stale_session' || e.code === 'unauthenticated') return '登录状态已过期，请重新登录后再确认';
  if (e.code === 'machine_ownership_changed') return '机器归属已经变化，本次配对已自动拒绝';
  if (e.code === 'grant_not_pending') return '这个确认请求已经处理或过期';
  if (e.code === 'bad_origin') return '页面来源校验失败，请从平台确认卡片重新打开';
  if (e.code === 'store_unavailable') return '设备服务暂时不可用，请稍后重试';
  return '操作失败，请稍后重试';
}

function statusText(status: DeviceGrantView['status']): string {
  if (status === 'approved' || status === 'consumed') return '已批准';
  if (status === 'denied') return '已拒绝';
  if (status === 'expired') return '已过期';
  return '等待确认';
}

export default function DeviceConfirmPage() {
  const grantId = useMemo(() => new URLSearchParams(location.search).get('grant') || '', []);
  const validGrantId = /^[a-f0-9]{16,64}$/.test(grantId);
  const [grant, setGrant] = useState<DeviceGrantView | null>(null);
  const [loading, setLoading] = useState(validGrantId);
  const [error, setError] = useState<string | null>(validGrantId ? null : '确认链接无效');
  const [needsLogin, setNeedsLogin] = useState(false);
  const [deciding, setDeciding] = useState<'approve' | 'deny' | null>(null);
  const [now, setNow] = useState(Date.now());

  const load = useCallback(async () => {
    if (!validGrantId) return;
    setLoading(true);
    try {
      setGrant(await deviceApi.getGrant(grantId));
      setError(null);
      setNeedsLogin(false);
    } catch (e) {
      const apiError = e instanceof DeviceApiError ? e : null;
      setNeedsLogin(apiError?.status === 401);
      setError(
        apiError?.status === 401 ? '请先用飞书登录，再确认这次设备配对' :
        apiError?.status === 404 ? '确认请求不存在、已失效，或不属于当前账号' :
        apiError?.code === 'store_unavailable' ? '设备服务暂时不可用，请稍后刷新' :
        '加载确认请求失败，请稍后刷新',
      );
    } finally {
      setLoading(false);
    }
  }, [grantId, validGrantId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);

  const secondsLeft = grant ? Math.max(0, Math.ceil((grant.expiresAt - now) / 1000)) : 0;
  const effectiveStatus = grant?.status === 'pending' && secondsLeft === 0 ? 'expired' : grant?.status;

  async function decide(action: 'approve' | 'deny') {
    if (!grant || effectiveStatus !== 'pending') return;
    setDeciding(action);
    try {
      const result = await deviceApi.decideGrant(grant.grantId, action);
      setGrant((current) => current ? { ...current, status: result.status } : current);
      setError(null);
      Message.success(action === 'approve' ? '已批准，桌面端正在完成配对' : '已拒绝这次配对');
    } catch (e) {
      setError(decisionError(e));
      if (e instanceof DeviceApiError && e.status === 401) setNeedsLogin(true);
    } finally {
      setDeciding(null);
    }
  }

  return (
    <DevicePageShell title="确认桌面设备" subtitle="只有你本人可以批准；请求发起后 5 分钟内有效。">
      {loading ? (
        <Card><div className="device-loading"><Spin tip="读取确认请求…" /></div></Card>
      ) : error && !grant ? (
        <Card>
          <Alert type={needsLogin ? 'info' : 'warning'} content={error} />
          <Space style={{ marginTop: 16 }}>
            {needsLogin && <Button type="primary" onClick={() => (location.href = freshLoginHref())}>飞书登录</Button>}
            <Button onClick={() => location.reload()}>刷新</Button>
          </Space>
        </Card>
      ) : grant ? (
        <Card className="device-confirm-card">
          {error && <Alert type="warning" content={error} style={{ marginBottom: 16 }} />}
          <div className="device-confirm-name">
            <Typography.Title heading={5}>{grant.deviceName}</Typography.Title>
            <Tag color="arcoblue">设备自报名称</Tag>
          </div>
          <dl className="device-detail-list">
            <div><dt>发起机器</dt><dd>{grant.machineName}</dd></div>
            <div><dt>设备类型</dt><dd>桌面 IDE</dd></div>
            <div><dt>状态</dt><dd>{statusText(effectiveStatus || grant.status)}</dd></div>
            <div><dt>剩余时间</dt><dd>{effectiveStatus === 'pending' ? `${secondsLeft} 秒` : '—'}</dd></div>
          </dl>
          <Typography.Text type="secondary">批准后，这台桌面设备将获得：</Typography.Text>
          <div className="device-scope-list">
            {grant.scopes.map((scope) => <Tag key={scope}>{SCOPE_LABELS[scope] || scope}</Tag>)}
          </div>
          <Alert
            type="warning"
            showIcon
            content="仅在你刚刚从这台机器发起配对时批准。批准不会把凭证显示在网页中。"
            style={{ marginTop: 18 }}
          />
          {effectiveStatus === 'pending' ? (
            <div className="device-confirm-actions">
              <Button status="danger" loading={deciding === 'deny'} disabled={deciding !== null} onClick={() => void decide('deny')}>拒绝</Button>
              <Button type="primary" loading={deciding === 'approve'} disabled={deciding !== null} onClick={() => void decide('approve')}>批准此设备</Button>
            </div>
          ) : (
            <Alert
              type={effectiveStatus === 'approved' || effectiveStatus === 'consumed' ? 'success' : 'info'}
              content={effectiveStatus === 'approved' || effectiveStatus === 'consumed' ? '已批准。可以关闭此页面。' : '本次请求未获批准。可以关闭此页面。'}
              style={{ marginTop: 18 }}
            />
          )}
          {needsLogin && <Button type="primary" style={{ marginTop: 12 }} onClick={() => (location.href = freshLoginHref())}>重新登录后继续</Button>}
        </Card>
      ) : null}
    </DevicePageShell>
  );
}
