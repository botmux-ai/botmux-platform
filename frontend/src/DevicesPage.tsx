import { useCallback, useEffect, useState } from 'react';
import '@arco-design/web-react/dist/css/arco.css';
import { Alert, Button, Card, Empty, Message, Popconfirm, Space, Spin, Tag, Typography } from '@arco-design/web-react';
import { DeviceApiError, deviceApi, freshLoginHref, type DeviceScope, type ManagedDevice } from './device-api';
import DevicePageShell from './components/DevicePageShell';
import { fmtAgo } from './util';

const SCOPE_LABELS: Record<DeviceScope, string> = {
  'machines:read': '查看机器',
  'sessions:open': '查看并打开会话',
  'terminal:control': '操作终端',
  'dashboard:manage': '管理 Dashboard',
  'self:refresh': '刷新凭证',
};

function formatDate(ms: number): string {
  return new Intl.DateTimeFormat('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit' }).format(ms);
}

export default function DevicesPage() {
  const [devices, setDevices] = useState<ManagedDevice[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [needsLogin, setNeedsLogin] = useState(false);
  const [revoking, setRevoking] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setDevices(await deviceApi.listDevices());
      setError(null);
      setNeedsLogin(false);
    } catch (e) {
      const apiError = e instanceof DeviceApiError ? e : null;
      setNeedsLogin(apiError?.status === 401);
      setError(
        apiError?.status === 401 ? '为保护设备凭证，请重新用飞书登录后查看设备' :
        apiError?.code === 'store_unavailable' ? '设备服务暂时不可用，请稍后重试' :
        '设备列表加载失败，请稍后重试',
      );
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function revoke(device: ManagedDevice) {
    setRevoking(device.deviceId);
    try {
      await deviceApi.revokeDevice(device.deviceId);
      setDevices((current) => current?.map((d) => d.deviceId === device.deviceId ? { ...d, status: 'revoked' } : d) || current);
      Message.success('设备已吊销');
    } catch (e) {
      if (e instanceof DeviceApiError && e.status === 401) {
        setNeedsLogin(true);
        setError('登录状态已过期，请重新登录后再吊销');
      } else if (e instanceof DeviceApiError && e.code === 'device_not_found') {
        Message.warning('设备不存在或不属于当前账号');
        void load();
      } else {
        Message.error('吊销失败，请稍后重试');
      }
    } finally {
      setRevoking(null);
    }
  }

  return (
    <DevicePageShell title="我的设备" subtitle="查看并吊销曾经批准的桌面设备。设备名称由设备自报，仅供识别。">
      <Alert
        type="info"
        showIcon
        content="吊销会立即阻止新请求；已连接会话在同节点通常 1 秒内断开，跨节点最迟约 70 秒。"
        style={{ marginBottom: 12 }}
      />
      {error && (
        <Card style={{ marginBottom: 12 }}>
          <Alert type={needsLogin ? 'info' : 'warning'} content={error} />
          <Space style={{ marginTop: 12 }}>
            {needsLogin && <Button type="primary" onClick={() => (location.href = freshLoginHref())}>重新登录</Button>}
            <Button onClick={() => void load()}>重试</Button>
          </Space>
        </Card>
      )}
      {devices === null && !error ? (
        <Card><div className="device-loading"><Spin tip="加载设备…" /></div></Card>
      ) : devices?.length === 0 ? (
        <Card><Empty description="还没有批准过桌面设备" /></Card>
      ) : (
        devices?.map((device) => (
          <Card key={device.deviceId} className="managed-device-card">
            <div className="managed-device-row">
              <div className="managed-device-main">
                <div className="managed-device-title">
                  <Typography.Text bold>{device.deviceName}</Typography.Text>
                  <Tag>设备自报名称</Tag>
                  <Tag color={device.status === 'active' ? 'green' : 'gray'}>{device.status === 'active' ? '有效' : '已吊销'}</Tag>
                </div>
                <Typography.Text type="secondary">
                  {device.deviceKind === 'desktop-ide' ? '桌面 IDE' : device.deviceKind}
                  {' · '}批准于 {formatDate(device.enrolledAt)}
                  {' · '}最近使用 {fmtAgo(device.lastSeenAt)}
                  {' · '}有效至 {formatDate(device.deviceExp)}
                </Typography.Text>
                <div className="device-scope-list">
                  {device.scopes.map((scope) => <Tag key={scope}>{SCOPE_LABELS[scope] || scope}</Tag>)}
                </div>
              </div>
              <Popconfirm
                focusLock
                position="br"
                title="吊销这个设备？"
                content="吊销后需要重新配对才能使用。新请求立即失效，已连接会话最迟约 70 秒断开。"
                okText="确认吊销"
                cancelText="取消"
                okButtonProps={{ status: 'danger' }}
                disabled={device.status !== 'active' || revoking !== null}
                onOk={() => revoke(device)}
              >
                <Button status="danger" disabled={device.status !== 'active' || revoking !== null} loading={revoking === device.deviceId}>吊销</Button>
              </Popconfirm>
            </div>
          </Card>
        ))
      )}
    </DevicePageShell>
  );
}
