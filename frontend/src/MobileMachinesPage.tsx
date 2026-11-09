import { useCallback, useEffect, useState } from 'react';
import '@arco-design/web-react/dist/css/arco.css';
import { Alert, Button, Card, Empty, Message, Spin, Tag, Typography } from '@arco-design/web-react';
import { getMachines, getMe, loginHref, openMachine, type Machine, type Me } from './api';
import { fmtAgo } from './util';

export default function MobileMachinesPage() {
  const [me, setMe] = useState<Me | null | undefined>(undefined);
  const [machines, setMachines] = useState<Machine[] | null>(null);
  const [error, setError] = useState(false);
  const [openingId, setOpeningId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const result = await getMachines();
      setMachines(result.machines);
      setError(false);
    } catch (e) {
      if (e instanceof Error && e.message === 'unauthenticated') setMe(null);
      else setError(true);
    }
  }, []);

  useEffect(() => { void getMe().then(setMe); }, []);
  useEffect(() => {
    if (!me) return;
    void load();
    const timer = setInterval(() => void load(), 5000);
    return () => clearInterval(timer);
  }, [load, me]);

  async function open(machine: Machine) {
    setOpeningId(machine.machineId);
    try {
      const result = await openMachine(machine.machineId);
      if (result.status === 200 && result.openUrl) location.assign(result.openUrl);
      else Message.error(result.error === 'dashboard_unreachable' ? 'Dashboard 通道暂不可用' : '打开失败，请稍后重试');
    } catch {
      Message.error('打开失败，请稍后重试');
    } finally {
      setOpeningId(null);
    }
  }

  return (
    <div className="mobile-shell">
      <header className="mobile-header">
        <div>
          <div className="mobile-brand">botmux</div>
          <Typography.Text type="secondary">我的机器</Typography.Text>
        </div>
        <a href="/?desktop=1">完整平台</a>
      </header>
      <main className="mobile-content">
        {me === undefined ? (
          <Card><div className="device-loading"><Spin tip="加载中…" /></div></Card>
        ) : me === null ? (
          <Card>
            <Typography.Title heading={5}>飞书登录</Typography.Title>
            <Typography.Paragraph type="secondary">登录后查看并打开你的 botmux 机器。</Typography.Paragraph>
            <Button type="primary" long onClick={() => (location.href = loginHref())}>飞书登录</Button>
          </Card>
        ) : (
          <>
            <div className="mobile-welcome">
              <Typography.Title heading={4}>你好，{me.name}</Typography.Title>
              <Typography.Text type="secondary">本期移动端仅提供机器列表和 Dashboard 跳转。</Typography.Text>
            </div>
            {error && <Alert type="warning" content="机器列表加载失败，正在自动重试" style={{ marginBottom: 12 }} />}
            {machines === null && !error ? (
              <Card><div className="device-loading"><Spin /></div></Card>
            ) : machines?.length === 0 ? (
              <Card><Empty description="还没有绑定机器" /></Card>
            ) : machines?.map((machine) => (
              <Card key={machine.machineId} className="mobile-machine-card">
                <div className="mobile-machine-title">
                  <Typography.Text bold>{machine.name}</Typography.Text>
                  <Tag color={machine.stale ? 'gray' : 'green'}>{machine.stale ? '离线' : '在线'}</Tag>
                </div>
                <Typography.Text type="secondary">
                  {machine.botmuxVersion} · {machine.stale ? `最后在线 ${fmtAgo(machine.lastSeen)}` : '可打开'}
                </Typography.Text>
                <Button
                  type="primary"
                  long
                  className="mobile-open-button"
                  disabled={machine.stale || openingId !== null}
                  loading={openingId === machine.machineId}
                  onClick={() => void open(machine)}
                >
                  打开 Dashboard
                </Button>
              </Card>
            ))}
          </>
        )}
      </main>
    </div>
  );
}

