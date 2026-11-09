import { useState } from 'react';
import { Card, Button, Tag, Space, Empty, Spin, Message, Typography, Input, Popconfirm } from '@arco-design/web-react';
import {
  IconPlus,
  IconCopy,
  IconEdit,
  IconCheck,
  IconClose,
  IconDelete,
  IconUserGroup,
} from '@arco-design/web-react/icon';
import type { Machine } from '../api';
import { bindCode, openMachine, renameMachine, unbindMachine, upgradeMachine } from '../api';
import { fmtAgo, copyText } from '../util';
import { machineVersionStatus } from '../machine-version';

interface Props {
  machines: Machine[] | null;
  /** 我被授权协管的机器（不是我 owner 的）。 */
  managedMachines?: Machine[] | null;
  latestVersion: string | null;
  loading: boolean;
  error: boolean;
  onChanged: () => void;
}

interface BindState {
  command: string;
  expiresInSec: number;
  ttl: number;
}

export default function Machines({
  machines,
  managedMachines,
  latestVersion,
  loading,
  error,
  onChanged,
}: Props) {
  const [bind, setBind] = useState<BindState | null>(null);
  const [binding, setBinding] = useState(false);
  const [openingId, setOpeningId] = useState<string | null>(null);
  const [upgradingId, setUpgradingId] = useState<string | null>(null);
  const [degradedIds, setDegradedIds] = useState<Set<string>>(() => new Set());
  const [unbindingId, setUnbindingId] = useState<string | null>(null);
  // 重命名：当前编辑中的机器 id + 输入值 + 保存中。本地名称覆盖让重命名后立刻显示（轮询稍后会带上后端值）。
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editVal, setEditVal] = useState('');
  const [savingRename, setSavingRename] = useState(false);
  const [nameOverrides, setNameOverrides] = useState<Record<string, string>>({});

  function startRename(m: Machine, displayName: string) {
    setEditingId(m.machineId);
    setEditVal(displayName);
  }

  async function saveRename(m: Machine) {
    const name = editVal.trim();
    if (!name) {
      Message.warning('名称不能为空');
      return;
    }
    setSavingRename(true);
    try {
      const r = await renameMachine(m.machineId, name);
      if (r.ok) {
        setNameOverrides((prev) => ({ ...prev, [m.machineId]: r.name || name }));
        setEditingId(null);
        Message.success('已重命名');
      } else if (r.status === 404) {
        Message.error('机器不存在');
      } else {
        Message.error('重命名失败');
      }
    } finally {
      setSavingRename(false);
    }
  }

  async function showBind() {
    setBinding(true);
    try {
      const j = await bindCode();
      setBind({ command: j.command, expiresInSec: j.expiresInSec, ttl: j.expiresInSec });
      // 倒计时；到 0 自动收起
      const start = Date.now();
      const timer = setInterval(() => {
        const left = j.expiresInSec - Math.floor((Date.now() - start) / 1000);
        if (left < 0) {
          clearInterval(timer);
          setBind((cur) => (cur && cur.command === j.command ? null : cur));
        } else {
          setBind((cur) => (cur && cur.command === j.command ? { ...cur, ttl: left } : cur));
        }
      }, 1000);
    } catch {
      Message.error('获取绑定码失败');
    } finally {
      setBinding(false);
    }
  }

  async function doOpen(m: Machine) {
    const target = window.open('', '_blank');
    if (!target) {
      Message.error('浏览器拦截了弹窗，请允许本站打开弹窗后重试');
      return;
    }
    setOpeningId(m.machineId);
    try {
      const j = await openMachine(m.machineId);
      if (j.status === 200 && j.openUrl) {
        setDegradedIds((prev) => {
          if (!prev.has(m.machineId)) return prev;
          const next = new Set(prev);
          next.delete(m.machineId);
          return next;
        });
        target.location.replace(j.openUrl);
      } else if (j.status === 503 && j.error === 'dashboard_unreachable') {
        target.close();
        setDegradedIds((prev) => new Set(prev).add(m.machineId));
        Message.warning('Dashboard 通道异常，请稍后重试');
      } else {
        target.close();
        Message.error('打开失败：' + (j.error || '未知'));
      }
    } catch {
      target.close();
      Message.error('打开失败，请稍后重试');
    } finally {
      setOpeningId(null);
    }
  }

  async function doUnbind(m: Machine) {
    setUnbindingId(m.machineId);
    try {
      const r = await unbindMachine(m.machineId);
      if (r.ok) {
        Message.success('已解绑');
        onChanged(); // 立即刷新（5s 轮询之外的即时反馈）
      } else if (r.status === 404) {
        Message.error('机器不存在或非本人');
        onChanged();
      } else {
        Message.error('解绑失败，请稍后重试');
      }
    } finally {
      setUnbindingId(null);
    }
  }

  async function doUpgrade(m: Machine) {
    setUpgradingId(m.machineId);
    Message.info('正在升级，完成后将自动重启 Botmux…');
    try {
      const r = await upgradeMachine(m.machineId);
      if (r.ok) {
        if (r.changed) Message.success(`已升级到 ${r.newVersion || '最新版本'}，正在重启`);
        else Message.success('当前已经是最新版，正在重启以应用');
        onChanged();
      } else if (r.status === 409) {
        Message.warning('升级正在进行中，请稍后再试');
      } else if (r.error === 'node_too_old') {
        Message.error('Node.js 版本过低，请先升级 Node.js');
      } else if (r.error === 'local_dev_no_update') {
        Message.error('本地开发安装不支持一键升级');
      } else if (r.error === 'upgrade_not_supported') {
        Message.error('当前版本过旧，不支持一键升级，请在机器上运行 botmux upgrade');
      } else if (r.error === 'unsupported_install_method') {
        Message.error('当前安装方式不支持一键升级，请使用原安装方式手动升级');
      } else if (r.error === 'restart_failed' && r.updateInstalled) {
        Message.error('升级已安装，但自动重启失败，请手动重启 Botmux');
      } else {
        Message.error('升级失败' + (r.detail ? `：${r.detail}` : '，请稍后重试'));
      }
    } catch {
      Message.error('升级失败，请稍后重试');
    } finally {
      setUpgradingId(null);
    }
  }

  return (
    <>
      <div className="section-head">
        <h2>我可管理的机器</h2>
        <Button type="primary" icon={<IconPlus />} loading={binding} onClick={showBind}>
          绑定新机器
        </Button>
      </div>

      {bind && (
        <Card style={{ marginBottom: 12 }}>
          <Typography.Text type="secondary">
            在要绑定的机器上执行（{bind.expiresInSec}s 内有效）：
          </Typography.Text>
          <code className="mono-block">{bind.command}</code>
          <Space>
            <Button
              size="small"
              icon={<IconCopy />}
              onClick={async () => {
                (await copyText(bind.command)) ? Message.success('已复制命令') : Message.error('复制失败');
              }}
            >
              复制命令
            </Button>
            <Typography.Text type="secondary" style={{ fontSize: 13 }}>
              {bind.ttl}s 后过期
            </Typography.Text>
          </Space>
        </Card>
      )}

      {error && !machines ? (
        <Card>
          <Empty description="加载机器列表失败，稍后自动重试…" />
        </Card>
      ) : loading && !machines ? (
        <Card>
          <div style={{ textAlign: 'center', padding: 24 }}>
            <Spin />
          </div>
        </Card>
      ) : !machines || machines.length === 0 ? (
        <Card>
          <Empty
            description={
              <span>
                还没有在线机器。点「绑定新机器」，在那台机器上跑 <code>botmux bind &lt;码&gt;</code>。
              </span>
            }
          />
        </Card>
      ) : (
        machines.map((m) => {
          const version = machineVersionStatus(m.botmuxVersion, latestVersion);
          const outdated = version.outdated;
          const displayName = nameOverrides[m.machineId] ?? m.name;
          const editing = editingId === m.machineId;
          const dashboardDegraded = !m.stale && degradedIds.has(m.machineId);
          return (
            <Card key={m.machineId} style={{ marginBottom: 12 }}>
              <div className="machine-row">
                <div className="machine-meta">
                  <Space>
                    {editing ? (
                      <>
                        <Input
                          autoFocus
                          size="small"
                          style={{ width: 180 }}
                          value={editVal}
                          maxLength={64}
                          onChange={setEditVal}
                          onPressEnter={() => saveRename(m)}
                          disabled={savingRename}
                        />
                        <Button
                          size="mini"
                          type="text"
                          icon={<IconCheck />}
                          loading={savingRename}
                          onClick={() => saveRename(m)}
                          aria-label="保存名称"
                        />
                        <Button
                          size="mini"
                          type="text"
                          icon={<IconClose />}
                          disabled={savingRename}
                          onClick={() => setEditingId(null)}
                          aria-label="取消"
                        />
                      </>
                    ) : (
                      <>
                        <Typography.Text bold>{displayName}</Typography.Text>
                        <Button
                          size="mini"
                          type="text"
                          icon={<IconEdit />}
                          onClick={() => startRename(m, displayName)}
                          aria-label="重命名机器"
                        />
                      </>
                    )}
                    <Tag color={outdated ? 'orange' : version.unknown ? 'gray' : 'green'}>
                      {version.label}
                      {outdated ? ` · 建议升级到 ${latestVersion}` : ''}
                    </Tag>
                    {/* 不点开也能看见这台机器开了权限给别人（授权/查看入口在团队页弹窗）。 */}
                    {!!m.coManagerCount && (
                      <Tag color="arcoblue" icon={<IconUserGroup />}>
                        协管 {m.coManagerCount}
                      </Tag>
                    )}
                  </Space>
                  <div>
                    {m.stale ? (
                      <Tag>
                        <span className="dot off" />
                        疑似离线 · {fmtAgo(m.lastSeen)}
                      </Tag>
                    ) : dashboardDegraded ? (
                      <Tag color="orange">Dashboard 通道异常</Tag>
                    ) : (
                      <Tag color="green">
                        <span className="dot on" />
                        在线
                      </Tag>
                    )}
                  </div>
                </div>
                <Space wrap>
                  {outdated && (
                    <Popconfirm
                      focusLock
                      position="br"
                      title="升级并重启这台机器？"
                      content="升级完成后会自动重启 Botmux，运行中的会话会短暂中断并自动恢复。"
                      okText="升级"
                      cancelText="取消"
                      okButtonProps={{ status: 'warning' }}
                      disabled={m.stale || upgradingId !== null}
                      onOk={() => doUpgrade(m)}
                    >
                      <Button
                        status="warning"
                        disabled={m.stale || upgradingId !== null}
                        loading={upgradingId === m.machineId}
                      >
                        一键升级
                      </Button>
                    </Popconfirm>
                  )}
                  <Popconfirm
                    focusLock
                    position="br"
                    title="解绑这台机器？"
                    content="将删除该机器的绑定记录并吊销其凭证，机器随即从列表移除。下次在该机器上执行 botmux bind 即可重新绑定。"
                    okText="解绑"
                    cancelText="取消"
                    okButtonProps={{ status: 'danger' }}
                    disabled={upgradingId === m.machineId}
                    onOk={() => doUnbind(m)}
                  >
                    <Button
                      status="danger"
                      type="text"
                      icon={<IconDelete />}
                      disabled={upgradingId === m.machineId}
                      loading={unbindingId === m.machineId}
                    >
                      解绑
                    </Button>
                  </Popconfirm>
                  <Button
                    type="primary"
                    status={dashboardDegraded ? 'warning' : undefined}
                    disabled={m.stale || upgradingId === m.machineId}
                    loading={openingId === m.machineId}
                    onClick={() => doOpen(m)}
                  >
                    {dashboardDegraded ? '重试打开' : '打开 dashboard'}
                  </Button>
                </Space>
              </div>
            </Card>
          );
        })
      )}

      {/* 「我有管理权限的机器」：别人授权给我的。行内只留「打开 dashboard」——
          解绑 / 升级 / 改名是 owner 专属（后端也会 403），画出来只会让人点了才知道没权限。 */}
      {!!managedMachines?.length && (
        <>
          <div className="section-head" style={{ marginTop: 24 }}>
            <h2>我有权限的机器</h2>
          </div>
          {managedMachines.map((m) => (
            <Card key={m.machineId} style={{ marginBottom: 12 }}>
              <div className="machine-row">
                <div className="machine-meta">
                  <Space>
                    <Typography.Text bold>{m.name}</Typography.Text>
                    <Tag>{m.botmuxVersion}</Tag>
                    {m.ownerName && (
                      <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                        所有人：{m.ownerName}
                      </Typography.Text>
                    )}
                  </Space>
                  <div>
                    <Space size={6} wrap>
                      {m.stale ? (
                        <Tag>
                          <span className="dot off" />
                          疑似离线 · {fmtAgo(m.lastSeen)}
                        </Tag>
                      ) : (
                        <Tag color="green">
                          <span className="dot on" />
                          在线
                        </Tag>
                      )}
                      <Tag color={m.myRole === 'viewer' ? 'gray' : 'arcoblue'}>
                        {m.myRole === 'viewer'
                          ? '只读：看 Dashboard、会话和终端输出'
                          : m.myScopes?.includes('terminal:control')
                            ? '看会话 + 接管终端'
                            : '只看会话'}
                      </Tag>
                    </Space>
                  </div>
                </div>
                <Space>
                  <Button
                    type="primary"
                    disabled={m.stale || openingId === m.machineId}
                    loading={openingId === m.machineId}
                    onClick={() => doOpen(m)}
                  >
                    打开 dashboard
                  </Button>
                </Space>
              </div>
            </Card>
          ))}
        </>
      )}
    </>
  );
}
