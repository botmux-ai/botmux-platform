// 机器协管者面板（DESIGN-machine-comanager.md §2.3）：查看 / 添加 / 移除同一个面板。
//
// 入口在团队页「管理我的机器人」弹窗的机器分组头（按最初的产品原型）。因为入口挂在
// 团队页，UI 必须让 owner 看清「授权给**勾选的人**」而不是「对整个团队开放」——
// 团队关系在这个平台里从不隐含管理权，见 CURRENT-team-bot-management.md 第八节。
import { useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Avatar,
  Button,
  Checkbox,
  Divider,
  Empty,
  Message,
  Modal,
  Radio,
  Select,
  Space,
  Spin,
  Tag,
  Typography,
} from '@arco-design/web-react';
import { IconExclamationCircleFill, IconUser } from '@arco-design/web-react/icon';
import {
  coManagerRoleOf,
  getCoManagers,
  removeCoManager,
  setCoManagers,
  type CoManager,
  type CoManagerRole,
  type RosterMember,
} from '../api';

/** 默认档的人类可读标签。scopes 是内部词表，不直接摊给用户看。 */
function scopeLabel(c: Pick<CoManager, 'role' | 'scopes'>): string {
  if (coManagerRoleOf(c) === 'viewer') return '只看 Dashboard、会话和终端输出';
  const scopes = c.scopes;
  const canControl = scopes.includes('terminal:control');
  const canManage = scopes.includes('dashboard:manage');
  if (canManage) return '看会话 + 接管终端 + 改配置';
  if (canControl) return '看会话 + 接管终端';
  return '只看会话';
}

function fmtDate(ms: number): string {
  if (!ms) return '';
  const d = new Date(ms);
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export interface CoManagerModalProps {
  visible: boolean;
  machineId: string;
  machineName: string;
  /** 本团队名册（候选人来源）。候选人限本团队成员，所以不需要全租户搜人授权。 */
  roster: RosterMember[];
  /** 自己的 unionId —— 候选列表里要排掉自己（owner 不能授权给自己）。 */
  myUnionId: string;
  onClose: () => void;
  /** 名单变更后通知外层刷新机器列表徽章。 */
  onChanged?: () => void;
}

export function CoManagerModal(props: CoManagerModalProps) {
  const { visible, machineId, machineName, roster, myUnionId, onClose, onChanged } = props;
  const [loading, setLoading] = useState(false);
  const [saving, setSaving] = useState(false);
  const [current, setCurrent] = useState<CoManager[]>([]);
  const [checked, setChecked] = useState<Set<string>>(new Set());
  const [loadError, setLoadError] = useState<string | null>(null);
  // 二期：可选连带授予「改配置」。默认不勾——多数协管场景只要看会话 + 接管终端。
  const [alsoManage, setAlsoManage] = useState(false);
  // 新加的人给什么角色。默认协管，与只读角色上线前的行为一致。
  const [addRole, setAddRole] = useState<CoManagerRole>('co-manager');

  useEffect(() => {
    if (!visible) return;
    let alive = true;
    setLoading(true);
    setLoadError(null);
    getCoManagers(machineId)
      .then((r) => {
        if (!alive) return;
        setCurrent(r.coManagers);
        setChecked(new Set());
      })
      .catch((e) => {
        if (!alive) return;
        setLoadError(
          String(e?.message) === 'store_unavailable'
            ? '机器归属状态暂不可用，请稍后重试'
            : '读取协管者失败',
        );
      })
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [visible, machineId]);

  const currentIds = useMemo(() => new Set(current.map((c) => c.unionId)), [current]);
  // 候选人 = 本团队正式成员，排掉自己和已经是协管者的人。pending（待加入）不能授权：
  // 他还没进租户，授权了也进不来，只会让名单里躺一条永远不生效的记录。
  const candidates = useMemo(
    () => roster.filter((m) => !m.pending && m.unionId !== myUnionId && !currentIds.has(m.unionId)),
    [roster, myUnionId, currentIds],
  );

  async function add() {
    if (!checked.size) return;
    setSaving(true);
    try {
      const next = [...current.map((c) => c.unionId), ...checked];
      // 只给新加的人指定角色；已有的人不列，后端保持原样。
      const roles = Object.fromEntries([...checked].map((id) => [id, addRole])) as Record<string, CoManagerRole>;
      const r = await setCoManagers(machineId, next, addRole === 'co-manager' && alsoManage, roles);
      if (!r.ok) {
        Message.error(
          r.error === 'not_teammate'
            ? '有人已不是本团队成员，无法授权'
            : r.error === 'too_many'
              ? '协管者数量超出上限'
              : r.error === 'machine_changed'
                ? '机器状态已变化，请重新打开本面板'
                : '授权失败',
        );
        return;
      }
      setCurrent(r.coManagers ?? []);
      setChecked(new Set());
      setAlsoManage(false);
      Message.success(`已授权 ${checked.size} 人${addRole === 'viewer' ? '（只读）' : ''}`);
      onChanged?.();
    } finally {
      setSaving(false);
    }
  }

  async function changeRole(c: CoManager, role: CoManagerRole) {
    if (coManagerRoleOf(c) === role) return;
    setSaving(true);
    try {
      const r = await setCoManagers(
        machineId,
        current.map((x) => x.unionId),
        false,
        { [c.unionId]: role },
      );
      if (!r.ok) {
        Message.error(
          r.error === 'not_teammate'
            ? `${c.name} 已不是本团队成员，只能移除`
            : r.error === 'machine_changed'
              ? '机器状态已变化，请重新打开本面板'
              : '修改失败',
        );
        return;
      }
      setCurrent(r.coManagers ?? []);
      Message.success(`已把 ${c.name} 改为${role === 'viewer' ? '只读' : '协管'}`);
      onChanged?.();
    } finally {
      setSaving(false);
    }
  }

  async function remove(c: CoManager) {
    setSaving(true);
    try {
      const r = await removeCoManager(machineId, c.unionId);
      if (!r.ok) {
        Message.error(r.error === 'machine_changed' ? '机器状态已变化，请重新打开' : '移除失败');
        return;
      }
      setCurrent(r.coManagers ?? []);
      Message.success(`已移除 ${c.name}`);
      onChanged?.();
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      title={`${machineName} 的协管者与只读成员`}
      visible={visible}
      onCancel={onClose}
      footer={
        <Space>
          <Button onClick={onClose}>关闭</Button>
          <Button type="primary" loading={saving} disabled={!checked.size} onClick={add}>
            {checked.size ? `授权选中的 ${checked.size} 人` : '授权'}
          </Button>
        </Space>
      }
      unmountOnExit
      style={{ width: 620 }}
    >
      <Typography.Text type="secondary" style={{ fontSize: 13 }}>
        协管者可以打开这台机器的 dashboard、查看会话、接管终端；只读成员只能看 Dashboard、会话列表和终端输出，不能输入、改配置或启停会话。仅限本团队成员，退出团队将自动失去权限。
      </Typography.Text>

      {/* 默认档不是只读——接管终端等于能替 owner 的 CLI 打字，必须说清楚，
          否则 owner 会以为自己只是给了个「看看」的权限。 */}
      <Alert
        type="warning"
        style={{ marginTop: 12 }}
        content="协管的「接管终端」= 能替你的 CLI 打字，这不是只读权限。只想让人看看，请选「只读」。任何人都不能解绑或升级这台机器。"
      />

      {loadError && <Alert type="error" style={{ marginTop: 12 }} content={loadError} />}

      <Divider orientation="left" style={{ marginTop: 16, marginBottom: 8 }}>
        已授权{current.length ? `（${current.length} 人）` : ''}
      </Divider>
      {loading ? (
        <div style={{ textAlign: 'center', padding: 16 }}>
          <Spin />
        </div>
      ) : current.length === 0 ? (
        <Typography.Text type="secondary" style={{ fontSize: 13 }}>
          还没有授权任何人。从下面的团队成员里勾选并授权。
        </Typography.Text>
      ) : (
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          {current.map((c) => (
            <div
              key={c.unionId}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 10,
                padding: '6px 8px',
                borderRadius: 6,
                background: c.leftTeam ? 'var(--color-warning-light-1)' : 'transparent',
              }}
            >
              <Avatar size={28}>
                <IconUser />
              </Avatar>
              <div style={{ flex: 1, minWidth: 0 }}>
                <Space size={6} wrap>
                  <Typography.Text style={{ fontWeight: 500 }}>{c.name}</Typography.Text>
                  <Tag size="small" color={coManagerRoleOf(c) === 'viewer' ? 'gray' : 'arcoblue'}>
                    {scopeLabel(c)}
                  </Tag>
                  {c.leftTeam && (
                    <Tag size="small" color="orange" icon={<IconExclamationCircleFill />}>
                      已退出团队
                    </Tag>
                  )}
                </Space>
                <div>
                  <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                    {fmtDate(c.grantedAt)} 授予
                    {c.leftTeam ? ' · 自动摘除未生效，建议手动清理' : ''}
                  </Typography.Text>
                </div>
              </div>
              <Select
                size="mini"
                style={{ width: 84 }}
                aria-label={`${c.name} 的角色`}
                disabled={saving}
                value={coManagerRoleOf(c)}
                onChange={(v: CoManagerRole) => changeRole(c, v)}
                options={[
                  { label: '协管', value: 'co-manager' },
                  { label: '只读', value: 'viewer' },
                ]}
              />
              <Button size="mini" status="danger" loading={saving} onClick={() => remove(c)}>
                移除
              </Button>
            </div>
          ))}
        </Space>
      )}

      <Divider orientation="left" style={{ marginTop: 16, marginBottom: 8 }}>
        从团队成员中添加
      </Divider>
      {candidates.length === 0 ? (
        <Empty description="本团队没有可添加的成员了" />
      ) : (
        <div style={{ maxHeight: 220, overflow: 'auto' }}>
          <Space direction="vertical" size={4} style={{ width: '100%' }}>
            {candidates.map((m) => (
              <Checkbox
                key={m.unionId}
                checked={checked.has(m.unionId)}
                onChange={(v) => {
                  const next = new Set(checked);
                  if (v) next.add(m.unionId);
                  else next.delete(m.unionId);
                  setChecked(next);
                }}
              >
                <Space size={8}>
                  <Avatar size={24}>{m.avatar ? <img src={m.avatar} alt="" /> : <IconUser />}</Avatar>
                  <Typography.Text>{m.name}</Typography.Text>
                </Space>
              </Checkbox>
            ))}
          </Space>
        </div>
      )}
      <div style={{ marginTop: 12 }}>
        <Typography.Text style={{ marginRight: 8 }}>授予角色</Typography.Text>
        <Radio.Group
          type="button"
          size="small"
          aria-label="新授权成员的角色"
          value={addRole}
          onChange={(v: CoManagerRole) => setAddRole(v)}
          options={[
            { label: '协管', value: 'co-manager' },
            { label: '只读', value: 'viewer' },
          ]}
        />
        {addRole === 'viewer' && (
          <div style={{ marginTop: 4 }}>
            <Typography.Text type="secondary" style={{ fontSize: 12 }}>
              只读成员看不到 token 和配置，也不能往终端输入。需要这台机器的 botmux 不低于 3.16.0，更旧的版本平台会拒绝只读访问。
            </Typography.Text>
          </div>
        )}
      </div>
      {/* 改配置是协管的可选勾选项，不是第三档角色；只读不带它。 */}
      <div style={{ marginTop: 12, display: addRole === 'viewer' ? 'none' : undefined }}>
        <Checkbox checked={alsoManage} onChange={setAlsoManage}>
          <Typography.Text>同时允许改机器配置</Typography.Text>
        </Checkbox>
        <div style={{ paddingLeft: 24 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            额外放开 settings / 定时任务 / 群管理的读写。仍然不含 debug shell、解绑、升级、改 bot
            启动命令。需要这台机器的 botmux 版本足够新，旧版本会忽略该权限。
          </Typography.Text>
        </div>
      </div>
      <div style={{ marginTop: 8 }}>
        <Typography.Text type="secondary" style={{ fontSize: 12 }}>
          候选人来自本团队名册，不需要额外搜人授权。保存需要 10 分钟内的飞书登录，过期会自动引导重新登录。
        </Typography.Text>
      </div>
    </Modal>
  );
}
