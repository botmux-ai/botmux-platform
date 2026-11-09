import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Card,
  Button,
  Space,
  Empty,
  Spin,
  Tag,
  Typography,
  Modal,
  Input,
  Message,
  Avatar,
  Checkbox,
  Dropdown,
  Menu,
  Tooltip,
  Radio,
  Alert,
  Select,
} from '@arco-design/web-react';
import {
  IconPlus,
  IconSearch,
  IconDown,
  IconRobot,
  IconUserGroup,
  IconUserAdd,
  IconEdit,
  IconCheck,
  IconClose,
  IconMore,
  IconLock,
} from '@arco-design/web-react/icon';
import type { Team, RosterMember, RosterMachine, CreateGroupResult, TeamBotRef, Bot, BotDirMode } from '../api';
import {
  createTeam,
  leaveTeam,
  disbandTeam,
  renameTeam,
  acceptInvite,
  getRoster,
  createGroup,
  updateTeamBots,
  joinHall,
  setBotDirMode,
  putTeamAdmins,
} from '../api';
import InvitePanel from './InvitePanel';
import { CoManagerModal } from './CoManagers';
import { saveWithDraft, takeDraft, inviteScopeDraftKey } from '../draft';

/** 团队机器人清单草稿键：暂存「选中的 bot 键集合」（machineId::appId[]）。 */
function manageBotsDraftKey(teamId: string): string {
  return `team-bots:${teamId}`;
}
/** 团队管理员草稿键：暂存选中的成员 unionId[]。 */
function adminsDraftKey(teamId: string): string {
  return `team-admins:${teamId}`;
}

interface Props {
  teams: Team[] | null;
  loading: boolean;
  error: boolean;
  onChanged: () => void;
  myUnionId: string;
}

function initial(name: string): string {
  return (name || '?').trim().charAt(0).toUpperCase() || '?';
}

// 单个拉群结果的反馈：成功→「已拉群」+（有 shareLink 时）弹窗给开群链接；
// autoInviteUnavailable→提示需手动加入；失败→错误。
function reportGroupResult(r: CreateGroupResult): void {
  if (r.ok) {
    if (r.autoInviteUnavailable) {
      Message.warning('群已建，但你需要手动加入');
    } else {
      Message.success('已拉群');
    }
    if (r.invalidBotIds && r.invalidBotIds.length) {
      Message.info(`有 ${r.invalidBotIds.length} 个 bot 未能加入（已跳过）`);
    }
    if (r.invalidOwnerUnionIds && r.invalidOwnerUnionIds.length) {
      Message.info(`有 ${r.invalidOwnerUnionIds.length} 位成员未能自动入群（可用分享链接加入）`);
    }
    if (r.shareLink) {
      const link = r.shareLink;
      Modal.info({
        title: '群已创建',
        content: r.autoInviteUnavailable ? '机器人无法自动把你加进群，请用下方链接手动加入：' : '群已创建，可点击下方打开。',
        okText: '打开飞书群',
        onOk: () => {
          window.open(link, '_blank');
        },
      });
    }
  } else {
    Message.error('拉群失败：' + (r.error || r.status));
  }
}

// 选择键：同一 appId 理论上只属于一台机器，但名册按 人→机器→bot 展示，键含 machineId 保证勾选行唯一。
function selKey(machineId: string, appId: string): string {
  return `${machineId}::${appId}`;
}

// 按 bot 名过滤名册：只保留含匹配 bot 的成员/机器，并把每台机器的 bots 收窄到匹配项。
// botQ 为空时原样返回（不裁剪 bots）。
function filterRosterByBot(members: RosterMember[], botQ: string): RosterMember[] {
  if (!botQ) return members;
  const out: RosterMember[] = [];
  for (const m of members) {
    const machines = [];
    for (const x of m.machines) {
      const bots = (x.bots || []).filter((b) => b.name.toLowerCase().includes(botQ));
      if (bots.length) machines.push({ ...x, bots });
    }
    if (machines.length) out.push({ ...m, machines });
  }
  return out;
}

// 收窄名册到「已加入团队」的 bot：丢掉 inTeam=false 的 bot，以及随之变空的机器。
// 成员（人）始终保留——刚接受邀请、还没添加机器人的成员也要在名册里可见。
function onlyInTeam(members: RosterMember[]): RosterMember[] {
  return members.map((m) => {
    const machines = [];
    for (const x of m.machines) {
      const bots = (x.bots || []).filter((b) => b.inTeam);
      if (bots.length) machines.push({ ...x, bots });
    }
    return { ...m, machines };
  });
}

// 团队机器人去重清单（按 appId；入参需已 onlyInTeam 收窄）——用于卡片概览与拉群计数。
function collectTeamBots(members: RosterMember[]): Bot[] {
  const seen = new Map<string, Bot>();
  for (const m of members)
    for (const x of m.machines) for (const b of x.bots || []) if (!seen.has(b.appId)) seen.set(b.appId, b);
  return [...seen.values()];
}

// bot「默认目录模式」徽标：off=橙色警示（队友没法直接用），default/oncall=正常标注，未知（离线）不显示。
function DirModeTag({ bot }: { bot: Bot }) {
  if (bot.dirMode === 'oncall')
    return (
      <Tooltip content={`Oncall 模式：${bot.dirModeDir || ''} —— 新进普通群自动绑定该目录并开放群内对话`}>
        <Tag size="small" color="green">
          oncall
        </Tag>
      </Tooltip>
    );
  if (bot.dirMode === 'default')
    return (
      <Tooltip content={`默认目录：${bot.dirModeDir || ''}`}>
        <Tag size="small" color="gray">
          默认目录
        </Tag>
      </Tooltip>
    );
  if (bot.dirMode === 'off')
    return (
      <Tooltip content="未配置默认目录 / oncall：新会话会弹出「选仓库」卡片，其他团队成员无法直接使用，需要机器人所有人配置">
        <Tag size="small" color="orange">
          未配置目录
        </Tag>
      </Tooltip>
    );
  return null;
}

/** 「我的团队机器人」压平视图（配置弹窗用）：bot + 所在机器。 */
interface MyTeamBot {
  machineId: string;
  machineName: string;
  online: boolean;
  appId: string;
  name: string;
  avatar?: string;
  dirMode?: BotDirMode | null;
  dirModeDir?: string | null;
}

// 单个 bot 的目录模式编辑行：三选一 Radio + 目录输入 + 保存。基线取自名册当前值；
// 保存成功后 onSaved 刷新名册，基线随之更新（行内 state 不被轮询冲掉——只初始化一次）。
function BotDirRow({ bot, onSaved }: { bot: MyTeamBot; onSaved: () => void }) {
  const [mode, setMode] = useState<BotDirMode>(bot.dirMode === 'default' || bot.dirMode === 'oncall' ? bot.dirMode : 'off');
  const [dir, setDir] = useState(bot.dirModeDir || '');
  const [saving, setSaving] = useState(false);
  const editable = bot.online;
  const baseMode: BotDirMode = bot.dirMode === 'default' || bot.dirMode === 'oncall' ? bot.dirMode : 'off';
  const dirty = mode !== baseMode || (mode !== 'off' && dir.trim() !== (bot.dirModeDir || ''));

  async function save() {
    const workingDir = dir.trim();
    if (mode !== 'off' && !workingDir) {
      Message.warning('请填写机器上的目录绝对路径');
      return;
    }
    setSaving(true);
    try {
      const r = await setBotDirMode(bot.machineId, bot.appId, mode, workingDir);
      if (!r.ok) {
        Message.error(r.error === 'machine_unreachable' ? '机器不在线，稍后再试' : `保存失败：${r.error || r.status}`);
        return;
      }
      Message.success(`已更新 ${bot.name} 的目录模式（下个新会话生效）`);
      onSaved();
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="roster-member">
      <Space align="center" size={8} wrap>
        <Avatar size={24}>{bot.avatar ? <img alt={bot.name} src={bot.avatar} /> : initial(bot.name)}</Avatar>
        <Typography.Text bold style={{ fontSize: 13 }}>
          {bot.name}
        </Typography.Text>
        <Tag size="small">{bot.machineName}</Tag>
        {!bot.online && (
          <Tag size="small" color="gray">
            机器离线
          </Tag>
        )}
        {bot.online && bot.dirMode == null && (
          <Tag size="small" color="gray">
            当前配置未知
          </Tag>
        )}
      </Space>
      <div style={{ marginTop: 8 }}>
        <Radio.Group size="small" type="button" value={mode} onChange={setMode} disabled={!editable || saving}>
          <Radio value="off">关闭</Radio>
          <Radio value="default">默认目录</Radio>
          <Radio value="oncall">Oncall</Radio>
        </Radio.Group>
      </div>
      {mode !== 'off' && (
        <Input
          style={{ marginTop: 8 }}
          size="small"
          placeholder="机器上的目录绝对路径，如 /home/you/repo"
          value={dir}
          onChange={setDir}
          disabled={!editable || saving}
          onPressEnter={() => dirty && save()}
        />
      )}
      <div style={{ marginTop: 8, display: 'flex', justifyContent: 'flex-end' }}>
        <Button size="mini" type="primary" loading={saving} disabled={!editable || !dirty} onClick={save}>
          保存
        </Button>
      </div>
    </div>
  );
}

// 「机器人目录配置」弹窗：列我在本团队的全部机器人，逐个设置默认目录模式。
// 队友能否直接使用取决于该配置——这是团队协作里 bot 主人的关键一步。
function BotDirModal({
  bots,
  visible,
  onClose,
  onSaved,
}: {
  bots: MyTeamBot[];
  visible: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  return (
    <Modal
      title="机器人目录配置"
      visible={visible}
      onCancel={onClose}
      footer={<Button onClick={onClose}>关闭</Button>}
      unmountOnExit
    >
      <Typography.Text type="secondary" style={{ fontSize: 13 }}>
        其他团队成员能否直接使用机器人，取决于默认目录模式（修改后从下一个新会话生效）：
      </Typography.Text>
      <ul style={{ margin: '6px 0 0', paddingLeft: 18, color: 'var(--color-text-3)', fontSize: 12, lineHeight: 1.9 }}>
        <li>
          <b>关闭</b>：新会话弹出「选仓库」卡片，其他团队成员无法直接使用
        </li>
        <li>
          <b>默认目录</b>：新会话固定进该目录、跳过选仓库，不改任何权限
        </li>
        <li>
          <b>Oncall</b>：默认目录基础上，新进普通群自动绑定并开放群内对话（值班 / 对外支持）
        </li>
      </ul>
      <div style={{ marginTop: 8, maxHeight: 420, overflow: 'auto' }}>
        {bots.length === 0 ? (
          <Typography.Text type="secondary">你在本团队还没有机器人——先在「管理我的机器人」里添加。</Typography.Text>
        ) : (
          bots.map((b) => <BotDirRow key={`${b.machineId}::${b.appId}`} bot={b} onSaved={onSaved} />)
        )}
      </div>
    </Modal>
  );
}

// 每个团队卡片自己拉名册（挂载即拉 + 轮询），卡片概览/详情/弹窗共享同一份数据。
function useRoster(teamId: string): { members: RosterMember[] | null; unavailable: boolean; reload: () => void } {
  const [members, setMembers] = useState<RosterMember[] | null>(null);
  const [unavailable, setUnavailable] = useState(false);
  const alive = useRef(true);

  async function load() {
    const r = await getRoster(teamId);
    if (!alive.current) return;
    if (r === null) {
      setUnavailable(true);
      return;
    }
    setUnavailable(false);
    setMembers(r);
  }

  useEffect(() => {
    alive.current = true;
    load();
    const t = setInterval(load, 10000); // 卡片常驻展示概览，轮询放缓到 10s
    return () => {
      alive.current = false;
      clearInterval(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [teamId]);

  return { members, unavailable, reload: load };
}

// 头像列：一排小头像 + 溢出「+N」，每个头像 hover 出名字。不用 Avatar.Group 是为了给每个头像包 Tooltip。
function AvatarStrip({
  items,
  max = 10,
}: {
  items: { key: string; name: string; avatar?: string; dim?: boolean; tip?: string }[];
  max?: number;
}) {
  const shown = items.slice(0, max);
  const extra = items.length - shown.length;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap' }}>
      {shown.map((it) => (
        <Tooltip key={it.key} content={it.tip || it.name}>
          <Avatar size={26} style={it.dim ? { opacity: 0.4 } : undefined}>
            {it.avatar ? <img alt={it.name} src={it.avatar} /> : initial(it.name)}
          </Avatar>
        </Tooltip>
      ))}
      {extra > 0 && (
        <Tooltip content={items.slice(max).map((it) => it.name).join('、')}>
          <Avatar size={26} style={{ backgroundColor: 'var(--color-fill-3)', color: 'var(--color-text-2)', fontSize: 12 }}>
            +{extra}
          </Avatar>
        </Tooltip>
      )}
    </div>
  );
}

// 「拉群」弹窗：专注的任务流——默认全选团队机器人，可勾掉不需要的，填个群名就建。
// 建群由平台机器人直建，不依赖任何成员机器在线——离线机器的 bot 也会进群（上线后即可应答）。
// 群里的人 = 发起人 + 所选 bot 的 owner（锁定、必然入群）+ 额外邀请的团队成员（可选）。
function CreateGroupModal({
  teamName,
  members,
  myUnionId,
  visible,
  onClose,
}: {
  teamName: string;
  /** 已 onlyInTeam 收窄的名册（人→机器→bot，只含团队机器人）。 */
  members: RosterMember[];
  myUnionId: string;
  visible: boolean;
  onClose: () => void;
}) {
  const withBots = members.filter((m) => m.machines.length > 0);
  const allKeys = useMemo(() => {
    const keys: string[] = [];
    for (const m of members) for (const x of m.machines) for (const b of x.bots || []) keys.push(selKey(x.machineId, b.appId));
    return keys;
  }, [members]);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [extra, setExtra] = useState<Set<string>>(new Set());
  const [groupName, setGroupName] = useState('');
  const [busy, setBusy] = useState(false);

  // 仅在「关→开」这一刻重置：默认全选团队机器人（最常见就是全员拉群，两步完成）。
  // 父层轮询会刷新 members/allKeys，若无此守卫会把用户正在编辑的勾选冲掉。
  const wasVisible = useRef(false);
  useEffect(() => {
    if (visible && !wasVisible.current) {
      setSelected(new Set(allKeys));
      setExtra(new Set());
      setGroupName('');
    }
    wasVisible.current = visible;
  }, [visible, allKeys]);

  const toggle = (key: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  const setKeys = (keys: string[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      for (const k of keys) (on ? next.add(k) : next.delete(k));
      return next;
    });

  // 计数按去重后的 appId 算（拉群提交的也是 appId）
  const appIds = new Set<string>();
  for (const m of members)
    for (const x of m.machines)
      for (const b of x.bots || []) if (selected.has(selKey(x.machineId, b.appId))) appIds.add(b.appId);
  const allChecked = allKeys.length > 0 && allKeys.every((k) => selected.has(k));

  // 锁定入群的人 = 发起人 + 拥有已勾选 bot 的 owner。这些人「必然入群、不可编辑」，
  // 在成员区渲染成带锁的灰 chip；随机器人勾选动态增减。
  const lockedIds = new Set<string>([myUnionId]);
  for (const m of members)
    for (const x of m.machines)
      for (const b of x.bots || []) if (selected.has(selKey(x.machineId, b.appId))) lockedIds.add(m.unionId);
  const lockedOwners = members.filter((m) => lockedIds.has(m.unionId));
  // 可邀请的其他成员 = 团队名册里不在锁定集里的人（含无 bot 的纯成员；pending 置灰不可选）。
  const invitable = members.filter((m) => !lockedIds.has(m.unionId));
  // 已锁定的人从「额外邀请」里剔除（可能先手选、后又勾了 TA 的 bot）——避免重复计数/提交。
  const effectiveExtra = [...extra].filter((u) => !lockedIds.has(u));
  const peopleCount = lockedIds.size + effectiveExtra.length;

  async function pull() {
    if (!appIds.size) return;
    setBusy(true);
    try {
      const r = await createGroup([...appIds], groupName.trim() || `${teamName} 协作群`, effectiveExtra);
      reportGroupResult(r);
      if (r.ok) onClose();
    } finally {
      setBusy(false);
    }
  }

  return (
    <Modal
      title="拉群"
      visible={visible}
      onCancel={onClose}
      onOk={pull}
      okText={`拉群（${appIds.size} 个机器人 · ${peopleCount} 人）`}
      cancelText="取消"
      okButtonProps={{ disabled: appIds.size === 0, loading: busy }}
      unmountOnExit
    >
      <Typography.Text type="secondary" style={{ fontSize: 13 }}>
        平台机器人会直接建一个飞书群，把勾选的机器人和成员拉进去。已默认全选团队机器人。
      </Typography.Text>
      <Input
        style={{ marginTop: 12 }}
        placeholder={`群名称（默认：${teamName} 协作群）`}
        value={groupName}
        onChange={setGroupName}
        allowClear
      />
      {allKeys.length > 0 && (
        <div style={{ marginTop: 4, textAlign: 'right' }}>
          <Button size="mini" type="text" onClick={() => setKeys(allKeys, !allChecked)}>
            {allChecked ? '清空' : '全选'}
          </Button>
        </div>
      )}
      <div style={{ maxHeight: 300, overflow: 'auto' }}>
        {withBots.map((m) => (
          <MemberRow key={m.unionId} member={m} forceOpen selected={selected} onToggle={toggle} onSetKeys={setKeys} />
        ))}
      </div>

      {/* 群成员：机器人主人锁定入群（不可编辑）+ 可选邀请其他团队成员 */}
      <div style={{ marginTop: 14, borderTop: '1px solid var(--color-border-2)', paddingTop: 12 }}>
        <Typography.Text style={{ fontSize: 13, fontWeight: 500 }}>群成员</Typography.Text>
        <div style={{ marginTop: 6 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            机器人主人自动入群，不可移除
          </Typography.Text>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 6 }}>
            {lockedOwners.map((o) => (
              <Tag key={o.unionId} icon={<IconLock />} color="gray">
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                  <Avatar size={18}>{o.avatar ? <img alt={o.name} src={o.avatar} /> : initial(o.name)}</Avatar>
                  {o.name}
                  {o.unionId === myUnionId ? '（你）' : ''}
                </span>
              </Tag>
            ))}
          </div>
        </div>
        <div style={{ marginTop: 10 }}>
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            邀请其他成员（可选）
          </Typography.Text>
          <Select
            mode="multiple"
            showSearch
            allowClear
            style={{ width: '100%', marginTop: 4 }}
            placeholder="搜团队成员，一起拉进这个群"
            value={effectiveExtra}
            filterOption={(input, option) =>
              String((option?.props as { extra?: { name?: string } })?.extra?.name || '')
                .toLowerCase()
                .includes(input.toLowerCase())
            }
            onChange={(v) => setExtra(new Set(v as string[]))}
            notFoundContent={<Typography.Text type="secondary">没有可邀请的成员</Typography.Text>}
          >
            {invitable.map((m) => (
              <Select.Option key={m.unionId} value={m.unionId} disabled={m.pending} extra={{ name: m.name }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Avatar size={22}>{m.avatar ? <img alt={m.name} src={m.avatar} /> : initial(m.name)}</Avatar>
                  <span>{m.name}</span>
                  {m.pending && <Tag size="small">待加入</Tag>}
                </div>
              </Select.Option>
            ))}
          </Select>
        </div>
      </div>
    </Modal>
  );
}

// 「管理机器人」弹窗：列全体成员的全部候选 bot（人 → 机器 → bot 三级树），勾选 = 加入团队。
// 初始勾选取自各 bot 的 inTeam；保存时按初始态算增删 delta 调 updateTeamBots，然后刷新名册。
function ManageBotsModal({
  teamId,
  pool,
  myUnionId,
  visible,
  onClose,
  onSaved,
  onAddedUnconfigured,
  restoreSelected,
}: {
  teamId: string;
  pool: RosterMember[];
  myUnionId: string;
  visible: boolean;
  onClose: () => void;
  onSaved: () => void;
  /** 本次保存新加入团队的 bot 里有未配置默认目录/oncall 的 → 通知父层顺势弹目录配置引导。 */
  onAddedUnconfigured?: () => void;
  /** 重登往返后待恢复的勾选键（machineId::appId[]）；非空时作为初始勾选，覆盖 inTeam 基线。 */
  restoreSelected?: string[] | null;
}) {
  // 只管自己名下的机器：是否加入团队由 bot 主人自己决定，别人（含管理员）不能替你增删。
  const myMachines = useMemo(
    () => pool.filter((m) => m.unionId === myUnionId).flatMap((m) => m.machines),
    [pool, myUnionId],
  );
  // 键 → {machineId, appId}，用于把勾选键还原成 API 需要的 ref（免解析字符串）
  const refByKey = useMemo(() => {
    const m = new Map<string, TeamBotRef>();
    for (const x of myMachines)
      for (const b of x.bots || []) m.set(selKey(x.machineId, b.appId), { machineId: x.machineId, appId: b.appId });
    return m;
  }, [myMachines]);
  // 初始已加入的键集合
  const initial = useMemo(() => {
    const s = new Set<string>();
    for (const x of myMachines) for (const b of x.bots || []) if (b.inTeam) s.add(selKey(x.machineId, b.appId));
    return s;
  }, [myMachines]);

  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  // 协管者面板：授权 / 查看 / 移除同一个面板（DESIGN-machine-comanager.md §2.3）。
  const [coMgr, setCoMgr] = useState<{ machineId: string; machineName: string } | null>(null);
  // 搜索只是视图过滤：被隐藏的 bot 勾选保留、增删 delta 照算（与名册的 bot 搜索同一原则）。
  const [botFilter, setBotFilter] = useState('');

  // 仅在「关→开」这一刻把勾选重置回当前 inTeam 真值。父层轮询会刷新 pool/initial，
  // 若无此守卫，轮询会在弹窗打开期间把用户正在编辑的勾选冲掉。
  // restoreSelected（重登往返恢复）优先于 inTeam 基线——把用户跳转前的勾选原样还原。
  const wasVisible = useRef(false);
  useEffect(() => {
    if (visible && !wasVisible.current) {
      // 按「是否传入草稿」判断，不按长度——restoreSelected=[] 是「清空全部」的有效恢复，
      // 不能退回 inTeam 基线把原勾选重新选上。
      setSelected(restoreSelected != null ? new Set(restoreSelected) : new Set(initial));
      setBotFilter('');
    }
    wasVisible.current = visible;
    // restoreSelected 只在开启瞬间读取一次，不进依赖（避免父层重渲染重复注入）。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, initial]);

  const toggle = (key: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(key) ? next.delete(key) : next.add(key);
      return next;
    });
  const setKeys = (keys: string[], on: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev);
      for (const k of keys) (on ? next.add(k) : next.delete(k));
      return next;
    });

  const hasBots = myMachines.some((x) => (x.bots || []).length > 0);
  // 搜索过滤（机器名命中 → 整机展示；否则按 bot 名过滤）
  const fq = botFilter.trim().toLowerCase();
  const shownMachines = !fq
    ? myMachines
    : myMachines
        .map((x) =>
          (x.name || '').toLowerCase().includes(fq)
            ? x
            : { ...x, bots: (x.bots || []).filter((b) => (b.name || '').toLowerCase().includes(fq)) },
        )
        .filter((x) => (x.bots || []).length > 0);
  // 与初始态比对算增删；无变化则禁用保存
  const add: TeamBotRef[] = [];
  const remove: TeamBotRef[] = [];
  for (const k of selected) if (!initial.has(k) && refByKey.has(k)) add.push(refByKey.get(k)!);
  for (const k of initial) if (!selected.has(k) && refByKey.has(k)) remove.push(refByKey.get(k)!);
  const dirty = add.length > 0 || remove.length > 0;

  async function save() {
    if (!dirty) return;
    setSaving(true);
    try {
      // 暂存当前勾选：若保存命中新鲜登录过期而整页跳飞书重登，回来后据此还原勾选，不丢选择。
      let ok = false;
      await saveWithDraft(manageBotsDraftKey(teamId), [...selected], async () => {
        const r = await updateTeamBots(teamId, add, remove);
        if (!r.ok) {
          Message.error('保存失败');
          return;
        }
        ok = true;
      });
      if (!ok) return;
      Message.success(`已更新我的团队机器人（+${add.length} / -${remove.length}）`);
      // 新加入的 bot 若未配置默认目录/oncall，顺势引导去配（否则队友没法直接用）
      const dirModeByKey = new Map<string, string | null | undefined>();
      for (const x of myMachines) for (const b of x.bots || []) dirModeByKey.set(selKey(x.machineId, b.appId), b.dirMode);
      const addedUnconfigured = add.some((ref) => dirModeByKey.get(selKey(ref.machineId, ref.appId)) === 'off');
      onSaved();
      onClose();
      if (addedUnconfigured) onAddedUnconfigured?.();
    } finally {
      setSaving(false);
    }
  }

  return (
    <Modal
      title="管理我的机器人"
      visible={visible}
      onCancel={onClose}
      onOk={save}
      okText="保存"
      cancelText="取消"
      okButtonProps={{ disabled: !dirty, loading: saving }}
      unmountOnExit
    >
      <Typography.Text type="secondary" style={{ fontSize: 13 }}>
        勾选你自己的机器人加入本团队，取消勾选则移出。只影响你名下的机器；团队名册与拉群会展示全团队已加入的机器人。
      </Typography.Text>
      {hasBots && (
        <Input
          allowClear
          prefix={<IconSearch />}
          placeholder="搜索机器人 / 机器"
          value={botFilter}
          onChange={setBotFilter}
          style={{ marginTop: 12 }}
        />
      )}
      <div style={{ marginTop: 12, maxHeight: 420, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 12 }}>
        {!hasBots ? (
          <Space direction="vertical" size={8}>
            <Typography.Text type="secondary">
              你名下暂无可加入团队的机器人——先去「我的机器」绑定一台跑着 botmux 的机器，它的机器人就会出现在这里。
            </Typography.Text>
            <Button
              size="small"
              type="primary"
              onClick={() => {
                onClose();
                location.hash = '#machines';
              }}
            >
              去绑定机器
            </Button>
          </Space>
        ) : shownMachines.length === 0 ? (
          <Typography.Text type="secondary">没有匹配「{botFilter.trim()}」的机器人</Typography.Text>
        ) : (
          shownMachines
            .filter((x) => (x.bots || []).length > 0)
            .map((x) => (
              <MachineRow
                key={x.machineId}
                machine={x}
                selected={selected}
                onToggle={toggle}
                onSetKeys={setKeys}
                onOpenCoManagers={(machineId, machineName) => setCoMgr({ machineId, machineName })}
              />
            ))
        )}
      </div>
      {coMgr && (
        <CoManagerModal
          visible
          machineId={coMgr.machineId}
          machineName={coMgr.machineName}
          roster={pool}
          myUnionId={myUnionId}
          onClose={() => setCoMgr(null)}
        />
      )}
    </Modal>
  );
}

// 团队成员（人）一行：头像 + 姓名 + 机器数；点开展开 TA 的机器，机器再展开其 bots（人 → 机器 → bot 三级树）。
// selected/onToggle/onSetKeys 三者齐全时进入勾选模式（拉群弹窗用）；不传则纯浏览（成员详情用）。
function MemberRow({
  member,
  forceOpen,
  selected,
  onToggle,
  onSetKeys,
}: {
  member: RosterMember;
  forceOpen: boolean;
  selected?: Set<string>;
  onToggle?: (key: string) => void;
  onSetKeys?: (keys: string[], on: boolean) => void;
}) {
  const [open, setOpen] = useState(forceOpen);
  const count = member.machines.length;
  const selectable = !!(selected && onToggle && onSetKeys);

  // 此人全部可见 bot 的选择键（成员级全选）
  const memberKeys = member.machines.flatMap((x) => (x.bots || []).map((b) => selKey(x.machineId, b.appId)));
  const memberChecked = selected ? memberKeys.filter((k) => selected.has(k)).length : 0;
  const memberAll = memberKeys.length > 0 && memberChecked === memberKeys.length;

  return (
    <div className="roster-member">
      <div className="machine-row">
        <div style={{ cursor: count ? 'pointer' : 'default' }} onClick={() => count && setOpen((o) => !o)}>
          <Space align="center">
            <Avatar size={28}>
              {member.avatar ? <img alt={member.name} src={member.avatar} /> : initial(member.name)}
            </Avatar>
            <Typography.Text bold>{member.name}</Typography.Text>
            {member.pending ? (
              <Tag color="orange">待加入</Tag>
            ) : (
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {count > 0 ? `${count} 台机器` : '尚未添加机器人'}
              </Typography.Text>
            )}
          </Space>
        </div>
        <Space align="center" size={4}>
          {selectable && memberKeys.length > 0 && (
            <Button size="mini" type="text" onClick={() => onSetKeys!(memberKeys, !memberAll)}>
              {memberAll ? '清空本人' : '全选本人'}
            </Button>
          )}
          {count > 0 && (
            <IconDown
              style={{
                cursor: 'pointer',
                transition: 'transform .15s',
                transform: open ? 'rotate(180deg)' : 'none',
                color: 'var(--color-text-3)',
              }}
              onClick={() => setOpen((o) => !o)}
            />
          )}
        </Space>
      </div>
      {open && count > 0 && (
        <div style={{ marginTop: 8, paddingLeft: 22, display: 'flex', flexDirection: 'column', gap: 12 }}>
          {member.machines.map((x) => (
            <MachineRow key={x.machineId} machine={x} selected={selected} onToggle={onToggle} onSetKeys={onSetKeys} />
          ))}
        </div>
      )}
    </div>
  );
}

// 机器一行：状态 Tag（+ 勾选模式下的本机全选/清空）；下挂 bots。勾选模式每个 bot 前有 Checkbox，浏览模式只列信息。
function MachineRow({
  machine,
  selected,
  onToggle,
  onSetKeys,
  onOpenCoManagers,
}: {
  machine: RosterMachine;
  selected?: Set<string>;
  onToggle?: (key: string) => void;
  onSetKeys?: (keys: string[], on: boolean) => void;
  /** 传了才显示「开放我的机器管理权限」——只在「管理我的机器人」弹窗里传（那里的机器
   *  都是自己 owner 的）。拉群弹窗会列到队友的机器，绝不能在那里出现这个入口。 */
  onOpenCoManagers?: (machineId: string, machineName: string) => void;
}) {
  const bots = machine.bots || [];
  const offline = machine.stale || !machine.online;
  const selectable = !!(selected && onToggle && onSetKeys);
  const keys = bots.map((b) => selKey(machine.machineId, b.appId));
  const machineChecked = selected ? keys.filter((k) => selected.has(k)).length : 0;
  const machineAll = keys.length > 0 && machineChecked === keys.length;

  return (
    <div>
      <Space align="center" size={8} wrap>
        <Tag color={offline ? undefined : 'green'}>
          <span className={`dot ${offline ? 'off' : 'on'}`} />
          {machine.name} · {machine.botmuxVersion}
        </Tag>
        {onOpenCoManagers && (
          <Button
            size="mini"
            icon={<IconUserAdd />}
            onClick={() => onOpenCoManagers(machine.machineId, machine.name)}
          >
            开放我的机器管理权限
          </Button>
        )}
        {selectable && bots.length > 0 && (
          <Button size="mini" type="text" onClick={() => onSetKeys!(keys, !machineAll)}>
            {machineAll ? '清空' : '全选'}
          </Button>
        )}
      </Space>
      <div style={{ marginTop: 6, paddingLeft: 16, display: 'flex', flexDirection: 'column', gap: 6 }}>
        {bots.length === 0 ? (
          <Typography.Text type="secondary" style={{ fontSize: 12 }}>
            无 bot
          </Typography.Text>
        ) : (
          bots.map((b) => {
            const key = selKey(machine.machineId, b.appId);
            return (
              <Space key={b.appId} align="center" size={6}>
                {selectable && <Checkbox checked={selected!.has(key)} onChange={() => onToggle!(key)} />}
                <Avatar size={22}>
                  {b.avatar ? <img alt={b.name} src={b.avatar} /> : initial(b.name)}
                </Avatar>
                <Typography.Text style={{ fontSize: 13 }}>{b.name}</Typography.Text>
                {b.cli && (
                  <Tag size="small" color="arcoblue">
                    {b.cli}
                  </Tag>
                )}
                <DirModeTag bot={b} />
              </Space>
            );
          })
        )}
      </div>
    </div>
  );
}

// 团队卡片：概览（成员/机器人头像列）+ 常驻操作栏（拉群 / 管理我的机器人 / 邀请成员）+ 可展开的成员详情。
// 低频与危险操作（加入机器人大厅、解散/退出）收进右上角 ⋯ 菜单。
function TeamCard({
  team: t,
  myUnionId,
  botQuery,
  onChanged,
}: {
  team: Team;
  myUnionId: string;
  botQuery: string;
  onChanged: () => void;
}) {
  const { members, unavailable, reload } = useRoster(t.teamId);
  const isCreator = t.createdBy === myUnionId;
  const isAdmin = isCreator || (Array.isArray(t.admins) && t.admins.includes(myUnionId));

  // 团队改名：与机器改名同款 inline 编辑（名称后铅笔图标 → 输入框 + ✓/✕）。
  const [editing, setEditing] = useState(false);
  const [editVal, setEditVal] = useState('');
  const [savingRename, setSavingRename] = useState(false);
  const [detailOpen, setDetailOpen] = useState(false);
  const [groupOpen, setGroupOpen] = useState(false);
  const [manageOpen, setManageOpen] = useState(false);
  const [inviteOpen, setInviteOpen] = useState(false);
  const [dirOpen, setDirOpen] = useState(false);
  const [adminsOpen, setAdminsOpen] = useState(false);
  const [adminDraft, setAdminDraft] = useState<string[]>([]);
  const [savingAdmins, setSavingAdmins] = useState(false);
  // 重登往返后待恢复的「管理机器人」勾选键；非 null 时自动重开弹窗并注入。
  const [botRestore, setBotRestore] = useState<string[] | null>(null);
  // 搜人增量授权回跳后待恢复的搜索词；非 null 时自动重开邀请弹窗并回填。
  const [inviteRestoreQuery, setInviteRestoreQuery] = useState<string | null>(null);

  // 重登往返恢复（每张团队卡片挂载时一次性检查自己团队的暂存草稿）：
  // 有机器人清单草稿 → 重开「管理我的机器人」并注入勾选；有管理员草稿 → 重开「设置管理员」并注入；
  // 有搜人授权草稿 → 重开「邀请成员」弹窗并回填搜索词。takeDraft 读完即删，只在挂载首个 render 触发。
  useEffect(() => {
    const bots = takeDraft<string[]>(manageBotsDraftKey(t.teamId));
    // 按「是否存在草稿」判断，不按长度——空数组=用户清空了全部 bot 的有效意图，同样要恢复。
    if (bots != null) {
      setBotRestore(bots);
      setManageOpen(true);
    }
    const admins = takeDraft<string[]>(adminsDraftKey(t.teamId));
    if (admins != null) {
      setAdminDraft(admins);
      setAdminsOpen(true);
    }
    const inviteQuery = takeDraft<string>(inviteScopeDraftKey(t.teamId));
    if (inviteQuery != null) {
      setInviteRestoreQuery(inviteQuery);
      setInviteOpen(true);
    }
    // 仅挂载时恢复一次。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const botQ = botQuery.trim().toLowerCase();
  const showDetail = detailOpen || !!botQ; // bot 搜索激活时强制展开详情以露出命中项
  const teamMembers = members ? onlyInTeam(members) : null;
  const bots = teamMembers ? collectTeamBots(teamMembers) : [];
  const pendingCount = members ? members.filter((m) => m.pending).length : 0;

  // 我在本团队的机器人（压平），及其中未配置默认目录/oncall 的——队友没法直接用，要引导 owner 去配。
  const myTeamBots: MyTeamBot[] = [];
  if (teamMembers) {
    const me = teamMembers.find((m) => m.unionId === myUnionId);
    for (const x of me?.machines || [])
      for (const b of x.bots || [])
        myTeamBots.push({
          machineId: x.machineId,
          machineName: x.name,
          online: x.online && !x.stale,
          appId: b.appId,
          name: b.name,
          avatar: b.avatar,
          dirMode: b.dirMode,
          dirModeDir: b.dirModeDir,
        });
  }
  const myUnconfigured = myTeamBots.filter((b) => b.dirMode === 'off');

  async function saveRename() {
    const name = editVal.trim();
    if (!name) {
      Message.warning('团队名不能为空');
      return;
    }
    setSavingRename(true);
    try {
      const r = await renameTeam(t.teamId, name);
      if (r.status === 403) {
        Message.error('只有创建人可以给团队改名');
        return;
      }
      if (!r.ok) {
        Message.error('改名失败');
        return;
      }
      Message.success(`已改名为「${name}」`);
      setEditing(false);
      onChanged();
    } finally {
      setSavingRename(false);
    }
  }

  function doDisband() {
    Modal.confirm({
      title: '解散团队',
      content: `确定解散「${t.teamName}」？此操作不可逆：团队与机器人大厅将被删除、成员间免授权互信随之失效，并会私聊通知所有成员。`,
      okText: '解散',
      okButtonProps: { status: 'danger' },
      onOk: async () => {
        const r = await disbandTeam(t.teamId);
        if (r.status === 403) {
          Message.error('只有创建人可以解散团队');
          return;
        }
        if (r.status === 503) {
          Message.error('存储暂不可用，稍后再试');
          return;
        }
        if (!r.ok) {
          Message.error('解散失败');
          return;
        }
        Message.success(`已解散「${t.teamName}」`);
        onChanged();
      },
    });
  }

  function doLeave() {
    Modal.confirm({
      title: '退出团队',
      content: `确定退出「${t.teamName}」？`,
      okButtonProps: { status: 'danger' },
      onOk: async () => {
        const r = await leaveTeam(t.teamId);
        if (r.status === 403) {
          Message.error('创建人不能退出团队——请用「解散」');
          return;
        }
        onChanged();
      },
    });
  }

  async function doJoinHall() {
    const r = await joinHall(t.teamId);
    if (r.ok) Message.success('已加入机器人大厅，去飞书查看');
    else Message.error(r.error === 'hall_not_ready' ? '大厅还没建好，稍后再试' : '加入失败，稍后再试');
  }

  function openAdmins() {
    setAdminDraft([...(t.admins ?? [])]);
    setAdminsOpen(true);
  }

  async function saveAdmins() {
    setSavingAdmins(true);
    try {
      // 暂存草稿：保存若命中重登跳转，回来自动重开弹窗并还原勾选。
      let ok = false;
      await saveWithDraft(adminsDraftKey(t.teamId), adminDraft, async () => {
        const r = await putTeamAdmins(t.teamId, adminDraft);
        if (r.status === 403) {
          Message.error('只有创建人可以任命管理员');
          return;
        }
        if (!r.ok) {
          Message.error(`保存失败：${r.error ?? r.status}`);
          return;
        }
        ok = true;
      });
      if (!ok) return;
      Message.success('管理员已更新');
      setAdminsOpen(false);
      onChanged();
    } finally {
      setSavingAdmins(false);
    }
  }

  const moreMenu = (
    <Menu
      onClickMenuItem={(key) => {
        if (key === 'hall') doJoinHall();
        else if (key === 'dirs') setDirOpen(true);
        else if (key === 'admins') openAdmins();
        else if (key === 'disband') doDisband();
        else if (key === 'leave') doLeave();
      }}
    >
      {myTeamBots.length > 0 && (
        <Menu.Item key="dirs">
          <IconEdit style={{ marginRight: 6 }} />
          机器人目录配置
        </Menu.Item>
      )}
      {t.hallChatId && (
        <Menu.Item key="hall">
          <IconRobot style={{ marginRight: 6 }} />
          加入机器人大厅
        </Menu.Item>
      )}
      {isCreator ? (
        <Menu.Item key="admins">
          <IconLock style={{ marginRight: 6 }} />
          设置管理员
        </Menu.Item>
      ) : null}
      {isCreator ? (
        <Menu.Item key="disband" style={{ color: 'rgb(var(--red-6))' }}>
          解散团队
        </Menu.Item>
      ) : (
        <Menu.Item key="leave" style={{ color: 'rgb(var(--red-6))' }}>
          退出团队
        </Menu.Item>
      )}
    </Menu>
  );

  // 成员详情（只读树）；bot 搜索时按命中过滤并默认展开
  let detail: React.ReactNode = null;
  if (showDetail) {
    if (members === null) {
      detail = (
        <div style={{ padding: 8 }}>
          <Spin size={16} />
        </div>
      );
    } else {
      const shown = filterRosterByBot(teamMembers!, botQ);
      detail =
        botQ && shown.length === 0 ? (
          <Typography.Text type="secondary">团队机器人中没有匹配「{botQuery.trim()}」的 bot</Typography.Text>
        ) : (
          shown.map((m) => <MemberRow key={m.unionId + '|' + botQ} member={m} forceOpen={!!botQ} />)
        );
    }
  }

  return (
    <Card style={{ marginBottom: 12 }}>
      <div className="machine-row">
        <Space align="center" size={4}>
          {editing ? (
            <>
              <Input
                autoFocus
                style={{ width: 200 }}
                value={editVal}
                maxLength={64}
                onChange={setEditVal}
                onPressEnter={saveRename}
                disabled={savingRename}
              />
              <Button
                size="mini"
                type="text"
                icon={<IconCheck />}
                loading={savingRename}
                onClick={saveRename}
                aria-label="保存团队名"
              />
              <Button
                size="mini"
                type="text"
                icon={<IconClose />}
                disabled={savingRename}
                onClick={() => setEditing(false)}
                aria-label="取消"
              />
            </>
          ) : (
            <>
              <Typography.Text bold style={{ fontSize: 15 }}>
                {t.teamName}
              </Typography.Text>
              {isCreator && (
                <Button
                  size="mini"
                  type="text"
                  icon={<IconEdit />}
                  onClick={() => {
                    setEditing(true);
                    setEditVal(t.teamName);
                  }}
                  aria-label="重命名团队"
                />
              )}
              {isCreator && (
                <Tag size="small" color="arcoblue" style={{ marginLeft: 4 }}>
                  我创建的
                </Tag>
              )}
              {!isCreator && isAdmin && (
                <Tag size="small" color="purple" style={{ marginLeft: 4 }}>
                  管理员
                </Tag>
              )}
            </>
          )}
        </Space>
        <Dropdown droplist={moreMenu} trigger="click" position="br">
          <Button size="small" type="text" icon={<IconMore />} aria-label="更多操作" style={{ color: 'var(--color-text-2)' }} />
        </Dropdown>
      </div>

      {/* 概览：不点开也能看到团队有谁、有哪些机器人 */}
      <div className="team-summary">
        {unavailable && members === null ? (
          <Typography.Text type="secondary">成员列表不可用</Typography.Text>
        ) : members === null ? (
          <Spin size={16} />
        ) : (
          <>
            <div className="team-strip">
              <span className="team-strip-label">成员 {members.length}</span>
              <AvatarStrip
                items={members.map((m) => ({
                  key: m.unionId,
                  name: m.name,
                  avatar: m.avatar,
                  dim: m.pending,
                  tip: m.pending ? `${m.name}（待加入）` : m.name,
                }))}
              />
              {pendingCount > 0 && (
                <Tag size="small" color="orange">
                  {pendingCount} 人待加入
                </Tag>
              )}
            </div>
            <div className="team-strip">
              <span className="team-strip-label">机器人 {bots.length}</span>
              {bots.length === 0 ? (
                <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                  还没有机器人——点「管理我的机器人」把你自己的机器人加入
                </Typography.Text>
              ) : (
                <AvatarStrip
                  items={bots.map((b) => ({
                    key: b.appId,
                    name: b.name,
                    avatar: b.avatar,
                    dim: b.dirMode === 'off',
                    tip:
                      b.dirMode === 'off'
                        ? `${b.name}（未配置目录，其他团队成员无法直接使用）`
                        : b.dirMode === 'oncall'
                          ? `${b.name}（oncall：${b.dirModeDir || ''}）`
                          : b.dirMode === 'default'
                            ? `${b.name}（默认目录：${b.dirModeDir || ''}）`
                            : b.name,
                  }))}
                />
              )}
            </div>
          </>
        )}
      </div>

      {/* 引导：我的团队机器人还没配默认目录/oncall → 队友没法直接用，提示 owner 一键去配 */}
      {myUnconfigured.length > 0 && (
        <Alert
          style={{ marginTop: 10 }}
          type="warning"
          content={`名下有 ${myUnconfigured.length} 个机器人尚未配置默认目录 / oncall，其他团队成员无法直接使用`}
          action={
            <Button size="mini" type="primary" onClick={() => setDirOpen(true)}>
              去配置
            </Button>
          }
        />
      )}

      {/* 常驻操作栏：核心操作不再藏在成员展开区里 */}
      <div className="team-actions">
        <Space wrap>
          <Button
            type="primary"
            size="small"
            icon={<IconUserGroup />}
            disabled={bots.length === 0}
            onClick={() => setGroupOpen(true)}
          >
            拉群
          </Button>
          <Button size="small" icon={<IconRobot />} disabled={!members} onClick={() => setManageOpen(true)}>
            管理我的机器人
          </Button>
          <Button size="small" icon={<IconUserAdd />} onClick={() => setInviteOpen(true)}>
            邀请成员
          </Button>
          {/* 创建人专属：任命管理员（也可从 ⋯ 菜单进）。管理员可改问题板表单/预设仓库。 */}
          {isCreator ? (
            <Button size="small" icon={<IconLock />} onClick={openAdmins}>
              设置管理员
              {(t.admins?.length ?? 0) > 0 ? (
                <Tag size="small" color="purple" style={{ marginLeft: 6 }}>
                  {t.admins!.length}
                </Tag>
              ) : null}
            </Button>
          ) : null}
        </Space>
        <Button size="small" type="text" style={{ color: 'var(--color-text-2)' }} onClick={() => setDetailOpen((o) => !o)}>
          成员详情
          <IconDown
            style={{ marginLeft: 4, transition: 'transform .15s', transform: showDetail ? 'rotate(180deg)' : 'none' }}
          />
        </Button>
      </div>

      {showDetail && <div style={{ marginTop: 4 }}>{detail}</div>}

      {teamMembers && (
        <CreateGroupModal teamName={t.teamName} members={teamMembers} myUnionId={myUnionId} visible={groupOpen} onClose={() => setGroupOpen(false)} />
      )}
      <Modal
        title="设置管理员"
        visible={adminsOpen}
        onOk={() => void saveAdmins()}
        onCancel={() => setAdminsOpen(false)}
        okText="保存"
        cancelText="取消"
        confirmLoading={savingAdmins}
      >
        <Typography.Paragraph type="secondary" style={{ fontSize: 12, marginBottom: 12 }}>
          仅团队创建人可任命管理员。管理员可修改问题板的预设仓库与自定义表单，并对 issue 做强制脱离/归档。
          你作为创建人始终拥有全部权限，无需勾选自己。
        </Typography.Paragraph>
        {members === null ? (
          <Spin />
        ) : (
          <>
            <div
              style={{
                marginBottom: 12,
                padding: '8px 10px',
                background: 'var(--color-fill-1)',
                borderRadius: 6,
                fontSize: 13,
              }}
            >
              <Tag size="small" color="arcoblue" style={{ marginRight: 8 }}>
                创建人
              </Tag>
              {members.find((m) => m.unionId === t.createdBy)?.name || '你'}
              <Typography.Text type="secondary" style={{ marginLeft: 8, fontSize: 12 }}>
                （固定，不可取消）
              </Typography.Text>
            </div>
            <div style={{ fontSize: 12, color: 'var(--color-text-3)', marginBottom: 8 }}>勾选要设为管理员的成员：</div>
            <Checkbox.Group
              value={adminDraft}
              onChange={(v) => setAdminDraft(v as string[])}
              style={{ display: 'flex', flexDirection: 'column', gap: 8 }}
            >
              {members
                .filter((m) => !m.pending && m.unionId !== t.createdBy)
                .map((m) => (
                  <Checkbox key={m.unionId} value={m.unionId}>
                    {m.name}
                  </Checkbox>
                ))}
            </Checkbox.Group>
          </>
        )}
        {members && members.filter((m) => !m.pending && m.unionId !== t.createdBy).length === 0 ? (
          <Typography.Text type="secondary">暂无其他成员可任命，请先邀请成员加入团队。</Typography.Text>
        ) : null}
      </Modal>
      <BotDirModal bots={myTeamBots} visible={dirOpen} onClose={() => setDirOpen(false)} onSaved={reload} />
      <ManageBotsModal
        teamId={t.teamId}
        pool={members || []}
        myUnionId={myUnionId}
        visible={manageOpen}
        onClose={() => {
          setManageOpen(false);
          setBotRestore(null);
        }}
        onSaved={reload}
        onAddedUnconfigured={() => setDirOpen(true)}
        restoreSelected={botRestore}
      />
      <Modal
        title={`邀请其他同学加入团队：${t.teamName}`}
        visible={inviteOpen}
        onCancel={() => {
          setInviteOpen(false);
          setInviteRestoreQuery(null);
          reload(); // 发完邀请立刻把「待加入」刷进成员列表
        }}
        footer={null}
        unmountOnExit
      >
        <InvitePanel teamId={t.teamId} initialQuery={inviteRestoreQuery ?? undefined} />
      </Modal>
    </Card>
  );
}

export default function Teams({ teams, loading, error, onChanged, myUnionId }: Props) {
  const [newTeamOpen, setNewTeamOpen] = useState(false);
  const [newTeamName, setNewTeamName] = useState('');
  const [creating, setCreating] = useState(false);
  const [acceptOpen, setAcceptOpen] = useState(false);
  const [acceptVal, setAcceptVal] = useState('');
  const [accepting, setAccepting] = useState(false);
  const [teamQuery, setTeamQuery] = useState('');
  const [botQuery, setBotQuery] = useState('');

  // 客户端按团队名过滤（大小写不敏感子串）；空查询=全部。5s 自动刷新会更新 teams，过滤实时应用。
  const q = teamQuery.trim().toLowerCase();
  const filteredTeams = teams ? (q ? teams.filter((t) => t.teamName.toLowerCase().includes(q)) : teams) : teams;

  async function doCreate() {
    const name = newTeamName.trim();
    if (!name) return;
    setCreating(true);
    try {
      const r = await createTeam(name);
      if (r.status !== 200) {
        Message.error('创建失败');
        return;
      }
      Message.success('已创建团队');
      setNewTeamOpen(false);
      setNewTeamName('');
      onChanged();
    } finally {
      setCreating(false);
    }
  }

  async function doAccept() {
    // 允许直接粘整条邀请链接（.../?invite=xxx）或裸 token——从链接里抠出 token。
    const raw = acceptVal.trim();
    if (!raw) return;
    let invite = raw;
    const m = raw.match(/[?&]invite=([^&#\s]+)/);
    if (m) {
      try {
        invite = decodeURIComponent(m[1]);
      } catch {
        invite = m[1];
      }
    }
    setAccepting(true);
    try {
      const r = await acceptInvite(invite);
      if (r.status === 404) {
        Message.error('团队不存在或已解散');
        return;
      }
      if (r.status === 400) {
        Message.error('邀请无效或已过期');
        return;
      }
      if (r.status !== 200) {
        Message.error('接受邀请失败');
        return;
      }
      Message.success('已加入团队：' + (r.teamName || ''));
      setAcceptOpen(false);
      setAcceptVal('');
      onChanged();
    } finally {
      setAccepting(false);
    }
  }

  return (
    <>
      <div className="section-head">
        <h2>团队</h2>
        <Space>
          <Button onClick={() => setAcceptOpen(true)}>接受邀请</Button>
          <Button type="primary" icon={<IconPlus />} onClick={() => setNewTeamOpen(true)}>
            创建团队
          </Button>
        </Space>
      </div>

      {teams && teams.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
          <Input
            allowClear
            prefix={<IconSearch />}
            placeholder="搜索团队"
            value={teamQuery}
            onChange={setTeamQuery}
            style={{ flex: 1, minWidth: 180 }}
          />
          <Input
            allowClear
            prefix={<IconRobot />}
            placeholder="按 bot 名搜索"
            value={botQuery}
            onChange={setBotQuery}
            style={{ flex: 1, minWidth: 180 }}
          />
        </div>
      )}

      {error && !teams ? (
        <Card>
          <Empty description="加载团队失败，稍后自动重试…" />
        </Card>
      ) : loading && !teams ? (
        <Card>
          <div style={{ textAlign: 'center', padding: 24 }}>
            <Spin />
          </div>
        </Card>
      ) : !teams || teams.length === 0 ? (
        <Card>
          <Empty description="还没有团队。「创建团队」后可邀请同事；或「接受邀请」加入别人的团队。" />
        </Card>
      ) : !filteredTeams || filteredTeams.length === 0 ? (
        <Card>
          <Empty description={`没有匹配「${teamQuery.trim()}」的团队`} />
        </Card>
      ) : (
        filteredTeams.map((t) => (
          <TeamCard key={t.teamId} team={t} myUnionId={myUnionId} botQuery={botQuery} onChanged={onChanged} />
        ))
      )}

      <Modal
        title="创建团队"
        visible={newTeamOpen}
        onCancel={() => setNewTeamOpen(false)}
        onOk={doCreate}
        confirmLoading={creating}
        okText="创建"
        cancelText="取消"
      >
        <Input
          autoFocus
          placeholder="团队名称"
          value={newTeamName}
          maxLength={64}
          onChange={setNewTeamName}
          onPressEnter={doCreate}
        />
      </Modal>

      <Modal
        title="接受邀请"
        visible={acceptOpen}
        onCancel={() => setAcceptOpen(false)}
        onOk={doAccept}
        confirmLoading={accepting}
        okText="加入"
        cancelText="取消"
      >
        <Typography.Text type="secondary" style={{ fontSize: 13 }}>
          粘贴同事发来的邀请链接（点开即可自动加入，粘贴到这里也行）：
        </Typography.Text>
        <Input.TextArea
          autoFocus
          style={{ marginTop: 8 }}
          placeholder="邀请链接"
          value={acceptVal}
          onChange={setAcceptVal}
          autoSize={{ minRows: 2, maxRows: 4 }}
        />
      </Modal>
    </>
  );
}
