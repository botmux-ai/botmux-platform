// 平台 API 客户端：所有请求同源带 cookie；POST 统一 JSON。

export interface Me {
  unionId: string;
  name: string;
  avatar?: string;
}

export interface Membership {
  teamId: string;
  teamName: string;
}

/** bot「默认目录模式」三选一：off=每次弹选仓库卡（队友没法直接用）；default=钉死默认目录；oncall=默认目录+新群自动绑定开放对话。 */
export type BotDirMode = 'off' | 'default' | 'oncall';

export interface Bot {
  appId: string;
  openId: string | null;
  name: string;
  avatar?: string;
  cli?: string;
  /** 仅名册返回：该 bot 是否已加入当前团队。 */
  inTeam?: boolean;
  /** 仅名册返回：默认目录模式；null = 未知（机器离线/查询超时，前端不显示徽标）。 */
  dirMode?: BotDirMode | null;
  /** 仅名册返回：当前模式绑定的目录（off/未知时为 null）。 */
  dirModeDir?: string | null;
}

export interface TeamBotRef {
  machineId: string;
  appId: string;
}

export interface Machine {
  machineId: string;
  name: string;
  botmuxVersion: string;
  stale: boolean;
  online: boolean;
  lastSeen: number;
  memberships: Membership[];
  bots?: Bot[];
  /** owner 视角：这台机器开给了几个协管者（机器行徽章用）。 */
  coManagerCount?: number;
  /** 仅 managedMachines：机器主人是谁（被授权方要知道这是谁的机器）。 */
  ownerName?: string;
  /** 仅 managedMachines：我在这台机器上有哪些权限。 */
  myScopes?: string[];
  /** 仅 managedMachines：我的角色，co-manager（协管）或 viewer（只读）。 */
  myRole?: CoManagerRole;
}

/** 授权角色。协管 = 能接管终端（可选改配置）；只读 = 只看 Dashboard、会话和终端输出。 */
export type CoManagerRole = 'co-manager' | 'viewer';

/** 机器协管者：owner 授权、能打开这台机器 dashboard 的人。 */
export interface CoManager {
  unionId: string;
  name: string;
  scopes: string[];
  grantedAt: number;
  grantedBy: string;
  viaTeamId?: string;
  /** 缺省 = 协管（只读角色上线前的老记录都没有这个字段）。 */
  role?: CoManagerRole;
  /** owner 视角：已不在任何共同团队（自动摘除未生效，建议手动清理）。
   *  undefined = 团队数据读取失败，未能判定，UI 不显示标记。 */
  leftTeam?: boolean;
}

/** 记录的实际角色：缺省按协管处理。 */
export function coManagerRoleOf(c: Pick<CoManager, 'role'>): CoManagerRole {
  return c.role === 'viewer' ? 'viewer' : 'co-manager';
}

export interface CoManagersResp {
  machineId: string;
  machineName: string;
  ownerName: string;
  isOwner: boolean;
  coManagers: CoManager[];
}

export interface MachinesResp {
  machines: Machine[];
  /** 我被授权协管的机器（不是我 owner 的）。 */
  managedMachines?: Machine[];
  latestVersion: string | null;
}

export interface Team {
  teamId: string;
  teamName: string;
  /** 创建人 unionId —— 前端据此只对创建人显示「解散」 */
  createdBy?: string;
  /** 机器人大厅群 chat_id。大厅是 bot-only 群（人不在群里），UI 靠它展示大厅状态 */
  hallChatId?: string;
  /** 团队管理员 unionId 列表（不含创建人；创建人天然是管理员） */
  admins?: string[];
  /** 团队预设仓库数量（完整列表走 issue-settings） */
  repoPresetCount?: number;
}

export interface TeamRepoPreset {
  id: string;
  label: string;
  remote?: string;
}

export type IssueFormFieldType = 'text' | 'textarea' | 'select' | 'multiselect' | 'repo';

export interface IssueFormField {
  id: string;
  type: IssueFormFieldType;
  label: string;
  required?: boolean;
  placeholder?: string;
  options?: string[];
  allowCustom?: boolean;
}

export interface IssueFormConfig {
  fields: IssueFormField[];
}

export interface TeamIssueSettings {
  teamId: string;
  repoPresets: TeamRepoPreset[];
  issueForm: IssueFormConfig;
  admins?: string[];
  createdBy?: string;
  /** 创建人或管理员可改表单/预设仓库 */
  canEdit: boolean;
}

export interface RosterMachine {
  machineId: string;
  name: string;
  botmuxVersion: string;
  online: boolean;
  stale: boolean;
  bots?: Bot[];
}

export interface RosterMember {
  /** 已发定向邀请、还没接受的人（无机器，展示「待加入」标签）。 */
  pending?: boolean;
  unionId: string;
  name: string;
  avatar?: string;
  machines: RosterMachine[];
}

export interface UserHit {
  unionId: string;
  openId: string;
  name: string;
  email?: string;
  avatar?: string;
}

export interface UserSearchResp {
  users: UserHit[];
  configured: boolean;
  /** 搜人 scope 未授权（基础登录/老会话）→ 前端引导走 scope=search 增量授权。 */
  needScope?: boolean;
  /** 已授权但 token 失效 → 需完整重新登录。 */
  reauth?: boolean;
  error?: string;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly loginUrl?: string;

  constructor(status: number, code: string, loginUrl?: string) {
    super(code);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.loginUrl = loginUrl;
  }
}

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

interface CurrentLocation {
  pathname: string;
  search: string;
  hash: string;
}

export function loginHrefFor(locationLike: CurrentLocation): string {
  const next = locationLike.pathname + locationLike.search + locationLike.hash;
  return `/auth/login?next=${encodeURIComponent(next)}`;
}

/**
 * 所有平台 API 请求共用的 fresh-SSO 门禁。敏感接口返回 stale_session 时，
 * 必须在任何业务调用方读取 JSON 之前中止，并保留当前完整地址重登续接。
 */
export function createApiRequest(
  fetchImpl: FetchLike,
  currentLocation: () => CurrentLocation,
  navigate: (href: string) => void,
) {
  return async (path: string, opts?: RequestInit): Promise<Response> => {
    const response = await fetchImpl(path, { credentials: 'same-origin', ...opts });
    if (response.status !== 401) return response;

    const body = (await response.clone().json().catch(() => ({}))) as {
      error?: string;
      loginUrl?: string;
    };
    if (body.error !== 'stale_session') return response;

    const loginUrl = loginHrefFor(currentLocation());
    navigate(loginUrl);
    throw new ApiError(response.status, body.error, loginUrl);
  };
}

const browserApiRequest = createApiRequest(
  (input, init) => fetch(input, init),
  () => location,
  (href) => { location.href = href; },
);

async function api(path: string, opts?: RequestInit): Promise<Response> {
  return browserApiRequest(path, opts);
}

function jsonPost(path: string, body?: unknown): Promise<Response> {
  return api(path, {
    method: 'POST',
    headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
}

export async function getMe(): Promise<Me | null> {
  const r = await api('/api/me');
  if (r.status === 401) return null;
  if (!r.ok) return null;
  return r.json();
}

export async function getMachines(): Promise<MachinesResp> {
  const r = await api('/api/machines');
  if (r.status === 401) throw new Error('unauthenticated');
  return r.json();
}

// ── 版本大盘 ──────────────────────────────────────────────────────────────

export interface VersionWindowCount {
  machines: number;
  /** 去重用户数（同一人多台机器只算一次） */
  users: number;
}

export type VersionWindow = 'online' | 'active7d' | 'all';

export interface VersionBucket {
  version: string;
  online: VersionWindowCount;
  active7d: VersionWindowCount;
  all: VersionWindowCount;
  /** 本版本及更新版本的累计（用户已按并集去重）；无法比较新旧的版本（unknown / 自编译）为 null */
  atOrAbove: Record<VersionWindow, VersionWindowCount> | null;
}

export interface VersionStats {
  generatedAt: number;
  latestVersion: string | null;
  totals: Record<VersionWindow, VersionWindowCount>;
  /** 按版本号从新到旧 */
  versions: VersionBucket[];
}

export async function getVersionStats(): Promise<VersionStats> {
  const r = await api('/api/stats/versions');
  if (r.status === 401) throw new Error('unauthenticated');
  if (!r.ok) throw new Error('stats_unavailable');
  return r.json();
}

export async function bindCode(): Promise<{ code: string; expiresInSec: number; command: string }> {
  const r = await jsonPost('/api/bind-code');
  return r.json();
}

// ── 机器协管者 ────────────────────────────────────────────────────────────
// 写操作是 strict fresh-SSO 档（10min）；stale_session 由 createApiRequest 统一
// 拦下并跳登录，业务层只需处理业务错误。

export async function getCoManagers(machineId: string): Promise<CoManagersResp> {
  const r = await api(`/api/machines/${machineId}/co-managers`);
  if (r.status === 401) throw new Error('unauthenticated');
  if (r.status === 404) throw new Error('machine_not_found');
  if (!r.ok) throw new Error('store_unavailable');
  return r.json();
}

export async function setCoManagers(
  machineId: string,
  unionIds: string[],
  /** 是否连带授予「改配置」（settings / schedules / groups）。需要机器端版本支持。 */
  canManage = false,
  /** 按人指定角色；没列出的人：新加的默认协管、已有的保持不变。 */
  roles?: Record<string, CoManagerRole>,
): Promise<{ ok: boolean; error?: string; unionIds?: string[]; coManagers?: CoManager[] }> {
  const r = await api(`/api/machines/${machineId}/co-managers`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(roles ? { unionIds, canManage, roles } : { unionIds, canManage }),
  });
  const j = (await r.json().catch(() => ({}))) as {
    ok?: boolean;
    error?: string;
    unionIds?: string[];
    coManagers?: CoManager[];
  };
  return { ok: r.ok && j.ok !== false, error: j.error, unionIds: j.unionIds, coManagers: j.coManagers };
}

export async function removeCoManager(
  machineId: string,
  unionId: string,
): Promise<{ ok: boolean; error?: string; coManagers?: CoManager[] }> {
  const r = await api(`/api/machines/${machineId}/co-managers/${encodeURIComponent(unionId)}`, {
    method: 'DELETE',
  });
  const j = (await r.json().catch(() => ({}))) as {
    ok?: boolean;
    error?: string;
    coManagers?: CoManager[];
  };
  return { ok: r.ok && j.ok !== false, error: j.error, coManagers: j.coManagers };
}

export async function openMachine(id: string): Promise<{ status: number; openUrl?: string; error?: string }> {
  const r = await jsonPost(`/api/machines/${id}/open`);
  const j = (await r.json().catch(() => ({}))) as { openUrl?: string; error?: string };
  return { ...j, status: r.status };
}

export async function renameMachine(
  id: string,
  name: string,
): Promise<{ ok: boolean; status: number; name?: string; error?: string }> {
  const r = await jsonPost(`/api/machines/${id}/rename`, { name });
  if (r.status === 200) {
    const j = await r.json().catch(() => ({}));
    return { ok: true, status: 200, name: j.name };
  }
  const j = await r.json().catch(() => ({}));
  return { ok: false, status: r.status, error: j.error };
}

export async function upgradeMachine(
  id: string,
): Promise<{
  ok: boolean;
  status: number;
  changed?: boolean;
  oldVersion?: string;
  newVersion?: string;
  restarting?: boolean;
  updateInstalled?: boolean;
  error?: string;
  detail?: string;
}> {
  const r = await jsonPost(`/api/machines/${id}/upgrade`, {});
  const j = await r.json().catch(() => ({}));
  return { ...j, ok: r.ok && j.ok === true, status: r.status };
}

// 解绑机器：删干净绑定记录 + 吊销 machine token，以备下次重新绑定。
export async function unbindMachine(
  id: string,
): Promise<{ ok: boolean; status: number; error?: string }> {
  const r = await jsonPost(`/api/machines/${id}/unbind`);
  if (r.status === 200) return { ok: true, status: 200 };
  const j = await r.json().catch(() => ({}));
  return { ok: false, status: r.status, error: j.error };
}

export interface CreateGroupResult {
  ok: boolean;
  status: number;
  chatId?: string;
  shareLink?: string;
  invalidBotIds?: string[];
  /** 未能自动入群的成员 unionId（可走分享链接加入）。 */
  invalidOwnerUnionIds?: string[];
  autoInviteUnavailable?: boolean;
  error?: string;
}

// 拉群：平台机器人直建飞书群，把所选 bot（larkAppIds = bot.appId，可跨机器/跨人）、
// 各 bot 的 owner，以及额外邀请的团队成员（extraUnionIds，可选）拉进来。不依赖任何机器在线。
export async function createGroup(
  larkAppIds: string[],
  name?: string,
  extraUnionIds?: string[],
): Promise<CreateGroupResult> {
  const r = await jsonPost('/api/groups/create', {
    larkAppIds,
    name,
    extraUnionIds,
  });
  const j = await r.json().catch(() => ({}));
  return {
    ok: r.status === 200 && j.ok === true,
    status: r.status,
    chatId: j.chatId,
    shareLink: j.shareLink,
    invalidBotIds: j.invalidBotIds,
    invalidOwnerUnionIds: j.invalidOwnerUnionIds,
    autoInviteUnavailable: j.autoInviteUnavailable,
    error: j.error,
  };
}

export async function getTeams(): Promise<Team[]> {
  const r = await api('/api/teams');
  if (r.status === 401) throw new Error('unauthenticated');
  const j = await r.json();
  return j.teams;
}

export async function createTeam(name: string): Promise<{ status: number }> {
  const r = await jsonPost('/api/teams', { name });
  return { status: r.status };
}

export async function leaveTeam(id: string): Promise<Response> {
  return jsonPost(`/api/teams/${id}/leave`);
}

/** 自助加入机器人大厅（大厅默认 bot-only 不拉人，这是留给人的隐藏入口）。 */
export async function joinHall(id: string): Promise<{ ok: boolean; error?: string }> {
  const r = await jsonPost(`/api/teams/${id}/hall/join`);
  const j = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string };
  return { ok: r.ok && !!j.ok, error: j.error };
}

/** 解散团队（仅创建人；不可逆——同时解散机器人大厅并通知成员）。 */
export async function disbandTeam(id: string): Promise<Response> {
  return api(`/api/teams/${id}`, { method: 'DELETE' });
}

/** 团队改名（仅创建人）。大厅群名跟随，成员机器随下一拍 team-sync 拿到新名。 */
export async function renameTeam(id: string, name: string): Promise<Response> {
  return jsonPost(`/api/teams/${id}/rename`, { name });
}

export async function inviteLink(
  id: string,
): Promise<{ inviteUrl?: string; teamName?: string }> {
  const r = await jsonPost(`/api/teams/${id}/invite`);
  return r.json();
}

export async function inviteUser(
  id: string,
  target: { openId: string; unionId?: string; name?: string },
): Promise<{ ok: boolean; status: number; error?: string; detail?: string }> {
  const r = await jsonPost(`/api/teams/${id}/invite-user`, target);
  if (r.status === 200) return { ok: true, status: 200 };
  const j = await r.json().catch(() => ({}));
  return { ok: false, status: r.status, error: j.error, detail: j.detail };
}

export async function acceptInvite(invite: string): Promise<{ status: number; teamName?: string }> {
  const r = await jsonPost('/api/teams/accept', { invite });
  if (r.status === 200) {
    const j = await r.json();
    return { status: 200, teamName: j.teamName };
  }
  return { status: r.status };
}

export async function getRoster(id: string): Promise<RosterMember[] | null> {
  const r = await api(`/api/teams/${id}/roster`);
  if (r.status !== 200) return null;
  const j = await r.json();
  return j.members;
}

// 改机器人「默认目录模式」（仅机器 owner）：平台经隧道调本机 dashboard，daemon 校验目录存在并落盘，
// next-session 生效。error 可能是错误码（machine_unreachable / workingDir_required）或 daemon 的人话错误文案。
export async function setBotDirMode(
  machineId: string,
  appId: string,
  mode: BotDirMode,
  workingDir: string,
): Promise<{ ok: boolean; status: number; error?: string }> {
  const r = await api(`/api/machines/${machineId}/bots/${encodeURIComponent(appId)}/working-dir-mode`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ mode, workingDir }),
  });
  const j = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string };
  return { ok: r.status === 200 && j.ok === true, status: r.status, error: j.error };
}

// 管理团队机器人：把若干 bot 加入/移出团队的「已选清单」。
export async function updateTeamBots(
  id: string,
  add: TeamBotRef[],
  remove: TeamBotRef[],
): Promise<{ ok: boolean; status: number }> {
  const r = await jsonPost(`/api/teams/${id}/bots`, { add, remove });
  return { ok: r.status === 200, status: r.status };
}

export async function searchUsers(q: string): Promise<UserSearchResp> {
  const r = await api(`/api/users/search?q=${encodeURIComponent(q)}`);
  return r.json().catch(() => ({ users: [], configured: false }));
}

export async function logout(): Promise<void> {
  await jsonPost('/auth/logout');
}

// ── Issue Board（DESIGN-issue-board.md）────────────────────────────────────────

export type IssueStatus =
  | 'open'
  | 'claimed'
  | 'in_progress'
  | 'in_review'
  | 'done'
  | 'cancelling'
  | 'needs_attention'
  | 'reopened';

export interface IssueClaim {
  claimId: string;
  claimEpoch: number;
  unionId: string;
  name: string;
  machineId: string;
  localTaskRef?: string;
  /** 本地任务的人类可读名（botmux 传 issue 群的群名）。仅展示。 */
  localTaskLabel?: string;
  /** 本地任务深链（飞书群 applink）。服务端已锁死 https，渲染时不必再判 scheme。 */
  localTaskUrl?: string;
  agent?: string;
  repoLabel?: string;
  claimedAt: number;
  leaseExpiresAt: number;
  bound: boolean;
}

export interface Issue {
  _id: string;
  teamId: string;
  title: string;
  body: string;
  status: IssueStatus;
  labels?: string[];
  targetRepoId?: string;
  targetRepoLabel?: string;
  customFields?: Record<string, string | string[]>;
  suggestedAssigneeUnionId?: string;
  claim?: IssueClaim;
  attentionSince?: number;
  attentionReason?: string;
  createdBy: string;
  createdByName: string;
  createdAt: number;
  updatedAt: number;
  rev: number;
  stateRev: number;
}

export interface IssueSections {
  needsAttention: Issue[];
  todo: Issue[];
  inProgress: Issue[];
  inReview: Issue[];
  done: Issue[];
}

export interface IssueEvent {
  _id: string;
  issueId: string;
  seq: number;
  kind: string;
  fromStatus?: IssueStatus;
  toStatus?: IssueStatus;
  actorUnionId: string;
  detail?: string;
  at: number;
}

export async function listIssues(teamId: string): Promise<IssueSections> {
  const r = await api(`/api/issues?teamId=${encodeURIComponent(teamId)}`);
  if (r.status === 401) throw new Error('unauthenticated');
  if (!r.ok) throw new ApiError(r.status, ((await r.json().catch(() => ({}))) as { error?: string }).error ?? 'error');
  const j = await r.json();
  return j.sections as IssueSections;
}

export async function createIssue(
  teamId: string,
  values: Record<string, unknown>,
): Promise<{ ok: boolean; status: number; issue?: Issue; error?: string; field?: string }> {
  const r = await jsonPost('/api/issues', { teamId, values });
  const j = await r.json().catch(() => ({}));
  return {
    ok: r.status === 201,
    status: r.status,
    issue: j.issue,
    error: j.error,
    field: j.field,
  };
}

export async function patchIssue(
  id: string,
  rev: number,
  patch: {
    title?: string;
    body?: string;
    labels?: string[];
    targetRepoId?: string | null;
    targetRepoLabel?: string | null;
  },
): Promise<{ ok: boolean; status: number; issue?: Issue; error?: string }> {
  const r = await api(`/api/issues/${id}`, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ rev, ...patch }),
  });
  const j = await r.json().catch(() => ({}));
  return { ok: r.status === 200, status: r.status, issue: j.issue, error: j.error };
}

export async function getTeamIssueSettings(teamId: string): Promise<TeamIssueSettings> {
  const r = await api(`/api/teams/${teamId}/issue-settings`);
  if (r.status === 401) throw new Error('unauthenticated');
  if (!r.ok) {
    throw new ApiError(
      r.status,
      ((await r.json().catch(() => ({}))) as { error?: string }).error ?? 'error',
    );
  }
  return (await r.json()) as TeamIssueSettings;
}

export async function putTeamIssueSettings(
  teamId: string,
  body: { repoPresets?: TeamRepoPreset[]; issueForm?: IssueFormConfig },
): Promise<{ ok: boolean; status: number; settings?: TeamIssueSettings; error?: string }> {
  const r = await api(`/api/teams/${teamId}/issue-settings`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  return {
    ok: r.status === 200,
    status: r.status,
    settings: r.ok ? (j as TeamIssueSettings) : undefined,
    error: j.error,
  };
}

/** 设置团队管理员（仅创建人）。admins = unionId[]，不含创建人。 */
export async function putTeamAdmins(
  teamId: string,
  admins: string[],
): Promise<{ ok: boolean; status: number; admins?: string[]; error?: string }> {
  const r = await api(`/api/teams/${teamId}/admins`, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ admins }),
  });
  const j = await r.json().catch(() => ({}));
  return {
    ok: r.status === 200,
    status: r.status,
    admins: r.ok ? (j.admins as string[]) : undefined,
    error: j.error,
  };
}

export async function forceDetachIssue(
  id: string,
  expectedStateRev: number,
): Promise<{ ok: boolean; status: number; issue?: Issue; error?: string }> {
  const r = await jsonPost(`/api/issues/${id}/force-detach`, { expectedStateRev });
  const j = await r.json().catch(() => ({}));
  return { ok: r.status === 200, status: r.status, issue: j.issue, error: j.error };
}

export async function archiveIssue(
  id: string,
): Promise<{ ok: boolean; status: number; error?: string }> {
  const r = await api(`/api/issues/${id}`, { method: 'DELETE' });
  const j = await r.json().catch(() => ({}));
  return { ok: r.status === 200, status: r.status, error: j.error };
}

export async function getIssueEvents(id: string, after = 0): Promise<IssueEvent[]> {
  const r = await api(`/api/issues/${id}/events?after=${after}`);
  if (!r.ok) return [];
  const j = await r.json().catch(() => ({ events: [] }));
  return (j.events ?? []) as IssueEvent[];
}

export function loginHref(): string {
  return loginHrefFor(location);
}

/** 增量授权入口：搜人（contact:user:search）授权页，授完回到当前页。 */
export function searchScopeLoginHref(): string {
  const next = location.pathname + location.search + location.hash;
  return `/auth/login?scope=search&next=${encodeURIComponent(next)}`;
}
