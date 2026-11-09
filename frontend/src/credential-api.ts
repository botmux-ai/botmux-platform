/**
 * 「我的凭据」页的 API 客户端（可注入 fetch 以便单测）。
 */
/** 平台名由后端下发：lark-cli 之外的设备码登录平台取决于部署。 */
export type CredentialPlatform = string;
export type ConsentTeams = 'all' | string[];

export interface CredentialRow {
  platform: CredentialPlatform;
  status: 'active' | 'reauth_required';
  statusReason?: string;
  consentTeams: ConsentTeams;
  createdAt: number;
  updatedAt: number;
  lastUsedAt?: number;
  lastUsedMachineId?: string;
  refreshExpiresAt?: number;
  meta: { account?: string; appId?: string };
}

/** 页面上的一张平台卡：oauth 跳转授权（lark-cli），device 打开登录链接后轮询 complete。 */
export interface PlatformCard {
  platform: CredentialPlatform;
  flow: 'oauth' | 'device';
  available: boolean;
  title: string;
  description: string;
  linked?: Array<{ title: string; description: string }>;
}

export interface CredentialsResp {
  vaultEnabled: boolean;
  providers: Record<CredentialPlatform, boolean>;
  platforms: PlatformCard[];
  teams: Array<{ id: string; name: string }>;
  credentials: CredentialRow[];
  pending?: { platform: CredentialPlatform; id: string; authUrl: string; createdAt: number };
}

export interface GrantRow {
  at: number;
  platform: CredentialPlatform;
  machineId: string;
  machineName: string;
  ownerUnionId: string;
  appId: string;
  outcome: 'granted' | 'refused';
  reason?: string;
}

export class CredentialApiError extends Error {
  constructor(readonly status: number, readonly code: string, readonly loginUrl?: string, readonly scopes?: string[]) {
    super(code);
    this.name = 'CredentialApiError';
  }
}

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

async function responseJson<T>(r: Response): Promise<T> {
  const body = (await r.json().catch(() => ({}))) as T & { error?: string; loginUrl?: string; scopes?: unknown };
  if (!r.ok) {
    const scopes = Array.isArray(body.scopes) ? body.scopes.filter((s): s is string => typeof s === 'string') : undefined;
    throw new CredentialApiError(r.status, body.error || `http_${r.status}`, body.loginUrl, scopes);
  }
  return body;
}

export function createCredentialApi(fetchImpl: FetchLike) {
  const call = (path: string, init?: RequestInit) =>
    fetchImpl(path, { credentials: 'same-origin', cache: 'no-store', ...init });
  const json = (method: string, path: string, body?: unknown) =>
    call(path, {
      method,
      headers: body !== undefined ? { 'content-type': 'application/json' } : undefined,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  return {
    list: () => call('/api/credentials').then((r) => responseJson<CredentialsResp>(r)),
    grants: (limit = 50) => call(`/api/credentials/grants?limit=${limit}`).then((r) => responseJson<{ grants: GrantRow[] }>(r)),
    /** scopes：lark-cli 增量授权要补的权限（来自 ?scope=）；不传就是完整的默认授权。 */
    authorize: (platform: CredentialPlatform, scopes?: string[]) =>
      json('POST', `/api/credentials/${platform}/authorize`, scopes?.length ? { scopes } : undefined).then((r) => responseJson<{ url?: string; pendingId?: string; authUrl?: string }>(r)),
    complete: (platform: CredentialPlatform, pendingId: string) =>
      json('POST', `/api/credentials/${platform}/complete`, { pendingId }).then((r) =>
        responseJson<{ state: 'authorized' | 'pending' | 'failed' | 'unavailable'; authUrl?: string; detail?: string }>(r)),
    setConsent: (platform: CredentialPlatform, teams: ConsentTeams) =>
      json('PUT', `/api/credentials/${platform}/consent`, { teams }).then((r) => responseJson<{ ok: true; consentTeams: ConsentTeams }>(r)),
    revoke: (platform: CredentialPlatform) =>
      json('DELETE', `/api/credentials/${platform}`).then((r) => responseJson<{ ok: true; removed: boolean }>(r)),
  };
}

/** 与平台后端一致的飞书 scope 名称规则。 */
const LARK_SCOPE_RE = /^[a-z0-9_]+(:[a-z0-9_.-]+)+$|^offline_access$/;
/** 后端一次最多接受的增量 scope 数。 */
export const MAX_REQUESTED_SCOPES = 100;

/**
 * 机器上 `botmux auth request --scope …` 生成的 /credentials?scope=a+b 链接里要补的 lark-cli 权限。
 * 空格或逗号分隔，可重复出现；去重保序，不合法的名字丢掉，超过上限只取前 MAX_REQUESTED_SCOPES 个。
 */
export function requestedScopesFrom(search: string): string[] {
  const out: string[] = [];
  for (const value of new URLSearchParams(search).getAll('scope')) {
    for (const scope of value.split(/[\s,]+/)) {
      if (scope.length <= 128 && LARK_SCOPE_RE.test(scope) && !out.includes(scope)) out.push(scope);
    }
  }
  return out.slice(0, MAX_REQUESTED_SCOPES);
}

export const credentialApi = createCredentialApi((input, init) => fetch(input, init));

export function freshLoginHref(): string {
  return `/auth/login?next=${encodeURIComponent(location.pathname + location.search)}`;
}
