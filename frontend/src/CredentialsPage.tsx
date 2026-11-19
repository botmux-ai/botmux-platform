import { useCallback, useEffect, useRef, useState } from 'react';
import '@arco-design/web-react/dist/css/arco.css';
import { Alert, Button, Card, Checkbox, Empty, Message, Modal, Popconfirm, Radio, Space, Spin, Table, Typography } from '@arco-design/web-react';
import { IconSafe, IconCloud, IconLink, IconCheckCircle, IconCloseCircle, IconArrowRight } from '@arco-design/web-react/icon';
import './credentials.css';
import DevicePageShell from './components/DevicePageShell';
import {
  AllowedMachine,
  CredentialApiError,
  CredentialPlatform,
  CredentialsResp,
  ConsentTeams,
  GrantRow,
  PlatformCard,
  RegionalLogin,
  RequestDetail,
  RequestItemState,
  credentialApi,
  credentialOwner,
  freshLoginHref,
  requestIdFrom,
  requestedScopesFrom,
} from './credential-api';

const fmt = new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'short' });
const when = (ms?: number) => (ms ? fmt.format(new Date(ms)) : '—');

const BASIS_TEXT: Record<NonNullable<GrantRow['basis']>, string> = { self: '你自己的机器', team: '机器主人和你在同一团队', machine: '你允许了这台机器' };
const basisText = (basis?: GrantRow['basis']) => (basis ? BASIS_TEXT[basis] : '—');
const REFUSE_REASON_TEXT: Record<string, string> = {
  consent_missing: '你还没有允许这台机器使用这项服务',
  not_teammate: '你和这台机器的主人不在同一个团队',
  credential_not_found: '你还没有授权这项服务',
  credential_reauth_required: '授权已失效，需要重新授权',
};
const refuseReasonText = (reason?: string) => (reason ? REFUSE_REASON_TEXT[reason] ?? '平台拒绝了这次请求。' : '未提供具体原因');
const REQUEST_STATE_TEXT: Record<RequestItemState, string> = {
  authorize: '还没授权',
  reauthorize: '授权已失效',
  add_scopes: '需要补充权限',
  allow: '还没允许这台机器',
  ready: '已就绪',
};
const GENERIC_ERROR_TEXT = '操作没有成功，请稍后再试。';

function GrantStatus({ outcome }: { outcome: GrantRow['outcome'] }) {
  return <span className={`credential-status ${outcome === 'granted' ? 'is-active' : 'is-refused'}`}>
    {outcome === 'granted' ? <IconCheckCircle /> : <IconCloseCircle />}
    {outcome === 'granted' ? '已发放' : '已拒绝'}
  </span>;
}
/** 飞书回调带回来的 ?error= 解释文案。 */
const AUTH_ERROR_TEXT: Record<string, string> = {
  no_refresh_token: '飞书没有返回 refresh_token，凭据不能自动续期，未保存。请联系平台管理员确认授权 scope 含 offline_access 后重试。',
  store_unavailable: '存储暂时不可用，稍后再试。',
  credential_vault_disabled: '平台未配置凭据库密钥。',
};
/** 写接口返回的 error 码解释文案。 */
const API_ERROR_TEXT: Record<string, string> = {
  scope_not_enabled: '平台飞书应用尚未开通所需权限，请联系平台管理员。',
  scope_unavailable: '拿不到平台飞书应用的权限列表，暂时不能发起授权（管理员可配置 LARK_CREDENTIAL_SCOPES）。',
  offline_access_not_enabled: '平台飞书应用尚未开通 offline_access（获取用户授权数据的持续访问权限），没有它飞书不返回可续期的凭据。请管理员在应用后台开通后重试。',
  provider_unavailable: '对应的授权服务暂时不可用。',
  store_unavailable: '存储暂时不可用，稍后再试。',
  primary_required: '请先连接账号，再授权站点。',
  machine_ownership_changed: '这台机器已换所有者或已移除，请回到飞书让 bot 重新发起授权。',
};

/**
 * 「我的凭据」：按触发人身份调用 CLI 的平台侧授权页。
 * 每个平台一张卡：状态 / 授权或重新授权 / 同意范围（全部团队 或 指定团队）/ 撤销；
 * 底部是最近发放审计（谁的机器、哪个 bot、结果）。
 */
export default function CredentialsPage() {
  const [data, setData] = useState<CredentialsResp | null>(null);
  const [grants, setGrants] = useState<GrantRow[] | null>(null);
  const [needsLogin, setNeedsLogin] = useState(false);
  const [unavailable, setUnavailable] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [selectedGrant, setSelectedGrant] = useState<GrantRow | null>(null);
  const pollTimer = useRef<number | null>(null);
  const requestFlowActive = useRef(false);
  // 机器上 botmux auth request --scope 带来的「这次要补的」lark-cli 权限；只在打开页面时读一次。
  const [requestedScopes, setRequestedScopes] = useState<string[]>(() => requestedScopesFrom(location.search));
  const [notEnabledScopes, setNotEnabledScopes] = useState<string[]>([]);
  // 飞书卡片的授权按钮带来的 ?request=；没有时用最近一条未过期的请求（例如从飞书授权页回来之后）。
  const [urlRequestId] = useState(() => requestIdFrom(location.search));
  const [returned] = useState(() => new URLSearchParams(location.search).has('authorized'));
  const [requestDetail, setRequestDetail] = useState<RequestDetail | null>(null);
  const [requestGone, setRequestGone] = useState(false);
  const activeRequestId = urlRequestId ?? data?.requests[0]?.id;

  const load = useCallback(async () => {
    try {
      const [d, g] = await Promise.all([credentialApi.list(), credentialApi.grants(50)]);
      setData(d);
      setGrants(g.grants);
      setNeedsLogin(false);
      setUnavailable(false);
    } catch (e) {
      if (e instanceof CredentialApiError && e.status === 401) setNeedsLogin(true);
      else if (e instanceof CredentialApiError && e.status === 503) setUnavailable(true);
      else Message.error('加载失败，请稍后刷新重试。');
    }
  }, []);

  const loadRequest = useCallback(async (id: string) => {
    try {
      const detail = await credentialApi.getRequest(id);
      setRequestDetail(detail);
      setRequestGone(false);
      if (detail.request.scopes.length && detail.items.some((i) => i.platform === 'lark-cli' && i.state !== 'ready')) {
        setRequestedScopes((current) => (current.length ? current : detail.request.scopes));
      }
    } catch (e) {
      if (e instanceof CredentialApiError && e.status === 404) setRequestGone(true);
      else if (e instanceof CredentialApiError && e.code === 'stale_session' && urlRequestId) location.href = freshLoginHref();
      else if (urlRequestId) Message.error('加载授权请求失败，请稍后刷新重试。');
    }
  }, [urlRequestId]);

  useEffect(() => {
    if (activeRequestId) void loadRequest(activeRequestId);
  }, [activeRequestId, loadRequest]);

  useEffect(() => {
    void load();
    const q = new URLSearchParams(location.search);
    if (q.get('authorized')) Message.success('授权已保存');
    if (q.get('error')) {
      const granted = q.get('granted');
      const extra = granted
        ? ` 飞书实际授予：${granted}${granted.split(/\s+/).includes('offline_access') ? '' : '（其中没有 offline_access）'}`
        : '';
      Message.error({ content: `授权未保存：${AUTH_ERROR_TEXT[q.get('error') || ''] || q.get('error')}${extra}`, duration: 15000 });
    }
    if (q.get('authorized') || q.get('error')) history.replaceState(null, '', location.pathname);
    return () => { if (pollTimer.current) window.clearTimeout(pollTimer.current); };
  }, [load]);

  const guard = async <T,>(key: string, fn: () => Promise<T>): Promise<T | undefined> => {
    // 注意：把常见错误码翻成能看懂的话，剩下的统一提示。
    setBusy(key);
    try {
      return await fn();
    } catch (e) {
      if (e instanceof CredentialApiError && e.status === 401 && e.code === 'stale_session') {
        location.href = freshLoginHref();
        return undefined;
      }
      if (e instanceof CredentialApiError && e.code === 'scope_not_enabled') {
        // 只有平台应用管理员能处理，提示常驻在页面上，不用弹窗一闪而过。
        setNotEnabledScopes(e.scopes ?? []);
        return undefined;
      }
      Message.error(e instanceof CredentialApiError && API_ERROR_TEXT[e.code] ? `失败：${API_ERROR_TEXT[e.code]}` : GENERIC_ERROR_TEXT);
      return undefined;
    } finally {
      setBusy(null);
    }
  };

  const pollDeviceLogin = useCallback((platform: CredentialPlatform, title: string, pendingId: string) => {
    const tick = async () => {
      try {
        const r = await credentialApi.complete(platform, pendingId);
        if (r.state === 'authorized') { Message.success(`${title} 授权已保存`); await load(); return; }
        if (r.state === 'failed') { Message.error(`${title} 授权失败：${r.detail || ''}`); await load(); return; }
        pollTimer.current = window.setTimeout(tick, 3000);
      } catch (e) {
        if (e instanceof CredentialApiError && e.status === 404) { await load(); return; }
        if (e instanceof CredentialApiError && e.code === 'primary_required') { Message.error(`${title} 授权未保存：${API_ERROR_TEXT.primary_required}`); await load(); return; }
        pollTimer.current = window.setTimeout(tick, 5000);
      }
    };
    pollTimer.current = window.setTimeout(tick, 3000);
  }, [load]);

  // 站点授权进行中时，pending 的平台名是站点记录（形如 `<卡片平台>--<站点>`），轮询要走它所属卡片的路由。
  const pendingId = data?.pending?.id;
  const pendingOwner = data?.pending ? credentialOwner(data.platforms, data.pending.platform) : undefined;
  const pollPlatform = pendingOwner?.card.platform ?? data?.pending?.platform;
  const pendingTitle = pendingOwner
    ? (pendingOwner.region ? `${pendingOwner.card.title} ${pendingOwner.region.title}` : pendingOwner.card.title)
    : pollPlatform;
  useEffect(() => {
    if (pollPlatform && pendingId && !requestFlowActive.current) pollDeviceLogin(pollPlatform, pendingTitle ?? pollPlatform, pendingId);
  }, [pollPlatform, pendingId, pendingTitle, pollDeviceLogin]);

  async function authorize(card: PlatformCard) {
    const { platform } = card;
    const scopes = platform === 'lark-cli' && requestedScopes.length ? requestedScopes : undefined;
    const r = await guard(`auth:${platform}`, () => credentialApi.authorize(platform, scopes));
    if (!r) return;
    if (card.flow === 'oauth' && r.url) { location.href = r.url; return; }
    if (card.flow === 'device' && r.authUrl) { window.open(r.authUrl, '_blank', 'noopener'); await load(); }
  }

  // 设备码登录要在另一个窗口完成：等到授权成功或失败，之后才能继续跳转飞书授权页。
  async function waitForDeviceLogin(platform: CredentialPlatform, pendingId: string): Promise<{ ok: boolean; detail?: string }> {
    for (let i = 0; i < 200; i++) {
      await new Promise((resolve) => window.setTimeout(resolve, 3000));
      const r = await credentialApi.complete(platform, pendingId);
      if (r.state === 'authorized') return { ok: true };
      if (r.state === 'failed') return { ok: false, detail: r.detail };
    }
    return { ok: false, detail: '等待超时' };
  }

  // 一次点击：先记录「允许这台机器」，再按顺序完成各服务授权；飞书授权会离开本页，所以放在最后。
  async function authorizeRequest(detail: RequestDetail) {
    requestFlowActive.current = true;
    try {
      await guard('request', async () => {
        await credentialApi.allowRequest(detail.request.id);
        const todo = detail.items.filter((i) => i.state === 'authorize' || i.state === 'reauthorize' || i.state === 'add_scopes');
        const flowOf = (platform: CredentialPlatform) => data?.platforms.find((p) => p.platform === platform)?.flow;
        for (const item of todo.filter((i) => flowOf(i.platform) === 'device')) {
          const r = await credentialApi.authorize(item.platform);
          if (!r.pendingId || !r.authUrl) continue;
          window.open(r.authUrl, '_blank', 'noopener');
          await load();
          const done = await waitForDeviceLogin(item.platform, r.pendingId);
          if (!done.ok) {
            Message.error(`${item.title} 授权失败：${done.detail || ''}`);
            await Promise.all([load(), loadRequest(detail.request.id)]);
            return;
          }
        }
        const lark = todo.find((i) => flowOf(i.platform) === 'oauth');
        if (lark) {
          const r = await credentialApi.authorize(lark.platform, detail.request.scopes);
          if (r.url) { location.href = r.url; return; }
        }
        Message.success('已授权，可以回到飞书继续了');
        await Promise.all([load(), loadRequest(detail.request.id)]);
      });
    } finally {
      requestFlowActive.current = false;
    }
  }

  async function revokeMachine(machine: AllowedMachine) {
    const r = await guard(`machine:${machine.machineId}`, () => credentialApi.revokeMachine(machine.machineId));
    if (r) { Message.success('已撤销对这台机器的允许'); await load(); }
  }

  async function authorizeRegion(card: PlatformCard, region: RegionalLogin) {
    const r = await guard(`auth:${region.platform}`, () => credentialApi.authorizeRegion(card.platform, region.region));
    if (r?.authUrl) { window.open(r.authUrl, '_blank', 'noopener'); await load(); }
  }

  async function revokeRegion(card: PlatformCard, region: RegionalLogin) {
    const r = await guard(`revoke:${region.platform}`, () => credentialApi.revokeRegion(card.platform, region.region));
    if (r) { Message.success(`已撤销 ${region.title}`); await load(); }
  }

  async function setConsent(platform: CredentialPlatform, teams: ConsentTeams) {
    const r = await guard(`consent:${platform}`, () => credentialApi.setConsent(platform, teams));
    if (r) { Message.success('已更新允许的团队'); await load(); }
  }

  async function revoke(platform: CredentialPlatform) {
    const r = await guard(`revoke:${platform}`, () => credentialApi.revoke(platform));
    if (r) { Message.success('已撤销'); await load(); }
  }

  if (needsLogin) {
    return (
      <DevicePageShell className="credentials-page" title="我的凭据">
        <Alert type="warning" content={<span>需要登录。<a href={freshLoginHref()}>去登录</a></span>} />
      </DevicePageShell>
    );
  }
  if (unavailable) {
    return (
      <DevicePageShell className="credentials-page" title="我的凭据">
        <Alert type="error" content="存储暂时不可用，稍后再试。" />
      </DevicePageShell>
    );
  }
  if (!data) {
    return (
      <DevicePageShell className="credentials-page" title="我的凭据"><div className="credential-loading" role="status" aria-label="正在加载凭据"><Spin /></div></DevicePageShell>
    );
  }

  const requestReady = requestDetail?.items.every((i) => i.state === 'ready') ?? false;
  const showRequest = requestDetail !== null && !requestGone && (urlRequestId !== undefined || returned || !requestReady);
  const platformTitle = (platform: string) => data.platforms.find((p) => p.platform === platform.split('--')[0])?.title ?? platform;
  const requestInfo = requestDetail?.request;
  const requestMachine = requestInfo
    ? `${requestInfo.ownerName ? `${requestInfo.ownerName}的机器` : '这台机器'}${requestInfo.machineName ? `「${requestInfo.machineName}」` : ''}`
    : '';

  return (
    <DevicePageShell
      className="credentials-page"
      title="我的凭据"
      subtitle="管理个人授权、机器使用范围与最近发放记录。"
    >
      {!data.vaultEnabled && <Alert type="error" style={{ marginBottom: 16 }} content="本平台未配置凭据库密钥（CREDENTIAL_KEK），暂不能保存授权。" />}
      {urlRequestId !== undefined && requestGone && (
        <Alert type="warning" style={{ marginBottom: 16 }} content="这条授权请求已失效，或不是发给你的。请回到飞书，让 bot 再触发一次。如果你已经点过允许，可以直接回到飞书继续。" />
      )}
      {showRequest && requestDetail && requestInfo && (
        <section className="credential-request" aria-labelledby="credential-request-heading">
          <h2 id="credential-request-heading">
            {`${requestInfo.botName ? `bot「${requestInfo.botName}」` : '一个未命名的 bot'}${requestDetail.machineChanged ? '的授权请求已不适用' : requestReady ? ` 现在可以用你的身份使用 ${requestDetail.items.map((i) => i.title).join('、')}` : ` 想以你的身份使用 ${requestDetail.items.map((i) => i.title).join('、')}`}`}
          </h2>
          {requestDetail.machineChanged ? (
            <p className="credential-request-key">这台机器已换所有者或已移除，请回到飞书让 bot 重新发起授权。</p>
          ) : (
            <>
              <p className="credential-request-key">
                {requestReady
                  ? `${requestMachine}上的 bot 现在可以用你的身份使用这些服务。`
                  : `允许后，${requestMachine}上的 bot 可以用你的身份使用这些服务。机器主人能控制这台机器，只允许你信任的人的机器。可随时在下方「允许使用的机器」里撤销。`}
              </p>
              <ul className="credential-request-items">
                {requestDetail.items.map((i) => (
                  <li key={i.platform}>
                    <span>{i.title}</span>
                    <span className={`credential-status ${i.state === 'ready' ? 'is-active' : 'is-warning'}`}>{REQUEST_STATE_TEXT[i.state]}</span>
                  </li>
                ))}
              </ul>
              <div className="credential-request-action">
                {requestReady ? (
                  <p className="credential-request-key">可以回到飞书继续了。</p>
                ) : (
                  <Button type="primary" disabled={!data.vaultEnabled || busy !== null} loading={busy === 'request'} onClick={() => void authorizeRequest(requestDetail)}>允许这台机器使用</Button>
                )}
              </div>
            </>
          )}
        </section>
      )}
      {requestedScopes.length > 0 && (!showRequest || notEnabledScopes.length > 0) && (
        <Alert
          className="credential-scope-request"
          type={notEnabledScopes.length ? 'error' : 'info'}
          style={{ marginBottom: 16 }}
          title={notEnabledScopes.length ? '平台飞书应用还没开通部分权限' : 'bot 需要你补充飞书权限'}
          closable
          onClose={() => { setRequestedScopes([]); setNotEnabledScopes([]); history.replaceState(null, '', location.pathname); }}
          content={notEnabledScopes.length ? (
            <div>
              <p>以下用户权限平台飞书应用尚未开通，现在授权也补不上：</p>
              <ul className="credential-scope-list">{notEnabledScopes.map((s) => <li key={s}><code>{s}</code></li>)}</ul>
              <p>请联系平台管理员在飞书开发者后台为平台应用开通（用户身份）并发布新版本，然后回到本页重试。</p>
            </div>
          ) : (
            <div>
              <p>在下方「飞书」卡片点「补充授权」，只会新增以下权限，已有授权保留：</p>
              <ul className="credential-scope-list">{requestedScopes.map((s) => <li key={s}><code>{s}</code></li>)}</ul>
            </div>
          )}
        />
      )}
      <div className="credential-notice"><IconSafe aria-hidden="true" /><p>授权用于 bot 的「按触发人身份调用 CLI」。平台保存刷新凭据，向已绑定的机器发放短期凭据。</p></div>
      <section aria-labelledby="credential-services-heading">
      <div className="credential-section-head"><h2 id="credential-services-heading">服务授权</h2><span>{data.credentials.filter((c) => c.status === 'active' && data.platforms.some((p) => p.platform === c.platform)).length} / {data.platforms.length} 已授权</span></div>
      <div className="credential-services">
        {data.platforms.map((card) => {
          const { platform } = card;
          const row = data.credentials.find((c) => c.platform === platform);
          const provider = card.available;
          const pending = data.pending?.platform === platform ? data.pending : undefined;
          const consent: ConsentTeams = row?.consentTeams ?? 'all';
          return (
            <Card key={platform} bordered className="credential-service">
              <div className="credential-service-identity">
              <div className="credential-service-heading">
                <span className={`credential-service-icon ${card.flow}`} aria-hidden="true">{card.flow === 'oauth' ? <IconLink /> : <IconCloud />}</span>
                <div><h3>{card.title}</h3></div>
                <span className={`credential-status ${pending ? 'is-pending' : row?.status === 'active' ? 'is-active' : row ? 'is-warning' : ''}`}>
                  {pending ? '授权进行中' : row?.status === 'active' ? '已授权' : row ? '需重新授权' : '未授权'}
                </span>
              </div>
              <p className="credential-service-description">{card.description}</p>
              </div>
                  {row && (
                    <dl className="credential-account">
                      {row.meta.account && <div><dt>账号</dt><dd>{row.meta.account}</dd></div>}
                      <div><dt>授权时间</dt><dd>{when(row.createdAt)}</dd></div>
                      <div><dt>最近使用</dt><dd>{when(row.lastUsedAt)}</dd></div>
                      {row.refreshExpiresAt && <div><dt>登录态到期</dt><dd>{when(row.refreshExpiresAt)}</dd></div>}
                      {row.statusReason && <div><dt>状态说明</dt><dd>{row.statusReason}</dd></div>}
                    </dl>
                  )}
                  {pending && (
                    <Typography.Paragraph className="credential-pending" style={{ margin: '8px 0 0' }}>
                      请在新窗口完成 {card.title} 授权；完成后本页会自动刷新。<a href={pending.authUrl} target="_blank" rel="noreferrer noopener">重新打开授权链接</a>
                    </Typography.Paragraph>
                  )}
                <Space className="credential-actions">
                  <Button
                    type={row?.status === 'active' && !(platform === 'lark-cli' && requestedScopes.length) ? 'secondary' : 'primary'}
                    disabled={!data.vaultEnabled || !provider || busy !== null}
                    loading={busy === `auth:${platform}`}
                    onClick={() => void authorize(card)}
                  >
                    {platform === 'lark-cli' && requestedScopes.length ? '补充授权' : row ? '重新授权' : '连接账号'}
                  </Button>
                  {row && (
                    <Popconfirm style={{ maxWidth: 300 }} title={`撤销后，所有机器使用这份授权的调用都会立即被拒绝${card.regions?.length ? '，下面各站点的授权也一并撤销' : ''}。确定撤销？`} onOk={() => void revoke(platform)}>
                      <Button type="text" status="danger" disabled={busy !== null}>撤销授权</Button>
                    </Popconfirm>
                  )}
                </Space>
              {!provider && <Alert style={{ marginTop: 12 }} type="warning" content={card.flow === 'oauth' ? '平台未配置飞书应用。' : `平台暂时不能运行 ${platform}。`} />}
              {row && (
                <div className="credential-consent">
                  <h4>允许使用的团队</h4>
                  <Radio.Group
                    aria-label={`${platform} 允许使用的团队`}
                    type="button"
                    size="small"
                    value={consent === 'all' ? 'all' : 'teams'}
                    disabled={busy !== null}
                    onChange={(v) => { if (v === 'all') void setConsent(platform, 'all'); else void setConsent(platform, Array.isArray(consent) ? consent : []); }}
                  >
                    <Radio value="all">所在的全部团队</Radio>
                    <Radio value="teams">指定团队</Radio>
                  </Radio.Group>
                  {consent !== 'all' && (
                    <div style={{ marginTop: 8 }}>
                      {data.teams.length === 0 ? (
                        <Typography.Text type="secondary">尚未加入任何团队。</Typography.Text>
                      ) : (
                        <Checkbox.Group
                          value={consent}
                          disabled={busy !== null}
                          onChange={(vals) => void setConsent(platform, vals as string[])}
                        >
                          {data.teams.map((t) => <Checkbox key={t.id} value={t.id}>{t.name}</Checkbox>)}
                        </Checkbox.Group>
                      )}
                      {Array.isArray(consent) && consent.length === 0 && (
                        <Typography.Text type="warning" style={{ display: 'block', marginTop: 4 }}>尚未选择团队，仅本人机器可使用这份授权。</Typography.Text>
                      )}
                    </div>
                  )}
                </div>
              )}
              {card.regions?.length ? (
                <div className="credential-regions">
                  <h4>海外站点</h4>
                  <p className="credential-regions-hint">
                    {row
                      ? '登录按站点分开保存：要让机器访问哪个站点，就单独授权哪个站点；同意的团队与上面一致。'
                      : `先连接 ${card.title} 账号，再按需授权海外站点。`}
                  </p>
                  <ul>
                    {card.regions.map((region) => {
                      const regionRow = data.credentials.find((c) => c.platform === region.platform);
                      const regionPending = data.pending?.platform === region.platform ? data.pending : undefined;
                      return (
                        <li key={region.platform} className="credential-region">
                          <div className="credential-region-name">
                            <strong>{region.title}</strong>
                            <span className="credential-cli">{regionRow?.meta.account ?? region.site}</span>
                          </div>
                          <span
                            className={`credential-status ${regionPending ? 'is-pending' : regionRow?.status === 'active' ? 'is-active' : regionRow ? 'is-warning' : ''}`}
                            title={regionRow?.statusReason}
                          >
                            {regionPending ? '授权进行中' : regionRow?.status === 'active' ? '已授权' : regionRow ? '需重新授权' : '未授权'}
                          </span>
                          <Space size={4} className="credential-region-actions">
                            {regionPending && <a href={regionPending.authUrl} target="_blank" rel="noreferrer noopener">打开授权链接</a>}
                            <Button
                              size="small"
                              type={regionRow?.status === 'active' ? 'secondary' : 'primary'}
                              disabled={!data.vaultEnabled || !provider || !row || busy !== null}
                              loading={busy === `auth:${region.platform}`}
                              onClick={() => void authorizeRegion(card, region)}
                            >
                              {regionRow ? '重新授权' : '授权'}
                            </Button>
                            {regionRow && (
                              <Popconfirm position="tr" style={{ maxWidth: 300 }} title={`撤销后，机器访问 ${region.site} 站点的调用会被拒绝。确定撤销？`} onOk={() => void revokeRegion(card, region)}>
                                <Button size="small" type="text" status="danger" disabled={busy !== null}>撤销</Button>
                              </Popconfirm>
                            )}
                          </Space>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ) : null}
              {card.linked?.map((linked) => <div key={linked.title} className="credential-linked-service"><IconLink aria-hidden="true" /><div><strong>{linked.title}</strong><p>{linked.description}</p></div></div>)}
            </Card>
          );
        })}
      </div>
      </section>

      <section className="credential-machines" aria-labelledby="credential-machines-heading">
      <div className="credential-section-head"><h2 id="credential-machines-heading">允许使用的机器</h2><span>{data.machines.length} 台</span></div>
      {data.machines.length === 0 ? <Empty description="还没有允许任何机器。在授权页点「允许这台机器使用」后，机器会出现在这里。" /> : (
        <>
        <p className="credential-section-description">在授权页点「允许这台机器使用」后，对应机器上的 bot 可以用你的身份使用这些服务；机器换了所有者后自动失效。</p>
        <ul className="credential-machine-list">
          {data.machines.map((machine) => (
            <li key={machine.machineId} className="credential-machine">
              <strong className="credential-machine-name">{machine.machineName || '已移除的机器'}</strong>
              <span className="credential-cli credential-machine-meta">
                {machine.current ? `所有者 ${machine.ownerName || '—'} · ` : ''}
                {machine.platforms.map(platformTitle).join('、')} · 允许于 {when(machine.updatedAt)}
              </span>
              <span className={`credential-status credential-machine-status ${machine.current ? 'is-active' : 'is-warning'}`}>{machine.current ? '生效中' : '已失效'}</span>
              <Space size={4} className="credential-machine-actions">
                <Popconfirm position="tr" style={{ maxWidth: 300 }} title="撤销后，这台机器上的 bot 不能再以你的身份调用这些服务。确定撤销？" onOk={() => void revokeMachine(machine)}>
                  <Button size="small" type="text" status="danger" disabled={busy !== null}>撤销</Button>
                </Popconfirm>
              </Space>
            </li>
          ))}
        </ul>
        </>
      )}
      </section>

      <section className="credential-history" aria-labelledby="credential-history-heading">
      <div className="credential-section-head"><h2 id="credential-history-heading">最近发放记录</h2><span>最近 {grants?.length ?? 0} 条</span></div>
      <p className="credential-section-description">包含已发放与已拒绝的申请。首次在新机器上使用时，将发送飞书通知。</p>
      {grants === null ? <Spin /> : grants.length === 0 ? <Empty description="还没有发放记录" /> : (
        <>
        <Table
          className="credential-grants-table"
          size="small"
          tableLayoutFixed
          scroll={{ x: 1000 }}
          pagination={false}
          rowKey={(r: GrantRow) => `${r.at}-${r.machineId}-${r.platform}`}
          data={grants}
          columns={[
            { title: '时间', dataIndex: 'at', render: (v: number) => when(v), width: 150 },
            { title: '平台', dataIndex: 'platform', width: 90, render: (v: string) => platformTitle(v) },
            { title: '机器', dataIndex: 'machineName', width: 200, ellipsis: true, render: (v: string, r: GrantRow) => <span title={v || r.machineId}>{v || r.machineId}</span> },
            { title: 'bot', dataIndex: 'appId', width: 180, ellipsis: true, render: (v: string) => <span className="credential-identifier" title={v}>{v || '—'}</span> },
            { title: '结果', dataIndex: 'outcome', width: 120, render: (v: GrantRow['outcome']) => <GrantStatus outcome={v} /> },
            { title: '放行依据', dataIndex: 'basis', width: 160, render: (v: GrantRow['basis']) => basisText(v) },
            { title: '详情', width: 100, render: (_: unknown, r: GrantRow) => <Button type="text" onClick={() => setSelectedGrant(r)} aria-label={`查看 ${r.machineName || r.machineId} 的发放记录`}>查看<IconArrowRight /></Button> },
          ]}
        />
        <ul className="credential-mobile-grants">
          {grants.map((r, i) => <li key={`${r.at}-${r.machineId}-${r.platform}-${i}`}>
            <button type="button" onClick={() => setSelectedGrant(r)} aria-label={`查看 ${r.machineName || r.machineId} 的发放记录`}>
              <span className="credential-grant-top"><span>{platformTitle(r.platform)}</span><GrantStatus outcome={r.outcome} /></span>
              <strong>{r.machineName || r.machineId}</strong>
              {r.basis && <span className="credential-grant-basis">放行依据：{basisText(r.basis)}</span>}
              <span className="credential-grant-bottom"><time dateTime={new Date(r.at).toISOString()}>{when(r.at)}</time><span>查看详情 <IconArrowRight /></span></span>
            </button>
          </li>)}
        </ul>
        </>
      )}
      </section>
      <Modal title="发放记录详情" visible={selectedGrant !== null} onCancel={() => setSelectedGrant(null)} footer={null} className="credential-detail" style={{ width: 'min(560px, calc(100vw - 32px))' }}>
        {selectedGrant && <dl className="credential-detail-list">
          <div><dt>结果</dt><dd><GrantStatus outcome={selectedGrant.outcome} /></dd></div>
          <div><dt>时间</dt><dd>{when(selectedGrant.at)}</dd></div>
          <div><dt>平台</dt><dd>{platformTitle(selectedGrant.platform)}</dd></div>
          <div><dt>机器名称</dt><dd>{selectedGrant.machineName || '—'}</dd></div>
          <div><dt>机器 ID</dt><dd className="credential-identifier">{selectedGrant.machineId}</dd></div>
          <div><dt>Bot</dt><dd className="credential-identifier">{selectedGrant.appId || '—'}</dd></div>
          {selectedGrant.outcome === 'granted' && <div><dt>放行依据</dt><dd>{basisText(selectedGrant.basis)}</dd></div>}
          {selectedGrant.outcome === 'refused' && <div><dt>拒绝原因</dt><dd>{refuseReasonText(selectedGrant.reason)}</dd></div>}
        </dl>}
      </Modal>
    </DevicePageShell>
  );
}
