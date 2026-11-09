import { useCallback, useEffect, useRef, useState } from 'react';
import '@arco-design/web-react/dist/css/arco.css';
import {
  Button,
  Space,
  Avatar,
  Typography,
  Card,
  Spin,
  Message,
  Tabs,
  Tooltip,
  Modal,
} from '@arco-design/web-react';
import { IconCopy, IconDownload, IconMoon, IconSun } from '@arco-design/web-react/icon';
import type { Me, Machine, Team } from './api';
import {
  ApiError,
  getMe,
  getMachines,
  getTeams,
  acceptInvite,
  logout,
  loginHref,
} from './api';
import { initialTheme, applyTheme, copyText } from './util';
import { identifyUser, installCommand, INSTALL_HINT, SOURCE_LINK } from '@edition/app';
import { acceptInviteAndClearOnSuccess, urlWithoutInvite } from './invite-flow';
import Machines from './components/Machines';
import Teams from './components/Teams';
import IssueBoard from './components/IssueBoard';
import VersionDashboard from './components/VersionDashboard';

function initial(name: string): string {
  return (name || '?').trim().charAt(0).toUpperCase() || '?';
}

export default function App() {
  const [me, setMe] = useState<Me | null | undefined>(undefined); // undefined=未知(加载中)
  const [theme, setTheme] = useState<'light' | 'dark'>(() => initialTheme());

  const [machines, setMachines] = useState<Machine[] | null>(null);
  // 别人授权给我协管的机器（与自己 owner 的分开展示）。
  const [managedMachines, setManagedMachines] = useState<Machine[] | null>(null);
  const [latestVersion, setLatestVersion] = useState<string | null>(null);
  const [machinesError, setMachinesError] = useState(false);

  const [teams, setTeams] = useState<Team[] | null>(null);
  const [teamsError, setTeamsError] = useState(false);

  // 顶部导航：我的机器 / 团队 / 问题板 / 版本大盘（用 hash 记忆，刷新保留）
  type TabKey = 'machines' | 'teams' | 'issues' | 'versions';
  const parseTab = (hash: string): TabKey =>
    hash === '#teams' ? 'teams' : hash === '#issues' ? 'issues' : hash === '#versions' ? 'versions' : 'machines';
  const [activeTab, setActiveTab] = useState<TabKey>(() => parseTab(location.hash));
  function switchTab(key: string) {
    const k = parseTab('#' + key);
    setActiveTab(k);
    history.replaceState(null, '', '#' + k);
  }

  // 深层组件（如「去绑定机器」CTA）通过改 location.hash 切 tab —— 这里监听同步状态。
  useEffect(() => {
    const onHash = () => setActiveTab(parseTab(location.hash));
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const refreshMachines = useCallback(async () => {
    try {
      const j = await getMachines();
      setMachines(j.machines);
      setManagedMachines(j.managedMachines ?? []);
      setLatestVersion(j.latestVersion);
      setMachinesError(false);
    } catch (e) {
      if (e instanceof Error && e.message === 'unauthenticated') {
        setMe(null);
        return;
      }
      setMachinesError(true);
    }
  }, []);

  const refreshTeams = useCallback(async () => {
    try {
      const t = await getTeams();
      setTeams(t);
      setTeamsError(false);
    } catch (e) {
      if (e instanceof Error && e.message === 'unauthenticated') {
        setMe(null);
        return;
      }
      setTeamsError(true);
    }
  }, []);

  // 首次：拉 me
  useEffect(() => {
    getMe().then(setMe);
  }, []);

  useEffect(() => {
    if (me) identifyUser(me.unionId, me.name);
  }, [me]);

  // 处理邀请深链（登录后）
  const inviteHandled = useRef(false);
  useEffect(() => {
    if (!me || inviteHandled.current) return;
    const inv = new URLSearchParams(location.search).get('invite');
    if (!inv) return;
    inviteHandled.current = true;
    acceptInviteAndClearOnSuccess(
      () => acceptInvite(inv),
      () => history.replaceState(null, '', urlWithoutInvite(location)),
    ).then((r) => {
      if (r.status === 200) {
        Message.success('已加入团队：' + (r.teamName || ''));
        refreshTeams();
      } else if (r.status === 404) {
        Message.error('团队不存在或已解散');
      } else {
        Message.error('邀请无效或已过期');
      }
    }).catch((e: unknown) => {
      // stale_session 已由公共 API 层带着完整邀请 URL 跳转；这里只兜底其它错误。
      if (e instanceof ApiError && e.code === 'stale_session') return;
      Message.error('接受邀请失败，请稍后重试');
    });
  }, [me, refreshTeams]);

  // 登录后：首拉 + 5s 轮询
  useEffect(() => {
    if (!me) return;
    refreshMachines();
    refreshTeams();
    const t = setInterval(() => {
      refreshMachines();
      refreshTeams();
    }, 5000);
    return () => clearInterval(t);
  }, [me, refreshMachines, refreshTeams]);

  const themeToggle = (
    <Button
      shape="circle"
      type="text"
      aria-label="切换主题"
      icon={theme === 'dark' ? <IconSun /> : <IconMoon />}
      onClick={() => setTheme((c) => (c === 'dark' ? 'light' : 'dark'))}
    />
  );

  if (me === undefined) {
    return (
      <>
        <Header right={themeToggle} />
        <div className="app-wrap" style={{ textAlign: 'center', paddingTop: 64 }}>
          <Spin tip="加载中…" />
        </div>
      </>
    );
  }

  if (me === null) {
    // 带邀请链接来的未登录访客：登录后由 loginHref 的 next 带回本页，自动加入团队。
    const hasInvite = !!new URLSearchParams(location.search).get('invite');
    return (
      <>
        <Header right={themeToggle} showInstallOnFirstVisit />
        <div className="app-wrap">
          <Card className="login-card">
            <Typography.Title heading={5} style={{ marginTop: 0, letterSpacing: '-0.022em' }}>
              {hasInvite ? '加入团队' : '登录'}
            </Typography.Title>
            <Typography.Paragraph type="secondary">
              {hasInvite
                ? '用飞书登录后即自动加入邀请你的团队。'
                : '用飞书登录后，即可看到你各台机器的 botmux dashboard。'}
            </Typography.Paragraph>
            <Button type="primary" onClick={() => (location.href = loginHref())}>
              {hasInvite ? '飞书登录并加入' : '飞书登录'}
            </Button>
          </Card>
        </div>
      </>
    );
  }

  return (
    <>
      <Header
        right={
          <Space size={8}>
            {themeToggle}
            <Avatar size={28}>{me.avatar ? <img alt={me.name} src={me.avatar} /> : initial(me.name)}</Avatar>
            <Typography.Text type="secondary">{me.name}</Typography.Text>
            <Button
              size="small"
              onClick={async () => {
                await logout();
                location.reload();
              }}
            >
              退出
            </Button>
          </Space>
        }
      />
      <div className="app-wrap">
        <Tabs className="app-tabs" activeTab={activeTab} onChange={switchTab} type="rounded">
          <Tabs.TabPane key="machines" title="我可管理的机器">
            <Machines
              machines={machines}
              managedMachines={managedMachines}
              latestVersion={latestVersion}
              loading={machines === null && !machinesError}
              error={machinesError}
              onChanged={refreshMachines}
            />
          </Tabs.TabPane>
          <Tabs.TabPane key="teams" title="团队">
            <Teams
              teams={teams}
              loading={teams === null && !teamsError}
              error={teamsError}
              onChanged={refreshTeams}
              myUnionId={me.unionId}
            />
          </Tabs.TabPane>
          <Tabs.TabPane key="issues" title="问题板">
            <IssueBoard teams={teams} myUnionId={me.unionId} />
          </Tabs.TabPane>
          <Tabs.TabPane key="versions" title="版本大盘">
            <VersionDashboard active={activeTab === 'versions'} />
          </Tabs.TabPane>
        </Tabs>
      </div>
    </>
  );
}

function Header({
  right,
  showInstallOnFirstVisit = false,
}: {
  right?: React.ReactNode;
  showInstallOnFirstVisit?: boolean;
}) {
  return (
    <header className="app-header">
      <div className="brand">
        <img className="brand-logo" src="/favicon.png" alt="" />
        botmux 平台
      </div>
      <div className="header-right">
        <InstallEntry autoOpen={showInstallOnFirstVisit} />
        <NavLinks />
        {right}
      </div>
    </header>
  );
}

const INSTALL_COMMAND = installCommand(window.location.origin);
const INSTALL_PROMPT_SEEN_KEY = 'botmux_platform_install_prompt_seen_v2';

function InstallEntry({ autoOpen }: { autoOpen: boolean }) {
  const [visible, setVisible] = useState(false);
  const autoOpenHandled = useRef(false);

  useEffect(() => {
    if (!autoOpen || autoOpenHandled.current) return;
    autoOpenHandled.current = true;
    try {
      if (localStorage.getItem(INSTALL_PROMPT_SEEN_KEY)) return;
      localStorage.setItem(INSTALL_PROMPT_SEEN_KEY, '1');
    } catch {
      // 隐私模式禁用 localStorage 时仍展示本次提示，不影响安装入口。
    }
    setVisible(true);
  }, [autoOpen]);

  async function copyInstallCommand() {
    (await copyText(INSTALL_COMMAND))
      ? Message.success('一键安装命令已复制')
      : Message.error('复制失败，请手动选择命令');
  }

  return (
    <>
      <Tooltip content="一键安装">
        <Button
          className="header-link"
          shape="circle"
          type="text"
          aria-label="打开一键安装"
          icon={<IconDownload />}
          onClick={() => setVisible(true)}
        />
      </Tooltip>
      <Modal
        title="一键安装 Botmux"
        visible={visible}
        onCancel={() => setVisible(false)}
        unmountOnExit
        style={{ width: 520, maxWidth: 'calc(100vw - 24px)' }}
        footer={
          <Space>
            <Button onClick={() => setVisible(false)}>关闭</Button>
            <Button type="primary" icon={<IconCopy />} onClick={copyInstallCommand}>
              复制安装命令
            </Button>
          </Space>
        }
      >
        <Typography.Paragraph>
          在 macOS 或 Linux 终端运行下面这条命令，即可自动安装 Botmux、运行环境和默认 AI 编程机器人。
        </Typography.Paragraph>
        <div className="install-command-row">
          <code className="mono-block install-command">{INSTALL_COMMAND}</code>
          <Button
            className="install-copy-button"
            shape="circle"
            aria-label="复制一键安装命令"
            icon={<IconCopy />}
            onClick={copyInstallCommand}
          />
        </div>
        <Typography.Paragraph type="secondary" className="install-hint">
          {INSTALL_HINT}
        </Typography.Paragraph>
      </Modal>
    </>
  );
}

// 顶部右上角外链入口（平台源码 / GitHub / 文档站）
const NAV_LINKS: { href: string; label: string; icon: React.ReactNode }[] = [
  {
    href: SOURCE_LINK.href,
    label: '平台源码',
    icon: SOURCE_LINK.host === 'gitlab' ? <GitlabIcon /> : <GithubIcon />,
  },
  {
    href: 'https://github.com/deepcoldy/botmux',
    label: 'GitHub',
    icon: <GithubIcon />,
  },
  {
    href: 'https://deepcoldy.github.io/botmux/',
    label: '文档站',
    icon: <DocIcon />,
  },
];

function NavLinks() {
  return (
    <>
      <a className="header-text-link" href="/devices">设备</a>
      <a className="header-text-link" href="/credentials">凭据</a>
      <a className="header-text-link" href="/mobile">移动版</a>
      {NAV_LINKS.map((l) => (
        <Tooltip key={l.href} content={l.label}>
          <a
            className="header-link"
            href={l.href}
            target="_blank"
            rel="noreferrer noopener"
            aria-label={l.label}
          >
            {l.icon}
          </a>
        </Tooltip>
      ))}
    </>
  );
}

function GithubIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 0 1 2-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

function GitlabIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="m23.6 9.59-.03-.08-3.27-8.53a.85.85 0 0 0-.34-.4.88.88 0 0 0-1 .06.88.88 0 0 0-.29.45L16.46 8H7.54L5.33 1.09a.86.86 0 0 0-.29-.45.88.88 0 0 0-1-.06.85.85 0 0 0-.34.4L.43 9.51l-.03.08a6.06 6.06 0 0 0 2.01 7l.01.01.03.02 4.97 3.72 2.46 1.86 1.5 1.13a1 1 0 0 0 1.21 0l1.5-1.13 2.46-1.86 5-3.74.02-.02a6.06 6.06 0 0 0 2.03-7Z" />
    </svg>
  );
}

function DocIcon() {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" />
      <path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z" />
    </svg>
  );
}
