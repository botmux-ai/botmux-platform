import { useEffect, useRef, useState } from 'react';
import { Select, Avatar, Typography, Button, Message, Link } from '@arco-design/web-react';
import { IconCopy } from '@arco-design/web-react/icon';
import type { UserHit } from '../api';
import { searchUsers, inviteUser, inviteLink, loginHref, searchScopeLoginHref } from '../api';
import { stashDraft, saveWithDraft, inviteScopeDraftKey } from '../draft';
import { copyText } from '../util';

const { Option } = Select;

function initial(name: string): string {
  return (name || '?').trim().charAt(0).toUpperCase() || '?';
}

interface Props {
  teamId: string;
  /** 授权回跳后恢复的搜索词：挂载即回填输入框并自动搜索。 */
  initialQuery?: string;
}

export default function InvitePanel({ teamId, initialQuery }: Props) {
  const [options, setOptions] = useState<UserHit[]>([]);
  const [fetching, setFetching] = useState(false);
  const [reauth, setReauth] = useState(false);
  const [needScope, setNeedScope] = useState(false);
  const [notConfigured, setNotConfigured] = useState(false);
  const [sending, setSending] = useState(false);
  const [link, setLink] = useState<string | null>(null);
  const [genning, setGenning] = useState(false);
  // 受控输入值：既让授权回跳能回填搜索词，也在跳授权前用它作为待暂存的 query。
  const [inputVal, setInputVal] = useState(initialQuery ?? '');
  const debTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reqSeq = useRef(0);

  // 授权回跳后自动恢复：回填搜索词并立即搜一次（needScope 已在新会话解除）。
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current || !initialQuery) return;
    restored.current = true;
    setInputVal(initialQuery);
    onSearch(initialQuery);
    // 仅挂载时恢复一次。
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialQuery]);

  // 跳搜人增量授权前，把当前搜索词按团队暂存；授权回来由 TeamCard 恢复弹窗+搜索词。
  function goAuthorizeSearch() {
    stashDraft(inviteScopeDraftKey(teamId), inputVal.trim());
    window.location.href = searchScopeLoginHref();
  }

  function onSearch(text: string) {
    if (debTimer.current) clearTimeout(debTimer.current);
    setInputVal(text); // 受控输入，供跳授权时暂存 / 回跳时回填
    const q = text.trim();
    if (!q) {
      setOptions([]);
      setFetching(false);
      return;
    }
    setFetching(true);
    setReauth(false);
    setNeedScope(false);
    setNotConfigured(false);
    debTimer.current = setTimeout(async () => {
      const seq = ++reqSeq.current;
      const j = await searchUsers(q);
      if (seq !== reqSeq.current) return; // 过期响应丢弃
      setFetching(false);
      if (j.configured === false) {
        setNotConfigured(true);
        setOptions([]);
        return;
      }
      if (j.needScope) {
        setNeedScope(true);
        setOptions([]);
        return;
      }
      if (j.reauth) {
        setReauth(true);
        setOptions([]);
        return;
      }
      setOptions(j.users || []);
    }, 300);
  }

  async function onSelect(openId: string) {
    // 带上 unionId/name：后端据此在成员列表记「待加入」（openId 是 app 作用域的，展示身份要 unionId）
    const hit = options.find((u) => u.openId === openId);
    setSending(true);
    try {
      // invite-user 是 strict 10min 操作，可能命中 stale_session 整页跳重登：先暂存搜索词，
      // 回来由 TeamCard 重开邀请弹窗并回填，不丢上下文（saveWithDraft 命中 stale 不 rethrow）。
      await saveWithDraft(inviteScopeDraftKey(teamId), inputVal.trim(), async () => {
        const r = await inviteUser(teamId, { openId, unionId: hit?.unionId, name: hit?.name });
        if (r.ok) Message.success('已发送邀请');
        else Message.error('发送失败：' + (r.detail || r.error || r.status));
      });
    } finally {
      setSending(false);
    }
  }

  async function genLink() {
    setGenning(true);
    try {
      // 生成邀请链接同为 strict 10min，命中 stale 时同样暂存上下文再跳重登。
      await saveWithDraft(inviteScopeDraftKey(teamId), inputVal.trim(), async () => {
        const j = await inviteLink(teamId);
        if (!j.inviteUrl) {
          Message.error('生成邀请链接失败');
          return;
        }
        setLink(j.inviteUrl);
      });
    } finally {
      setGenning(false);
    }
  }

  return (
    <div>
      <Typography.Text type="secondary">
        搜同事（姓名或邮箱前缀），选中后直接把邀请以飞书消息发给 TA：
      </Typography.Text>
      <Select
        showSearch
        allowClear
        style={{ width: '100%', marginTop: 8 }}
        placeholder="姓名 / 邮箱前缀"
        filterOption={false}
        loading={fetching || sending}
        inputValue={inputVal}
        onInputValueChange={(v, reason) => {
          // 只跟随用户输入更新受控值；optionListHide 等内部原因不清空（否则回跳回填会被抹掉）。
          if (reason === 'manual') setInputVal(v);
        }}
        notFoundContent={
          notConfigured ? (
            <Typography.Text type="secondary">搜索未配置（缺通讯录权限）</Typography.Text>
          ) : needScope ? (
            <Typography.Text type="secondary">
              搜同事需要一次性授权，请 <Link onClick={goAuthorizeSearch}>点此授权搜索</Link>（授完自动回到这里）。
            </Typography.Text>
          ) : reauth ? (
            <Typography.Text type="secondary">
              登录已过期，请 <Link href={loginHref()}>重新登录</Link> 一次。
            </Typography.Text>
          ) : undefined
        }
        onSearch={onSearch}
        onChange={(v) => v && onSelect(v as string)}
        value={undefined}
      >
        {options.map((u) => (
          <Option key={u.openId} value={u.openId}>
            <div className="user-option">
              <Avatar size={28}>
                {u.avatar ? <img alt={u.name} src={u.avatar} /> : initial(u.name)}
              </Avatar>
              <div className="uo-text">
                <span>{u.name}</span>
                {u.email && <span className="uo-email">{u.email}</span>}
              </div>
            </div>
          </Option>
        ))}
      </Select>

      {needScope && (
        <Button
          type="primary"
          long
          style={{ marginTop: 10 }}
          onClick={goAuthorizeSearch}
        >
          授权搜索同事（一次性，授完回到这里）
        </Button>
      )}

      {reauth && (
        <Button
          type="primary"
          status="warning"
          long
          style={{ marginTop: 10 }}
          onClick={() => {
            window.location.href = loginHref();
          }}
        >
          登录已过期，点此重新登录
        </Button>
      )}

      <div style={{ marginTop: 12 }}>
        <Typography.Text type="secondary" style={{ fontSize: 13 }}>
          或{' '}
        </Typography.Text>
        <Link onClick={genLink} disabled={genning}>
          生成邀请链接
        </Link>
      </div>

      {link && (
        <div style={{ marginTop: 8 }}>
          <Typography.Text type="secondary" style={{ fontSize: 13 }}>
            把链接发给同事，点开即自动加入（未登录会先登录再自动加入）。可多人多次使用，30 天有效：
          </Typography.Text>
          <code className="mono-block">{link}</code>
          <Button
            size="small"
            icon={<IconCopy />}
            onClick={async () => {
              (await copyText(link)) ? Message.success('已复制邀请链接') : Message.error('复制失败');
            }}
          >
            复制链接
          </Button>
        </div>
      )}
    </div>
  );
}
