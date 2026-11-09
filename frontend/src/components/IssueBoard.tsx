import { Fragment, useCallback, useEffect, useMemo, useState } from 'react';
import type { Dispatch, SetStateAction } from 'react';
import {
  Alert,
  Button,
  Card,
  Descriptions,
  Drawer,
  Empty,
  Input,
  Message,
  Modal,
  Popconfirm,
  Radio,
  Select,
  Space,
  Spin,
  Switch,
  Tag,
  Tooltip,
  Typography,
} from '@arco-design/web-react';
import {
  IconDelete,
  IconDown,
  IconLink,
  IconPlus,
  IconRefresh,
  IconSearch,
  IconSettings,
  IconUp,
} from '@arco-design/web-react/icon';
import type {
  Issue,
  IssueClaim,
  IssueEvent,
  IssueFormConfig,
  IssueFormField,
  IssueFormFieldType,
  IssueSections,
  IssueStatus,
  Team,
  TeamIssueSettings,
  TeamRepoPreset,
} from '../api';
import {
  ApiError,
  archiveIssue,
  createIssue,
  forceDetachIssue,
  getIssueEvents,
  getTeamIssueSettings,
  listIssues,
  patchIssue,
  putTeamIssueSettings,
} from '../api';
import { saveWithDraft, takeDraft } from '../draft';

/** 表单设置草稿键（按团队）。重登往返后据此恢复未保存的表单编辑。 */
function settingsDraftKey(teamId: string): string {
  return `issue-settings:${teamId}`;
}

// 平台问题板（DESIGN-issue-board.md §十）+ 团队预设仓库 / 可自定义创建表单。
// 2026-08 Apple UX 重设计（详见 index.css 「问题板」一节）：
// - 空间模型统一：详情 / 新建 / 表单设置全部从右缘滑入，看板是唯一的「家」。
// - 卡片减重：列已表达的状态不再重复为彩色 Tag，只保留有歧义的子状态 pill（重开 / 预约中 / 取消中）。
// - 新建问题 = iOS 分组表单 + 原地校验；服务端 {error,field} 落到对应字段下方。
// - 表单设置 = 编辑即预览：列表顺序即成员所见顺序，点按字段行内展开修改。
// - 「需关注」沿用品牌「在场感」呼吸点的红色变体 —— 那里可能仍有任务在运行。

interface Props {
  teams: Team[] | null;
  myUnionId: string;
}

const STATUS_LABEL: Record<IssueStatus, string> = {
  open: '待处理',
  reopened: '已重开',
  claimed: '已领取',
  in_progress: '处理中',
  in_review: '待验收',
  done: '已完成',
  cancelling: '取消中',
  needs_attention: '需关注',
};

const STATUS_COLOR: Record<IssueStatus, string> = {
  open: 'arcoblue',
  reopened: 'purple',
  claimed: 'cyan',
  in_progress: 'gold',
  in_review: 'orange',
  done: 'green',
  cancelling: 'gray',
  needs_attention: 'red',
};

const ATTENTION_REASON_LABEL: Record<string, string> = {
  cancel_delivery_timeout: '取消投递超时',
  claim_activate_timeout: '领取后未启动超时',
  task_blocked: '任务受阻待答复',
  run_timeout: '运行超时',
};

const EVENT_KIND_LABEL: Record<string, string> = {
  created: '创建',
  claimed: '领取',
  bound: '绑定本地任务',
  status: '状态变更',
  reopened: '重开',
  released: '释放',
  archived: '归档',
  lease_expired: '租约过期',
  force_detached: '强制脱离',
};

const FIELD_TYPE_LABEL: Record<IssueFormFieldType, string> = {
  text: '单行文本',
  textarea: '多行文本',
  select: '单选',
  multiselect: '多选',
  repo: '目标仓库',
};

const CREATE_ERROR_LABEL: Record<string, string> = {
  title_required: '请填写标题',
  body_required: '请填写问题描述',
  repo_required: '请选择或填写目标仓库',
  labels_required: '请填写标签',
  field_required: '请填写必填项',
  invalid_option: '选项不在允许范围内',
};

const BUILTIN_FIELD_IDS = ['title', 'body', 'repo', 'labels'];

type ColumnKey = 'todo' | 'inProgress' | 'inReview' | 'done';

const COLUMNS: { key: ColumnKey; title: string; pick: (s: IssueSections) => Issue[]; empty: string }[] = [
  { key: 'todo', title: '待处理', pick: (s) => s.todo, empty: '没有待处理的问题' },
  { key: 'inProgress', title: '处理中', pick: (s) => s.inProgress, empty: '还没有问题被领取' },
  { key: 'inReview', title: '待验收', pick: (s) => s.inReview, empty: '没有等待验收的问题' },
  { key: 'done', title: '已完成', pick: (s) => s.done, empty: '还没有完成的问题' },
];

function shortId(id: string): string {
  const bare = id.includes('_') ? id.slice(id.lastIndexOf('_') + 1) : id;
  return bare.slice(-6);
}

function formatRelative(ts: number | undefined, now = Date.now()): string {
  if (!ts) return '—';
  const delta = ts - now;
  const abs = Math.abs(delta);
  const sec = Math.floor(abs / 1000);
  // delta===0 算「刚刚」：>0 才是未来（预约租约等）
  if (sec < 60) return delta > 0 ? '即将' : '刚刚';
  const min = Math.floor(sec / 60);
  if (min < 60) return delta >= 0 ? `${min} 分钟后` : `${min} 分钟前`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return delta >= 0 ? `${hr} 小时后` : `${hr} 小时前`;
  const day = Math.floor(hr / 24);
  if (day < 30) return delta >= 0 ? `${day} 天后` : `${day} 天前`;
  return new Date(ts).toLocaleDateString();
}

function formatAbsolute(ts: number | undefined): string {
  if (!ts) return '—';
  return new Date(ts).toLocaleString();
}

function bodyPreview(body: string | undefined, max = 72): string | null {
  if (!body) return null;
  const line = body
    .replace(/\r\n/g, '\n')
    .split('\n')
    .map((l) => l.replace(/^#+\s*/, '').trim())
    .find((l) => l.length > 0);
  if (!line) return null;
  return line.length > max ? `${line.slice(0, max)}…` : line;
}

function genId(prefix: string): string {
  return `${prefix}_${Math.random().toString(16).slice(2, 10)}`;
}

/** 相对时间文本需要随时间流逝刷新：30s 一个 tick，只驱动「更新于 x 前」这类展示。 */
function useNow(intervalMs: number): number {
  const [now, setNow] = useState<number>(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(t);
  }, [intervalMs]);
  return now;
}

/** 列已经表达的状态不再重复；只有列内有歧义的子状态才浮出 pill。 */
function statusPill(issue: Issue, column: ColumnKey): { text: string; cls: 'purple' | 'cyan' | 'orange' } | null {
  if (column === 'todo' && issue.status === 'reopened') return { text: '已重开', cls: 'purple' };
  if (column === 'inProgress') {
    if (issue.status === 'claimed' && issue.claim && !issue.claim.bound) return { text: '预约中', cls: 'cyan' };
    if (issue.status === 'cancelling') return { text: '取消中', cls: 'orange' };
  }
  return null;
}

function matchesQuery(issue: Issue, q: string): boolean {
  const hay = [
    issue.title,
    issue.body,
    issue.targetRepoLabel ?? '',
    issue.createdByName,
    ...(issue.labels ?? []),
    issue.claim?.name ?? '',
    issue.claim?.agent ?? '',
  ]
    .join('\n')
    .toLowerCase();
  return q
    .split(/\s+/)
    .filter(Boolean)
    .every((tok) => hay.includes(tok));
}

/**
 * 「绑定」那一行的值：优先显示本地任务的可读名，能点就做成链接。
 *
 * 回落链条 label → localTaskRef → 「已绑定」：老数据没有 label（字段是后加的），不能因此
 * 显示成空白；而 localTaskRef 虽然是一串 ID，至少还能拿去对账。
 *
 * href 不在这里判 scheme —— 服务端 bind 时已经把非 https 的一律丢掉了（见
 * `sanitizeLocalTaskUrl`）。校验放在写入侧只跑一次，比每个渲染点各防一次可靠。
 */
function BoundTask({ claim }: { claim: IssueClaim }): JSX.Element {
  const text = claim.localTaskLabel || claim.localTaskRef;
  if (!text) return <>已绑定</>;
  if (!claim.localTaskUrl) {
    return (
      <Tooltip content={claim.localTaskRef ?? ''}>
        <span>{text}</span>
      </Tooltip>
    );
  }
  return (
    <Tooltip content={claim.localTaskRef ?? ''}>
      {/* rel=noopener 是必须的：target=_blank 打开的页面能通过 window.opener 反向操纵本页。 */}
      <a
        href={claim.localTaskUrl}
        target="_blank"
        rel="noopener noreferrer"
        style={{ color: 'var(--color-link-default, rgb(var(--primary-6)))' }}
      >
        <IconLink style={{ marginRight: 4 }} />
        {text}
      </a>
    </Tooltip>
  );
}

// ── 看板卡片 / 列 ────────────────────────────────────────────────────────────

function IssueCard({
  issue,
  column,
  onOpen,
}: {
  issue: Issue;
  column: ColumnKey;
  onOpen: (i: Issue) => void;
}): JSX.Element {
  const preview = bodyPreview(issue.body);
  const labelsAll = issue.labels ?? [];
  const labels = labelsAll.slice(0, 2);
  const extraLabels = labelsAll.length - labels.length;
  const pill = statusPill(issue, column);
  const meta: string[] = [issue.createdByName || '—'];
  if (issue.claim?.name) meta.push(`领取 ${issue.claim.name}${issue.claim.agent ? ` · ${issue.claim.agent}` : ''}`);
  meta.push(formatRelative(issue.updatedAt || issue.createdAt));
  const metaLine = meta.join(' · ');

  return (
    <Card hoverable size="small" className="issue-card" onClick={() => onOpen(issue)}>
      <div className="issue-card-head">
        <span className="issue-card-id" title={issue._id}>
          {shortId(issue._id)}
        </span>
        <div className="issue-card-title" style={{ marginBottom: 0 }}>
          {issue.title}
        </div>
      </div>
      {preview ? <div className="issue-card-preview">{preview}</div> : null}
      {pill || issue.targetRepoLabel || labels.length > 0 ? (
        <div className="issue-card-chips">
          {pill ? <span className={`issue-chip issue-pill-${pill.cls}`}>{pill.text}</span> : null}
          {issue.targetRepoLabel ? (
            <span className="issue-chip" title={issue.targetRepoLabel}>
              {issue.targetRepoLabel}
            </span>
          ) : null}
          {labels.map((l) => (
            <span key={l} className="issue-chip">
              {l}
            </span>
          ))}
          {extraLabels > 0 ? <span className="issue-chip issue-chip-muted">+{extraLabels}</span> : null}
        </div>
      ) : null}
      <div className="issue-card-meta" title={metaLine}>
        {metaLine}
      </div>
    </Card>
  );
}

function Column({
  title,
  issues,
  colKey,
  empty,
  onOpen,
}: {
  title: string;
  issues: Issue[];
  colKey: ColumnKey;
  empty: string;
  onOpen: (i: Issue) => void;
}): JSX.Element {
  return (
    <div className="issue-column">
      <div className="issue-column-title">
        <span>{title}</span>
        <span className="issue-count">{issues.length}</span>
      </div>
      {issues.length === 0 ? (
        <div className="issue-column-empty">{empty}</div>
      ) : (
        issues.map((i) => <IssueCard key={i._id} issue={i} column={colKey} onOpen={onOpen} />)
      )}
    </div>
  );
}

// ── 动态表单字段（新建问题 / 预览共用） ────────────────────────────────────────

function RepoControl({
  field,
  value,
  onChange,
  onSubmit,
  presets,
  required,
}: {
  field: IssueFormField;
  value: unknown;
  onChange: (v: unknown) => void;
  onSubmit?: () => void;
  presets: TeamRepoPreset[];
  required: boolean;
}): JSX.Element {
  const allowCustom = field.allowCustom !== false;
  const asObj =
    value && typeof value === 'object' && !Array.isArray(value) ? (value as { id?: string; label?: string }) : null;
  const presetIds = new Set(presets.map((p) => p.id));
  const selectedId =
    asObj?.id && presetIds.has(asObj.id)
      ? asObj.id
      : typeof value === 'string' && presetIds.has(value)
        ? value
        : '';
  const customLabel =
    asObj && !asObj.id
      ? (asObj.label ?? '')
      : typeof value === 'string' && value && !presetIds.has(value) && value !== '__none__'
        ? value
        : '';
  const customActive = allowCustom && !selectedId && (customLabel !== '' || (asObj !== null && !asObj.id));

  if (presets.length === 0 && !allowCustom) {
    return (
      <div className="issue-form-note">
        团队尚未配置预设仓库 — 请创建人在「表单设置」中添加，或开启「允许自定义仓库名」。
      </div>
    );
  }

  const customInput = (
    <Input
      className="issue-repo-custom"
      value={customLabel}
      placeholder="自定义仓库名，如 botmux-clients"
      onChange={(v) => onChange(v.trim() ? { label: v } : { label: '' })}
      onPressEnter={() => onSubmit?.()}
      aria-label={`${field.label}（自定义）`}
    />
  );

  // 预设少 → iOS 分段控件：一眼看全，一次点按选中
  if (presets.length > 0 && presets.length <= 4) {
    const options: { label: string; value: string }[] = presets.map((p) => ({ label: p.label, value: p.id }));
    if (allowCustom) options.push({ label: '自定义…', value: '__custom__' });
    if (!required) options.push({ label: '不指定', value: '__none__' });
    const radioValue = selectedId || (customActive ? '__custom__' : value === '__none__' ? '__none__' : undefined);
    return (
      <div>
        <Radio.Group
          className="issue-repo-seg"
          type="button"
          options={options}
          value={radioValue}
          onChange={(v: string) => {
            if (v === '__none__') {
              onChange('__none__');
              return;
            }
            if (v === '__custom__') {
              onChange({ label: customLabel });
              return;
            }
            const p = presets.find((x) => x.id === v);
            if (p) onChange({ id: p.id, label: p.label });
          }}
        />
        {allowCustom && customActive ? customInput : null}
      </div>
    );
  }

  // 预设多 → 下拉
  if (presets.length > 0) {
    return (
      <div>
        <Select
          value={selectedId || (customActive ? '__custom__' : undefined)}
          placeholder="选择目标仓库"
          style={{ width: '100%' }}
          allowClear
          aria-label={field.label}
          onChange={(v) => {
            if (!v) {
              onChange('');
              return;
            }
            if (v === '__custom__') {
              onChange({ label: customLabel });
              return;
            }
            const p = presets.find((x) => x.id === v);
            if (p) onChange({ id: p.id, label: p.label });
          }}
        >
          {presets.map((p) => (
            <Select.Option key={p.id} value={p.id}>
              {p.label}
              {p.remote ? `（${p.remote}）` : ''}
            </Select.Option>
          ))}
          {allowCustom ? <Select.Option value="__custom__">自定义仓库名…</Select.Option> : null}
        </Select>
        {allowCustom && customActive ? customInput : null}
      </div>
    );
  }

  // 无预设 + 允许自定义 → 直接一个输入框
  return customInput;
}

function IssueFieldControl({
  field,
  value,
  error,
  onChange,
  onSubmit,
  presets,
  autoFocus,
}: {
  field: IssueFormField;
  value: unknown;
  error?: string;
  onChange: (v: unknown) => void;
  onSubmit?: () => void;
  presets: TeamRepoPreset[];
  autoFocus?: boolean;
}): JSX.Element {
  const required = !!field.required || field.id === 'title';

  let control: JSX.Element;
  if (field.type === 'textarea' || field.id === 'body') {
    control = (
      <Input.TextArea
        value={String(value ?? '')}
        onChange={(v) => onChange(v)}
        placeholder={field.placeholder}
        autoSize={{ minRows: field.id === 'body' ? 4 : 3, maxRows: 12 }}
        aria-label={field.label}
      />
    );
  } else if (field.type === 'repo' || field.id === 'repo') {
    control = (
      <RepoControl
        field={field}
        value={value}
        onChange={onChange}
        onSubmit={onSubmit}
        presets={presets}
        required={required}
      />
    );
  } else if (field.type === 'select') {
    control = (
      <Select
        value={(value as string) || undefined}
        placeholder={field.placeholder || '请选择'}
        style={{ width: '100%' }}
        allowClear
        aria-label={field.label}
        onChange={(v) => onChange(v ?? '')}
      >
        {(field.options ?? []).map((o) => (
          <Select.Option key={o} value={o}>
            {o}
          </Select.Option>
        ))}
      </Select>
    );
  } else if (field.type === 'multiselect') {
    control = (
      <Select
        mode="multiple"
        value={Array.isArray(value) ? (value as string[]) : []}
        placeholder={field.placeholder || '请选择'}
        style={{ width: '100%' }}
        aria-label={field.label}
        onChange={(v) => onChange(v)}
      >
        {(field.options ?? []).map((o) => (
          <Select.Option key={o} value={o}>
            {o}
          </Select.Option>
        ))}
      </Select>
    );
  } else {
    control = (
      <Input
        value={String(value ?? '')}
        onChange={(v) => onChange(v)}
        placeholder={field.placeholder}
        maxLength={field.id === 'title' ? 200 : undefined}
        showWordLimit={field.id === 'title'}
        onPressEnter={() => onSubmit?.()}
        autoFocus={autoFocus}
        aria-label={field.label}
      />
    );
  }

  return (
    <div className={`issue-field${error ? ' has-error' : ''}`} data-field={field.id}>
      <div className="issue-field-label">
        <span>{field.label}</span>
        {!required ? <span className="issue-field-optional">可选</span> : null}
      </div>
      {control}
      {error ? (
        <div className="issue-field-error" role="alert">
          {error}
        </div>
      ) : null}
    </div>
  );
}

function IssueFormRenderer({
  fields,
  presets,
  values,
  errors,
  onChange,
  onSubmit,
  autoFocusFirst,
}: {
  fields: IssueFormField[];
  presets: TeamRepoPreset[];
  values: Record<string, unknown>;
  errors: Record<string, string | undefined>;
  onChange: (id: string, v: unknown) => void;
  onSubmit?: () => void;
  autoFocusFirst?: boolean;
}): JSX.Element {
  // 严格按 fields 顺序渲染——设置页承诺「按这里的顺序展示」，拆组会破坏它；
  // 只在第一个自定义字段前插入「其他信息」分隔。
  const firstCustomIdx = fields.findIndex((f) => !BUILTIN_FIELD_IDS.includes(f.id));
  return (
    <div className="issue-form-group">
      {fields.map((f, i) => (
        <Fragment key={f.id}>
          {i === firstCustomIdx ? <div className="issue-form-group-title">其他信息</div> : null}
          <IssueFieldControl
            field={f}
            value={values[f.id]}
            error={errors[f.id]}
            presets={presets}
            autoFocus={!!autoFocusFirst && i === 0}
            onSubmit={onSubmit}
            onChange={(v) => onChange(f.id, v)}
          />
        </Fragment>
      ))}
    </div>
  );
}

function initFormValues(fields: IssueFormField[], presets: TeamRepoPreset[]): Record<string, unknown> {
  const init: Record<string, unknown> = {};
  for (const f of fields) {
    if ((f.type === 'repo' || f.id === 'repo') && presets.length === 1) {
      // 只有一个预设仓库时直接预选——这是最常见的默认答案
      init[f.id] = { id: presets[0].id, label: presets[0].label };
    } else if (f.type === 'multiselect') {
      init[f.id] = [];
    } else {
      init[f.id] = '';
    }
  }
  return init;
}

/** 本地镜像服务端必填校验：能当场指出的错误不走一次往返。 */
function validateFormValues(
  fields: IssueFormField[],
  presets: TeamRepoPreset[],
  values: Record<string, unknown>,
): Record<string, string> {
  const errors: Record<string, string> = {};
  const presetIds = new Set(presets.map((p) => p.id));
  for (const f of fields) {
    const required = !!f.required || f.id === 'title';
    const v = values[f.id];
    if (f.type === 'repo' || f.id === 'repo') {
      const asObj = v && typeof v === 'object' && !Array.isArray(v) ? (v as { id?: string; label?: string }) : null;
      const has =
        (asObj?.id && presetIds.has(asObj.id)) ||
        (asObj && !asObj.id && (asObj.label ?? '').trim()) ||
        (typeof v === 'string' && v !== '__none__' && (presetIds.has(v) || v.trim()));
      if (required && !has) errors[f.id] = `请选择或填写「${f.label}」`;
      continue;
    }
    if (f.type === 'select' || f.type === 'multiselect') {
      if (required && (!Array.isArray(v) ? !v : (v as unknown[]).length === 0)) {
        errors[f.id] = `请选择「${f.label}」`;
      }
      continue;
    }
    if (required && !String(v ?? '').trim()) errors[f.id] = `请填写「${f.label}」`;
  }
  return errors;
}

// ── 表单设置：编辑即预览 ──────────────────────────────────────────────────────

function OptionsEditor({
  options,
  onChange,
}: {
  options: string[];
  onChange: (next: string[]) => void;
}): JSX.Element {
  const [draft, setDraft] = useState('');
  const full = options.length >= 30;

  function add(): void {
    const v = draft.trim().slice(0, 64);
    setDraft('');
    if (!v || options.includes(v) || full) return;
    onChange([...options, v]);
  }

  return (
    <div className="issue-opts">
      {options.length > 0 ? (
        <Space size={4} wrap>
          {options.map((o) => (
            <Tag key={o} size="small" closable onClose={() => onChange(options.filter((x) => x !== o))}>
              {o}
            </Tag>
          ))}
        </Space>
      ) : null}
      <Input
        className="issue-opts-add"
        value={draft}
        placeholder={full ? '最多 30 个选项' : options.length ? '继续添加…' : '输入选项，回车添加'}
        disabled={full}
        onChange={setDraft}
        onPressEnter={add}
        onBlur={add}
      />
    </div>
  );
}

function allowedTypesFor(field: IssueFormField): IssueFormFieldType[] | null {
  if (field.id === 'title' || field.id === 'repo') return null;
  if (field.id === 'body') return ['textarea', 'text'];
  if (field.id === 'labels') return ['text', 'multiselect'];
  return ['text', 'textarea', 'select', 'multiselect'];
}

function SettingFieldRow({
  field,
  expanded,
  error,
  canMoveUp,
  canMoveDown,
  onToggle,
  onPatch,
  onMove,
  onRemove,
}: {
  field: IssueFormField;
  expanded: boolean;
  error?: string;
  canMoveUp: boolean;
  canMoveDown: boolean;
  onToggle: () => void;
  onPatch: (patch: Partial<IssueFormField>) => void;
  onMove: (delta: number) => void;
  onRemove: (() => void) | null;
}): JSX.Element {
  const isBuiltin = BUILTIN_FIELD_IDS.includes(field.id);
  const isTitle = field.id === 'title';
  const required = isTitle || !!field.required;
  const types = allowedTypesFor(field);
  const needsOptions = field.type === 'select' || field.type === 'multiselect';

  const metaParts: string[] = [];
  if (isBuiltin) metaParts.push('系统');
  metaParts.push(field.id === 'repo' ? FIELD_TYPE_LABEL.repo : FIELD_TYPE_LABEL[field.type]);
  metaParts.push(required ? '必填' : '可选');
  if (field.id === 'repo' && field.allowCustom === false) metaParts.push('仅预设');
  if (needsOptions) metaParts.push(`${(field.options ?? []).length} 个选项`);

  return (
    <div className={`issue-setting-field${error ? ' has-error' : ''}`}>
      <div
        className="issue-setting-field-head"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={onToggle}
        onKeyDown={(e) => {
          // 只响应行头自身的按键——上移/下移按钮的 Enter/Space 会冒泡上来，不能吞
          if (e.target !== e.currentTarget) return;
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            onToggle();
          }
        }}
      >
        <div className="issue-setting-field-heading">
          <span className="issue-setting-field-name">{field.label || field.id}</span>
          <span className="issue-setting-field-meta">{metaParts.join(' · ')}</span>
        </div>
        <div className="issue-setting-field-actions">
          {!isTitle ? (
            <>
              <Button
                type="text"
                size="mini"
                icon={<IconUp />}
                disabled={!canMoveUp}
                aria-label={`上移「${field.label}」`}
                onClick={(e) => {
                  e.stopPropagation();
                  onMove(-1);
                }}
              />
              <Button
                type="text"
                size="mini"
                icon={<IconDown />}
                disabled={!canMoveDown}
                aria-label={`下移「${field.label}」`}
                onClick={(e) => {
                  e.stopPropagation();
                  onMove(1);
                }}
              />
            </>
          ) : null}
          <IconDown className={`issue-setting-chevron${expanded ? ' open' : ''}`} />
        </div>
      </div>

      {expanded ? (
        <div className="issue-setting-field-body">
          <div className="issue-setting-row">
            <span className="issue-setting-caption">显示名</span>
            <Input value={field.label} placeholder="成员看到的字段名" onChange={(v) => onPatch({ label: v })} />
          </div>
          <div className="issue-setting-row">
            <span className="issue-setting-caption">占位提示</span>
            <Input
              value={field.placeholder ?? ''}
              placeholder="输入框为空时展示的提示（可留空）"
              onChange={(v) => onPatch({ placeholder: v || undefined })}
            />
          </div>
          {types ? (
            <div className="issue-setting-row-horizontal">
              <span className="issue-setting-caption">类型</span>
              <Select
                style={{ width: 150 }}
                value={field.type}
                onChange={(v) => {
                  const next = v as IssueFormFieldType;
                  onPatch({
                    type: next,
                    ...(next !== 'select' && next !== 'multiselect' ? { options: undefined } : {}),
                  });
                }}
              >
                {types.map((t) => (
                  <Select.Option key={t} value={t}>
                    {FIELD_TYPE_LABEL[t]}
                  </Select.Option>
                ))}
              </Select>
            </div>
          ) : null}
          {needsOptions ? (
            <div className="issue-setting-row">
              <span className="issue-setting-caption">选项</span>
              <OptionsEditor options={field.options ?? []} onChange={(options) => onPatch({ options })} />
            </div>
          ) : null}
          <div className="issue-setting-row-horizontal">
            <span className="issue-setting-caption">必填 — 成员创建时必须填写</span>
            <Switch size="small" checked={required} disabled={isTitle} onChange={(v) => onPatch({ required: v })} />
          </div>
          {field.id === 'repo' ? (
            <div className="issue-setting-row-horizontal">
              <span className="issue-setting-caption">允许自定义仓库名</span>
              <Switch
                size="small"
                checked={field.allowCustom !== false}
                onChange={(v) => onPatch({ allowCustom: v })}
              />
            </div>
          ) : null}
          {isTitle ? (
            <div className="issue-setting-caption">标题是系统字段，始终在最前且必填。</div>
          ) : null}
          {error ? <div className="issue-setting-error">{error}</div> : null}
          {onRemove ? (
            <div className="issue-setting-field-foot">
              <Button type="text" size="mini" status="danger" onClick={onRemove}>
                删除字段
              </Button>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

function IssueSettingsEditor({
  settings,
  onSave,
  onCancel,
  onDirtyChange,
  onPreview,
  draftKey,
  initialDraft,
}: {
  settings: TeamIssueSettings;
  onSave: (next: { repoPresets: TeamRepoPreset[]; issueForm: IssueFormConfig }) => Promise<void>;
  onCancel: () => void;
  onDirtyChange: (dirty: boolean) => void;
  onPreview: () => void;
  /** 敏感保存前暂存草稿的键（按团队）；重登往返后据此恢复。 */
  draftKey: string;
  /** 重登回来待恢复的草稿：优先于 settings 作为初值。 */
  initialDraft?: { repoPresets: TeamRepoPreset[]; issueForm: IssueFormConfig };
}): JSX.Element {
  const [presets, setPresets] = useState<TeamRepoPreset[]>(() =>
    (initialDraft ? initialDraft.repoPresets : settings.repoPresets).map((p) => ({ ...p })),
  );
  const [fields, setFields] = useState<IssueFormField[]>(() =>
    (initialDraft ? initialDraft.issueForm.fields : settings.issueForm.fields).map((f) => ({
      ...f,
      options: f.options ? [...f.options] : undefined,
    })),
  );
  const [saving, setSaving] = useState(false);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  // 草稿恢复的编辑也是「未保存的改动」——直接关闭要弹确认（takeDraft 一次性，丢了找不回）
  const [dirty, setDirty] = useState(() => !!initialDraft);

  useEffect(() => {
    onDirtyChange(dirty);
  }, [dirty, onDirtyChange]);

  function mutate<T>(setter: Dispatch<SetStateAction<T>>, fn: (prev: T) => T): void {
    setter(fn);
    setDirty(true);
  }

  const fieldErrors = useMemo(() => {
    const errs = new Map<string, string>();
    for (const f of fields) {
      if (!f.label.trim()) errs.set(f.id, '请填写显示名');
      else if ((f.type === 'select' || f.type === 'multiselect') && !(f.options ?? []).length) {
        errs.set(f.id, '至少需要 1 个选项');
      }
    }
    return errs;
  }, [fields]);

  const updateField = (idx: number, patch: Partial<IssueFormField>): void =>
    mutate(setFields, (prev) => prev.map((f, i) => (i === idx ? { ...f, ...patch } : f)));

  const moveField = (idx: number, delta: number): void =>
    mutate(setFields, (prev) => {
      const j = idx + delta;
      if (j < 0 || j >= prev.length) return prev;
      const next = [...prev];
      [next[idx], next[j]] = [next[j], next[idx]];
      return next;
    });

  const removeField = (idx: number): void =>
    mutate(setFields, (prev) => {
      const removed = prev[idx];
      if (removed && expandedId === removed.id) setExpandedId(null);
      return prev.filter((_, i) => i !== idx);
    });

  const addCustomField = (): void => {
    if (fields.length >= 20) {
      Message.warning('最多 20 个字段');
      return;
    }
    const field: IssueFormField = { id: genId('f'), type: 'text', label: '新字段', required: false };
    mutate(setFields, (prev) => [...prev, field]);
    setExpandedId(field.id);
  };

  const restoreField = (f: IssueFormField): void => mutate(setFields, (prev) => [...prev, f]);

  const updatePreset = (idx: number, patch: Partial<TeamRepoPreset>): void =>
    mutate(setPresets, (prev) => prev.map((p, i) => (i === idx ? { ...p, ...patch } : p)));

  const removePreset = (idx: number): void => mutate(setPresets, (prev) => prev.filter((_, i) => i !== idx));

  const addPreset = (): void => {
    if (presets.length >= 50) {
      Message.warning('最多 50 个预设仓库');
      return;
    }
    mutate(setPresets, (prev) => [...prev, { id: genId('repo'), label: '' }]);
  };

  async function save(): Promise<void> {
    const firstErr = fields.find((f) => fieldErrors.has(f.id));
    if (firstErr) {
      setExpandedId(firstErr.id);
      Message.error('还有字段没有填写完整');
      return;
    }
    setSaving(true);
    try {
      // 展示名为空的预设行在保存时被忽略（服务端 normalize 同样会丢弃）
      const next = { repoPresets: presets.filter((p) => p.label.trim()), issueForm: { fields } };
      // 保存前暂存草稿：若命中新鲜登录过期而整页跳飞书重登，回来后可恢复表单，不丢已填内容。
      await saveWithDraft(draftKey, next, () => onSave(next));
      setDirty(false);
    } finally {
      setSaving(false);
    }
  }

  const missing = (id: string): boolean => !fields.some((f) => f.id === id);

  return (
    <div>
      <div className="issue-settings-note">
        这是成员创建问题时看到的表单，按这里的顺序展示。点按字段即可展开修改，保存后立即生效。
        <Button type="text" size="small" className="issue-settings-preview-link" onClick={onPreview}>
          预览表单
        </Button>
      </div>

      <div className="issue-settings-group">
        <span className="issue-settings-group-title">表单字段</span>
      </div>
      {fields.map((f, i) => (
        <SettingFieldRow
          key={f.id}
          field={f}
          expanded={expandedId === f.id}
          error={fieldErrors.get(f.id)}
          canMoveUp={f.id !== 'title' && i > 0 && fields[i - 1].id !== 'title'}
          canMoveDown={f.id !== 'title' && i < fields.length - 1}
          onToggle={() => setExpandedId((cur) => (cur === f.id ? null : f.id))}
          onPatch={(patch) => updateField(i, patch)}
          onMove={(delta) => moveField(i, delta)}
          onRemove={f.id === 'title' ? null : () => removeField(i)}
        />
      ))}
      <div className="issue-settings-actions">
        <Button size="small" type="dashed" icon={<IconPlus />} onClick={addCustomField}>
          添加字段
        </Button>
        {missing('body') ? (
          <Button
            size="small"
            type="dashed"
            onClick={() =>
              restoreField({
                id: 'body',
                type: 'textarea',
                label: '问题描述',
                required: true,
                placeholder: '现象、复现步骤、期望结果…',
              })
            }
          >
            恢复「问题描述」
          </Button>
        ) : null}
        {missing('repo') ? (
          <Button
            size="small"
            type="dashed"
            onClick={() =>
              restoreField({ id: 'repo', type: 'repo', label: '目标仓库', required: true, allowCustom: true })
            }
          >
            恢复「目标仓库」
          </Button>
        ) : null}
        {missing('labels') ? (
          <Button
            size="small"
            type="dashed"
            onClick={() =>
              restoreField({ id: 'labels', type: 'text', label: '标签', required: false, placeholder: '逗号分隔' })
            }
          >
            恢复「标签」
          </Button>
        ) : null}
      </div>

      <div className="issue-settings-group" style={{ marginTop: 20 }}>
        <span className="issue-settings-group-title">预设仓库</span>
      </div>
      <div className="issue-settings-group-cap">
        成员创建问题时从列表选择目标仓库。展示名为空的行在保存时会被忽略。
      </div>
      {presets.map((p, i) => (
        <div className="issue-setting-field issue-preset-row" key={p.id}>
          <Input
            style={{ flex: 1 }}
            value={p.label}
            placeholder="展示名，如 botmux-clients"
            aria-label="预设仓库展示名"
            onChange={(v) => updatePreset(i, { label: v })}
          />
          <Input
            style={{ flex: 1 }}
            value={p.remote ?? ''}
            placeholder="remote 可选，如 org/repo"
            aria-label="预设仓库 remote"
            onChange={(v) => updatePreset(i, { remote: v || undefined })}
          />
          <Button
            type="text"
            size="mini"
            status="danger"
            icon={<IconDelete />}
            aria-label={`删除仓库「${p.label || '未命名'}」`}
            onClick={() => removePreset(i)}
          />
        </div>
      ))}
      <div className="issue-settings-actions">
        <Button size="small" type="dashed" icon={<IconPlus />} onClick={addPreset}>
          添加仓库
        </Button>
      </div>

      <div className="issue-settings-footer">
        <Button onClick={onCancel}>取消</Button>
        <Button type="primary" loading={saving} onClick={() => void save()}>
          保存更改
        </Button>
      </div>
    </div>
  );
}

// ── 主页面 ──────────────────────────────────────────────────────────────────

export default function IssueBoard({ teams, myUnionId }: Props): JSX.Element {
  const teamList = teams ?? [];
  const [teamId, setTeamId] = useState<string>('');
  const [sections, setSections] = useState<IssueSections | null>(null);
  const [settings, setSettings] = useState<TeamIssueSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastLoadedAt, setLastLoadedAt] = useState<number | null>(null);
  const [query, setQuery] = useState('');
  const [createOpen, setCreateOpen] = useState(false);
  const [createPreview, setCreatePreview] = useState(false);
  const [formValues, setFormValues] = useState<Record<string, unknown>>({});
  const [formErrors, setFormErrors] = useState<Record<string, string | undefined>>({});
  const [settingsOpen, setSettingsOpen] = useState(false);
  // 重登往返后待恢复的表单设置草稿（按团队暂存）。非 null 时自动重开设置抽屉并注入初值。
  const [settingsDraft, setSettingsDraft] = useState<{
    repoPresets: TeamRepoPreset[];
    issueForm: IssueFormConfig;
  } | null>(null);
  const [settingsDirty, setSettingsDirty] = useState(false);
  const [detail, setDetail] = useState<Issue | null>(null);
  const [events, setEvents] = useState<IssueEvent[]>([]);
  const [editing, setEditing] = useState(false);
  /** 进入编辑时冻结的 rev；保存用它 CAS，避免刷新把 detail.rev 推到最新后静默覆盖他人改动 */
  const [editRev, setEditRev] = useState<number | null>(null);
  const [editTitle, setEditTitle] = useState('');
  const [editBody, setEditBody] = useState('');
  const [editLabels, setEditLabels] = useState('');
  const [editRepoLabel, setEditRepoLabel] = useState('');
  const [editRepoId, setEditRepoId] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [creating, setCreating] = useState(false);
  const now = useNow(30_000);

  useEffect(() => {
    if (!teamId && teamList.length > 0) setTeamId(teamList[0].teamId);
  }, [teamList, teamId]);

  // 重登往返后恢复表单设置草稿：切到有暂存草稿的团队时，取出草稿并自动重开设置抽屉。
  // takeDraft 一次性读取(读完即删)，只在切换到该团队的首个 render 触发一次。
  useEffect(() => {
    if (!teamId) return;
    const d = takeDraft<{ repoPresets: TeamRepoPreset[]; issueForm: IssueFormConfig }>(
      settingsDraftKey(teamId),
    );
    if (d) {
      setSettingsDraft(d);
      setSettingsOpen(true);
    }
  }, [teamId]);

  const loadSettings = useCallback(async (tid: string) => {
    try {
      setSettings(await getTeamIssueSettings(tid));
    } catch {
      setSettings(null);
    }
  }, []);

  const refresh = useCallback(async () => {
    if (!teamId) return;
    setLoading(true);
    setError(null);
    try {
      const [s] = await Promise.all([listIssues(teamId), loadSettings(teamId)]);
      setSections(s);
      setLastLoadedAt(Date.now());
    } catch (e) {
      setError(e instanceof Error ? e.message : 'error');
      setSections(null);
    } finally {
      setLoading(false);
    }
  }, [teamId, loadSettings]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const openDetail = useCallback(async (issue: Issue) => {
    setDetail(issue);
    setEditing(false);
    setEditRev(null);
    setEditTitle(issue.title);
    setEditBody(issue.body || '');
    setEditLabels((issue.labels ?? []).join(', '));
    setEditRepoLabel(issue.targetRepoLabel || '');
    setEditRepoId(issue.targetRepoId ?? null);
    const url = new URL(location.href);
    url.searchParams.set('issue', issue._id);
    history.replaceState(null, '', url.toString());
    setEvents(await getIssueEvents(issue._id));
  }, []);

  const closeDetail = useCallback(() => {
    setDetail(null);
    setEditing(false);
    setEditRev(null);
    const url = new URL(location.href);
    url.searchParams.delete('issue');
    history.replaceState(null, '', url.toString());
  }, []);

  const allIssues = useMemo(() => {
    if (!sections) return [];
    return [
      ...sections.needsAttention,
      ...sections.todo,
      ...sections.inProgress,
      ...sections.inReview,
      ...sections.done,
    ];
  }, [sections]);

  useEffect(() => {
    const want = new URL(location.href).searchParams.get('issue');
    if (want && !detail) {
      const found = allIssues.find((i) => i._id === want);
      if (found) void openDetail(found);
    }
  }, [allIssues, detail, openDetail]);

  useEffect(() => {
    if (!detail) return;
    const fresh = allIssues.find((i) => i._id === detail._id);
    if (
      fresh &&
      (fresh.stateRev !== detail.stateRev || fresh.rev !== detail.rev || fresh.status !== detail.status)
    ) {
      if (editing) {
        // 编辑中只同步 status/claim 等展示字段，绝不推进 detail.rev（保存用 editRev 快照）
        setDetail((cur) =>
          cur && cur._id === fresh._id
            ? {
                ...cur,
                status: fresh.status,
                claim: fresh.claim,
                stateRev: fresh.stateRev,
                attentionReason: fresh.attentionReason,
                attentionSince: fresh.attentionSince,
              }
            : cur,
        );
        return;
      }
      setDetail(fresh);
      setEditTitle(fresh.title);
      setEditBody(fresh.body || '');
      setEditLabels((fresh.labels ?? []).join(', '));
      setEditRepoLabel(fresh.targetRepoLabel || '');
      setEditRepoId(fresh.targetRepoId ?? null);
    }
  }, [allIssues, detail, editing]);

  const formFields = settings?.issueForm.fields ?? [];
  const presets = settings?.repoPresets ?? [];

  function openCreate(preview: boolean): void {
    setFormValues(initFormValues(formFields, presets));
    setFormErrors({});
    setCreatePreview(preview);
    setCreateOpen(true);
  }

  function closeCreate(): void {
    if (creating) return;
    setCreateOpen(false);
    setCreatePreview(false);
  }

  const requestCloseSettings = useCallback(() => {
    if (!settingsDirty) {
      setSettingsOpen(false);
      return;
    }
    Modal.confirm({
      title: '放弃更改？',
      content: '已修改的内容不会保存。',
      okText: '放弃更改',
      cancelText: '继续编辑',
      onOk: () => {
        setSettingsDirty(false);
        setSettingsOpen(false);
      },
    });
  }, [settingsDirty]);

  /** 服务端 {error, field} 落到对应字段下方；定位到第一个出错的字段。 */
  function revealFormErrors(errors: Record<string, string>): void {
    setFormErrors(errors);
    const first = formFields.find((f) => errors[f.id]);
    if (!first) return;
    document
      .getElementById(createPreview ? 'issue-form-preview' : 'issue-form-create')
      ?.querySelector(`[data-field="${first.id}"]`)
      ?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function createErrorMessage(r: { error?: string; field?: string }): string {
    const fieldLabel = (r.field && formFields.find((f) => f.id === r.field)?.label) || r.field || '';
    if (r.error === 'field_required' || r.error === 'invalid_option') {
      if (fieldLabel) {
        return r.error === 'field_required' ? `请填写「${fieldLabel}」` : `「${fieldLabel}」选项无效`;
      }
    }
    if (r.error && CREATE_ERROR_LABEL[r.error]) return CREATE_ERROR_LABEL[r.error];
    if (fieldLabel && r.error) return `「${fieldLabel}」：${r.error}`;
    return `创建失败：${r.error ?? 'error'}`;
  }

  async function submitCreate(): Promise<void> {
    if (!teamId || creating) return;
    const local = validateFormValues(formFields, presets, formValues);
    if (Object.keys(local).length > 0) {
      revealFormErrors(local);
      return;
    }
    // 提交前清掉 repo 分段控件里的「不指定」哨兵值
    const values = { ...formValues };
    for (const f of formFields) {
      if ((f.type === 'repo' || f.id === 'repo') && values[f.id] === '__none__') delete values[f.id];
    }
    setCreating(true);
    try {
      const r = await createIssue(teamId, values);
      if (r.ok) {
        Message.success('问题已创建');
        setCreateOpen(false);
        setFormValues({});
        setFormErrors({});
        void refresh();
      } else if (r.field && formFields.some((f) => f.id === r.field)) {
        revealFormErrors({ [r.field]: createErrorMessage(r) });
      } else {
        // field 指向当前表单之外的字段（表单被管理员并行改过）——原地无处可指，走全局提示
        Message.error(createErrorMessage(r));
      }
    } finally {
      setCreating(false);
    }
  }

  function beginEdit(): void {
    if (!detail) return;
    setEditRev(detail.rev);
    setEditTitle(detail.title);
    setEditBody(detail.body || '');
    setEditLabels((detail.labels ?? []).join(', '));
    setEditRepoLabel(detail.targetRepoLabel || '');
    setEditRepoId(detail.targetRepoId ?? null);
    setEditing(true);
  }

  async function submitEdit(): Promise<void> {
    if (!detail || editRev == null) return;
    setSaving(true);
    try {
      const labels = editLabels
        .split(/[,，]/)
        .map((s) => s.trim())
        .filter(Boolean);
      const label = editRepoLabel.trim();
      // 文本改名后不再沿用旧预设 id（避免 id/label 自相矛盾）
      const sameAsOriginal = label === (detail.targetRepoLabel || '');
      const targetRepoId = label ? (sameAsOriginal ? editRepoId : null) : null;
      const r = await patchIssue(detail._id, editRev, {
        title: editTitle.trim(),
        body: editBody,
        labels,
        targetRepoLabel: label || null,
        targetRepoId,
      });
      if (r.ok && r.issue) {
        Message.success('已保存');
        setDetail(r.issue);
        setEditing(false);
        setEditRev(null);
        void refresh();
      } else if (r.status === 409) {
        Message.warning('内容已被他人修改，请刷新后重试');
        void refresh();
      } else {
        Message.error(`保存失败：${r.error ?? r.status}`);
      }
    } finally {
      setSaving(false);
    }
  }

  async function doForceDetach(issue: Issue): Promise<void> {
    try {
      const r = await forceDetachIssue(issue._id, issue.stateRev);
      if (r.ok) {
        Message.success('已强制脱离 — 问题已重新打开');
        void refresh();
        if (detail?._id === issue._id) closeDetail();
      } else if (r.status === 401) {
        Message.warning('高敏操作需重新登录');
      } else {
        Message.error(`操作失败：${r.error ?? r.status}`);
      }
    } catch (e) {
      // stale_session 时请求层已跳转重登
      if (!(e instanceof ApiError && e.code === 'stale_session')) Message.error('网络异常，请稍后重试');
    }
  }

  async function doArchive(issue: Issue): Promise<void> {
    try {
      const r = await archiveIssue(issue._id);
      if (r.ok) {
        Message.success('已归档');
        void refresh();
        closeDetail();
      } else {
        Message.error(`操作失败：${r.error ?? r.status}`);
      }
    } catch (e) {
      if (!(e instanceof ApiError && e.code === 'stale_session')) Message.error('网络异常，请稍后重试');
    }
  }

  async function copyDetailLink(): Promise<void> {
    if (!detail) return;
    const url = new URL(location.href);
    url.searchParams.set('issue', detail._id);
    try {
      await navigator.clipboard.writeText(url.toString());
      Message.success('已复制链接');
    } catch {
      Message.error('复制失败 — 请手动复制地址栏链接');
    }
  }

  const canManage = (issue: Issue): boolean => {
    if (issue.createdBy === myUnionId) return true;
    const t = teamList.find((x) => x.teamId === teamId);
    if (!t) return false;
    if (t.createdBy === myUnionId) return true;
    return Array.isArray(t.admins) && t.admins.includes(myUnionId);
  };

  const canEditBody = (issue: Issue): boolean => issue.status === 'open' || issue.status === 'reopened';

  if (teamList.length === 0) {
    return (
      <Card>
        <Empty description="先在「团队」页创建或加入一个团队，即可使用问题板。" />
      </Card>
    );
  }

  const q = query.trim().toLowerCase();
  const filterCol = (list: Issue[] | undefined): Issue[] => (q ? (list ?? []).filter((i) => matchesQuery(i, q)) : (list ?? []));
  // 筛选同样作用于「需关注」条——否则列区显示「没有匹配」时上方却列着匹配项，自相矛盾
  const na = filterCol(sections?.needsAttention);
  const filteredAllEmpty =
    sections !== null &&
    q !== '' &&
    na.length === 0 &&
    COLUMNS.every((c) => filterCol(c.pick(sections)).length === 0);

  function loadErrorText(err: string): string {
    if (err === 'store_unavailable') return '存储暂时不可用 — 请稍后刷新重试';
    if (err === 'not_found') return '这个团队不存在，或你不是它的成员';
    return `加载失败：${err}`;
  }

  return (
    <div className="issue-board">
      <div className="section-head">
        <h2>问题板</h2>
        <Space size={8} wrap>
          <Input
            className="issue-filter"
            prefix={<IconSearch />}
            allowClear
            placeholder="筛选问题…"
            value={query}
            onChange={setQuery}
            aria-label="筛选问题"
          />
          <Select
            value={teamId}
            onChange={(v) => setTeamId(v as string)}
            style={{ width: 150 }}
            placeholder="选择团队"
            aria-label="选择团队"
          >
            {teamList.map((t) => (
              <Select.Option key={t.teamId} value={t.teamId}>
                {t.teamName}
              </Select.Option>
            ))}
          </Select>
          {sections && lastLoadedAt ? (
            // now 的初值早于首次 refresh 完成时刻，夹紧避免渲染成「即将」
            <span className="issue-freshness">更新于 {formatRelative(Math.min(lastLoadedAt, now), now)}</span>
          ) : null}
          <Tooltip content="刷新问题板">
            <Button icon={<IconRefresh />} onClick={() => void refresh()} loading={loading} aria-label="刷新问题板" />
          </Tooltip>
          {settings?.canEdit ? (
            <Button icon={<IconSettings />} onClick={() => setSettingsOpen(true)}>
              表单设置
            </Button>
          ) : null}
          <Button type="primary" icon={<IconPlus />} onClick={() => openCreate(false)}>
            新建问题
          </Button>
        </Space>
      </div>

      {error ? <Alert type="error" content={loadErrorText(error)} style={{ marginBottom: 12 }} /> : null}

      {settings && presets.length === 0 && formFields.some((f) => f.id === 'repo' && f.required) ? (
        <Alert
          type="warning"
          content={
            settings.canEdit
              ? '团队尚未配置预设仓库。可点「表单设置」添加，或创建时使用自定义仓库名。'
              : '团队尚未配置预设仓库。创建人可在「表单设置」中添加；你仍可自定义仓库名（若允许）。'
          }
          style={{ marginBottom: 12 }}
        />
      ) : null}

      {na.length > 0 ? (
        <div className="issue-attention">
          <div className="issue-attention-head">
            <span className="dot alert" aria-hidden="true" />
            <span>需关注 · {na.length} 个问题可能有任务仍在运行</span>
          </div>
          <div className="issue-attention-list">
            {na.map((i) => (
              <div key={i._id} className="issue-attention-item">
                <div className="issue-card-title">{i.title}</div>
                <div className="issue-attention-reason">
                  {i.attentionReason ? ATTENTION_REASON_LABEL[i.attentionReason] ?? i.attentionReason : STATUS_LABEL[i.status]}
                  {i.targetRepoLabel ? ` · ${i.targetRepoLabel}` : ''}
                  {i.claim?.name ? ` · ${i.claim.name}` : ''}
                </div>
                <Space size={8}>
                  <Button size="mini" onClick={() => void openDetail(i)}>
                    详情
                  </Button>
                  {canManage(i) ? (
                    <Popconfirm
                      title="强制脱离将放弃当前领取并重开；旧 agent 可能仍在运行。确认？"
                      onOk={() => void doForceDetach(i)}
                    >
                      <Button size="mini" status="danger">
                        强制脱离
                      </Button>
                    </Popconfirm>
                  ) : null}
                </Space>
              </div>
            ))}
          </div>
        </div>
      ) : null}

      {sections === null && loading ? (
        <div style={{ textAlign: 'center', padding: 40 }}>
          <Spin />
        </div>
      ) : filteredAllEmpty ? (
        <Empty
          style={{ padding: 32 }}
          description={
            <span>
              没有匹配「{query.trim()}」的问题 —{' '}
              <Button type="text" size="small" onClick={() => setQuery('')}>
                清除筛选
              </Button>
            </span>
          }
        />
      ) : (
        <div className="issue-columns">
          {COLUMNS.map((c) => (
            <Column
              key={c.key}
              title={c.title}
              issues={filterCol(sections ? c.pick(sections) : [])}
              colKey={c.key}
              empty={c.empty}
              onOpen={openDetail}
            />
          ))}
        </div>
      )}

      <Drawer
        width="min(560px, 100vw)"
        title={createPreview ? '预览表单' : '新建问题'}
        visible={createOpen}
        onCancel={closeCreate}
        footer={null}
        // 关闭即卸载：title 的 autoFocus 每次打开都重新生效，预览叠层时顶层 FocusLock 正确接管
        unmountOnExit
        autoFocus={false}
      >
        {!settings ? (
          <div style={{ textAlign: 'center', padding: 24 }}>
            <Spin />
          </div>
        ) : formFields.length === 0 ? (
          <Empty description="表单未配置 — 请先在「表单设置」中添加字段" />
        ) : (
          <div id={createPreview ? 'issue-form-preview' : 'issue-form-create'}>
            <IssueFormRenderer
              fields={formFields}
              presets={presets}
              values={formValues}
              errors={formErrors}
              autoFocusFirst={!createPreview}
              onSubmit={createPreview ? undefined : () => void submitCreate()}
              onChange={(id, v) => {
                setFormValues((prev) => ({ ...prev, [id]: v }));
                setFormErrors((prev) => (prev[id] ? { ...prev, [id]: undefined } : prev));
              }}
            />
            {createPreview ? (
              <div className="issue-form-preview-note">
                预览模式 — 这是成员在「新建问题」中看到的表单；这里填写的内容不会提交。
              </div>
            ) : (
              <div className="issue-form-footer">
                <Button onClick={closeCreate} disabled={creating}>
                  取消
                </Button>
                <Button type="primary" loading={creating} disabled={creating} onClick={() => void submitCreate()}>
                  创建问题
                </Button>
              </div>
            )}
          </div>
        )}
      </Drawer>

      <Drawer
        width="min(720px, 100vw)"
        title="表单设置"
        visible={settingsOpen && !!settings}
        onCancel={requestCloseSettings}
        footer={null}
        // 关闭即卸载：编辑器本地 presets/fields/dirty 随之重置——「放弃更改」才真正生效
        unmountOnExit
      >
        {settings ? (
          <IssueSettingsEditor
            settings={settings}
            draftKey={settingsDraftKey(teamId)}
            initialDraft={settingsDraft ?? undefined}
            onCancel={requestCloseSettings}
            onDirtyChange={setSettingsDirty}
            onPreview={() => openCreate(true)}
            onSave={async (next) => {
              const r = await putTeamIssueSettings(teamId, next);
              if (r.ok && r.settings) {
                Message.success('表单已更新');
                setSettings(r.settings);
                setSettingsDraft(null);
                setSettingsDirty(false);
                setSettingsOpen(false);
              } else {
                Message.error(`保存失败：${r.error ?? r.status}`);
              }
            }}
          />
        ) : null}
      </Drawer>

      <Drawer
        width="min(520px, 100vw)"
        title={
          detail ? (
            <span>
              <span
                style={{
                  fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
                  fontSize: 12,
                  color: 'var(--color-text-3)',
                  marginRight: 8,
                }}
              >
                {shortId(detail._id)}
              </span>
              {detail.title}
            </span>
          ) : (
            ''
          )
        }
        visible={detail !== null}
        onCancel={closeDetail}
        footer={null}
      >
        {detail ? (
          <div>
            <div className="issue-detail-flags">
              <Space size={6} wrap>
                <Tag color={STATUS_COLOR[detail.status]}>{STATUS_LABEL[detail.status]}</Tag>
                {detail.attentionReason ? (
                  <Tag color="red">{ATTENTION_REASON_LABEL[detail.attentionReason] ?? detail.attentionReason}</Tag>
                ) : null}
                {(detail.labels ?? []).map((l) => (
                  <Tag key={l} color="gray">
                    {l}
                  </Tag>
                ))}
              </Space>
              {!editing ? (
                <span className="issue-detail-actions">
                  <Button type="text" size="small" icon={<IconLink />} onClick={() => void copyDetailLink()}>
                    复制链接
                  </Button>
                  {canEditBody(detail) ? (
                    <Button type="text" size="small" onClick={beginEdit}>
                      编辑
                    </Button>
                  ) : (
                    <span className="issue-detail-hint">活跃状态不可编辑正文</span>
                  )}
                </span>
              ) : null}
            </div>

            {editing ? (
              <div style={{ marginBottom: 16 }}>
                <Input
                  value={editTitle}
                  onChange={setEditTitle}
                  maxLength={200}
                  style={{ marginBottom: 8 }}
                  placeholder="标题"
                />
                <Input.TextArea
                  value={editBody}
                  onChange={setEditBody}
                  autoSize={{ minRows: 6, maxRows: 16 }}
                  style={{ marginBottom: 8 }}
                  placeholder="描述（Markdown）"
                />
                <Input
                  value={editRepoLabel}
                  onChange={setEditRepoLabel}
                  placeholder="目标仓库"
                  style={{ marginBottom: 8 }}
                />
                <Input
                  value={editLabels}
                  onChange={setEditLabels}
                  placeholder="标签（逗号分隔）"
                  style={{ marginBottom: 8 }}
                />
                <Space>
                  <Button type="primary" loading={saving} onClick={() => void submitEdit()}>
                    保存
                  </Button>
                  <Button
                    onClick={() => {
                      setEditing(false);
                      setEditRev(null);
                    }}
                  >
                    取消
                  </Button>
                </Space>
              </div>
            ) : (
              <>
                <Typography.Paragraph style={{ whiteSpace: 'pre-wrap', fontSize: 13 }}>
                  {detail.body || '（无描述）'}
                </Typography.Paragraph>
                {detail.customFields && Object.keys(detail.customFields).length > 0 ? (
                  <Descriptions
                    column={1}
                    size="small"
                    style={{ marginBottom: 12 }}
                    labelStyle={{ width: 100, color: 'var(--color-text-3)' }}
                    data={Object.entries(detail.customFields).map(([k, v]) => ({
                      label: formFields.find((f) => f.id === k)?.label ?? k,
                      value: Array.isArray(v) ? v.join(', ') : v,
                    }))}
                  />
                ) : null}
              </>
            )}

            <Descriptions
              column={1}
              size="small"
              style={{ marginBottom: 16 }}
              labelStyle={{ width: 96, color: 'var(--color-text-3)' }}
              data={[
                { label: '目标仓库', value: detail.targetRepoLabel || '—' },
                { label: '创建人', value: detail.createdByName },
                {
                  label: '创建时间',
                  value: `${formatAbsolute(detail.createdAt)}（${formatRelative(detail.createdAt)}）`,
                },
                {
                  label: '更新时间',
                  value: `${formatAbsolute(detail.updatedAt)}（${formatRelative(detail.updatedAt)}）`,
                },
              ]}
            />

            {detail.claim ? (
              <>
                <Typography.Title heading={6}>领取信息</Typography.Title>
                <Descriptions
                  column={1}
                  size="small"
                  style={{ marginBottom: 12 }}
                  labelStyle={{ width: 96, color: 'var(--color-text-3)' }}
                  data={[
                    { label: '领取人', value: detail.claim.name || detail.claim.unionId },
                    { label: 'Agent', value: detail.claim.agent || '—' },
                    { label: '执行仓库', value: detail.claim.repoLabel || '—' },
                    {
                      label: '绑定',
                      value: detail.claim.bound ? <BoundTask claim={detail.claim} /> : '预约中',
                    },
                    { label: '机器', value: detail.claim.machineId ? shortId(detail.claim.machineId) : '—' },
                    { label: '领取时间', value: formatAbsolute(detail.claim.claimedAt) },
                  ]}
                />
              </>
            ) : (
              <div style={{ fontSize: 12, color: 'var(--color-text-3)', marginBottom: 12 }}>
                尚未被领取 — 成员可在 Desktop「Botmux Team」领取并派发 agent。
              </div>
            )}

            <Typography.Title heading={6} style={{ marginTop: 20, letterSpacing: '-0.018em' }}>
              时间线
            </Typography.Title>
            {events.length === 0 ? (
              <div className="issue-events-empty">暂无事件</div>
            ) : (
              <div className="issue-events">
                {events.map((e) => (
                  <div key={e._id} className="issue-event">
                    <Space size={6} wrap>
                      <Tag size="small">{EVENT_KIND_LABEL[e.kind] ?? e.kind}</Tag>
                      {e.fromStatus || e.toStatus ? (
                        <span className="issue-event-desc">
                          {e.fromStatus ? STATUS_LABEL[e.fromStatus] ?? e.fromStatus : '—'}
                          {' → '}
                          {e.toStatus ? STATUS_LABEL[e.toStatus] ?? e.toStatus : '—'}
                        </span>
                      ) : null}
                    </Space>
                    {e.detail ? (
                      <div className="issue-event-desc" style={{ marginTop: 2 }}>
                        {e.detail}
                      </div>
                    ) : null}
                    <div style={{ color: 'var(--color-text-4)', marginTop: 2, fontSize: 11 }}>
                      {formatAbsolute(e.at)} · {formatRelative(e.at)}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {canManage(detail) ? (
              <Space style={{ marginTop: 20 }}>
                {detail.status === 'needs_attention' || detail.status === 'cancelling' ? (
                  <Popconfirm
                    title="强制脱离将放弃当前领取并重开；旧 agent 可能仍在运行。确认？"
                    onOk={() => void doForceDetach(detail)}
                  >
                    <Button status="danger">强制脱离</Button>
                  </Popconfirm>
                ) : null}
                <Popconfirm title="归档该问题？（活跃态不可归档）" onOk={() => void doArchive(detail)}>
                  <Button>归档</Button>
                </Popconfirm>
              </Space>
            ) : null}
          </div>
        ) : null}
      </Drawer>
    </div>
  );
}
