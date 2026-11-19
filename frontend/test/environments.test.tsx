import test from 'node:test';
import assert from 'node:assert/strict';
import { renderToStaticMarkup } from 'react-dom/server';
import { environmentMenu, type PlatformEnvironment } from '../src/environments';
import { ENVIRONMENTS } from '../src/edition/environments';
import EnvironmentSwitcher, { ENVIRONMENT_HINT, EnvironmentMenu } from '../src/components/EnvironmentSwitcher';

const ENVS: PlatformEnvironment[] = [
  { label: '一区', origin: 'https://one.example.com' },
  { label: '二区', origin: 'https://two.example.net' },
  { label: '预发', origin: 'https://staging.example.com:8443' },
];

test('environmentMenu：按 host 标出当前环境，每个环境都跳到自己的首页', () => {
  assert.deepEqual(environmentMenu(ENVS, 'two.example.net'), [
    { label: '一区', host: 'one.example.com', href: 'https://one.example.com/', current: false },
    { label: '二区', host: 'two.example.net', href: 'https://two.example.net/', current: true },
    { label: '预发', host: 'staging.example.com:8443', href: 'https://staging.example.com:8443/', current: false },
  ]);
});

test('environmentMenu：host 不分大小写但端口要一致；不认识的 host 没有当前环境', () => {
  const current = (host: string) => environmentMenu(ENVS, host).filter((i) => i.current).map((i) => i.label);
  assert.deepEqual(current('ONE.Example.COM'), ['一区']);
  assert.deepEqual(current('staging.example.com:8443'), ['预发']);
  assert.deepEqual(current('staging.example.com'), []);
  assert.deepEqual(current('localhost:5173'), []);
});

test('environmentMenu：跳转只取 origin（配置里多写的路径、斜杠不带上），路径由 homePath 决定', () => {
  const [item] = environmentMenu([{ label: 'x', origin: 'https://x.example.com/some/page?q=1' }], 'other.example.com');
  assert.equal(item.href, 'https://x.example.com/');
  assert.deepEqual(
    environmentMenu(ENVS, 'one.example.com', '/mobile').map((i) => i.href),
    ['https://one.example.com/mobile', 'https://two.example.net/mobile', 'https://staging.example.com:8443/mobile'],
  );
});

test('EnvironmentSwitcher：环境列表为空时什么都不渲染（开源版的列表就是空的）', () => {
  assert.deepEqual(ENVIRONMENTS, []);
  for (const variant of ['link', 'button', 'mobile'] as const) {
    assert.equal(renderToStaticMarkup(<EnvironmentSwitcher environments={[]} host="one.example.com" variant={variant} />), '');
  }
});

test('EnvironmentSwitcher：入口显示当前环境；host 对不上时显示「切换环境」', () => {
  const html = renderToStaticMarkup(<EnvironmentSwitcher environments={ENVS} host="two.example.net" />);
  assert.match(html, /^<button type="button" class="header-text-link env-switcher-trigger"/);
  assert.match(html, /aria-label="切换环境，当前：二区"/);
  assert.match(html, /<span class="env-switcher-label">二区<\/span>/);

  const unknown = renderToStaticMarkup(<EnvironmentSwitcher environments={ENVS} host="localhost:5173" />);
  assert.match(unknown, /aria-label="切换环境"/);
  assert.match(unknown, /<span class="env-switcher-label">切换环境<\/span>/);

  // 设备/凭据页顶栏是 Arco 文字按钮，移动版顶栏是蓝字
  assert.match(renderToStaticMarkup(<EnvironmentSwitcher environments={ENVS} host="one.example.com" variant="button" />), /class="[^"]*arco-btn-text[^"]*env-switcher-trigger/);
  assert.match(renderToStaticMarkup(<EnvironmentSwitcher environments={ENVS} host="one.example.com" variant="mobile" />), /class="env-switcher-trigger env-switcher-mobile"/);
});

test('EnvironmentMenu：当前环境高亮且不可点，其余环境链接到各自首页，附「账号和数据分开」提示', () => {
  const html = renderToStaticMarkup(<EnvironmentMenu items={environmentMenu(ENVS, 'two.example.net')} />);
  const rows = [...html.matchAll(/<li>(.*?)<\/li>/g)].map((m) => m[1]);
  assert.equal(rows.length, 3);

  assert.match(rows[1], /^<span class="env-menu-item env-menu-item-current" aria-current="true"/);
  assert.match(rows[1], /二区.*two\.example\.net/);
  assert.doesNotMatch(rows[1], /href=/);

  assert.deepEqual(
    rows.map((row) => row.match(/^<a class="env-menu-item" href="([^"]+)"/)?.[1] ?? null),
    ['https://one.example.com/', null, 'https://staging.example.com:8443/'],
  );
  assert.equal(html.match(/aria-current/g)?.length, 1);
  assert.ok(html.includes(ENVIRONMENT_HINT));
});
