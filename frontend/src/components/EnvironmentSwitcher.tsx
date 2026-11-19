import { useState } from 'react';
import { Button, Dropdown } from '@arco-design/web-react';
import { IconCheck, IconDown, IconPublic } from '@arco-design/web-react/icon';
import { environmentMenu, type EnvironmentMenuItem, type PlatformEnvironment } from '../environments';

// One sentence per line (.env-menu-hint keeps the line break) instead of wrapping wherever the menu ends.
export const ENVIRONMENT_HINT = '各环境的账号绑定和数据是分开的。\n切换后进入该环境首页。';

/**
 * Header menu for going to another deployment of the platform. Renders nothing
 * without environments (the open-source edition).
 */
export default function EnvironmentSwitcher({
  environments,
  host = location.host,
  homePath = '/',
  variant = 'link',
}: {
  environments: readonly PlatformEnvironment[];
  host?: string;
  /** Path opened in the chosen environment. */
  homePath?: string;
  /** Matches the header it sits in: the main header's text links, the device pages' text buttons, or the mobile header. */
  variant?: 'link' | 'button' | 'mobile';
}) {
  const [open, setOpen] = useState(false);
  if (environments.length === 0) return null;

  const items = environmentMenu(environments, host, homePath);
  const current = items.find((item) => item.current);
  const triggerProps = {
    'aria-label': current ? `切换环境，当前：${current.label}` : '切换环境',
    'aria-haspopup': true,
    'aria-expanded': open,
  };
  const content = (
    <>
      <IconPublic />
      <span className="env-switcher-label">{current?.label ?? '切换环境'}</span>
      <IconDown className="env-switcher-caret" />
    </>
  );

  return (
    <Dropdown
      trigger="click"
      position="br"
      popupVisible={open}
      onVisibleChange={setOpen}
      droplist={<EnvironmentMenu items={items} />}
    >
      {variant === 'button' ? (
        <Button size="small" type="text" className="env-switcher-trigger" {...triggerProps}>
          {content}
        </Button>
      ) : (
        <button
          type="button"
          className={variant === 'mobile' ? 'env-switcher-trigger env-switcher-mobile' : 'header-text-link env-switcher-trigger'}
          {...triggerProps}
        >
          {content}
        </button>
      )}
    </Dropdown>
  );
}

/** The environments as links, the current one checked instead of linked. */
export function EnvironmentMenu({ items }: { items: readonly EnvironmentMenuItem[] }) {
  return (
    <div className="env-menu">
      <ul className="env-menu-list" aria-label="环境">
        {items.map((item) => {
          const body = (
            <>
              <IconCheck className="env-menu-check" aria-hidden="true" />
              <span className="env-menu-label">{item.label}</span>
              <span className="env-menu-host">{item.host}</span>
            </>
          );
          return (
            <li key={item.href}>
              {item.current ? (
                <span className="env-menu-item env-menu-item-current" aria-current="true" title="当前环境">
                  {body}
                </span>
              ) : (
                <a className="env-menu-item" href={item.href}>
                  {body}
                </a>
              )}
            </li>
          );
        })}
      </ul>
      <p className="env-menu-hint">{ENVIRONMENT_HINT}</p>
    </div>
  );
}
