// Switching between deployments of the platform from the header. The list
// comes from @edition/environments; the open-source edition has none, and an
// empty list hides the switcher.

/** One deployment of the platform. */
export interface PlatformEnvironment {
  /** Shown in the header and the menu. */
  label: string;
  /** Scheme and host the deployment is served from, e.g. https://botmux.example.com. */
  origin: string;
}

export interface EnvironmentMenuItem {
  label: string;
  host: string;
  /** Where choosing the environment goes. */
  href: string;
  /** Whether this page is served by the environment. */
  current: boolean;
}

/**
 * The switcher's entries, the environment serving `currentHost` (location.host)
 * marked current. Each one links to the environment's `homePath`, not to the
 * page being viewed: deployments keep separate accounts, machines and teams,
 * so a machine, team, invite or device link has nothing behind it elsewhere.
 */
export function environmentMenu(
  environments: readonly PlatformEnvironment[],
  currentHost: string,
  homePath = '/',
): EnvironmentMenuItem[] {
  const host = currentHost.toLowerCase();
  return environments.map(({ label, origin }) => {
    const url = new URL(origin);
    return { label, host: url.host, href: url.origin + homePath, current: url.host === host };
  });
}
