// Edition seam (environments). A private edition replaces this module through
// the @edition alias in vite.config.ts. Every page header loads it (the main
// app, the device and credential pages, the mobile shell), so it holds data
// and nothing else.
import type { PlatformEnvironment } from '../environments';

/**
 * Deployments the header offers to switch between; the one being viewed is
 * matched by host. Empty hides the switcher.
 */
export const ENVIRONMENTS: readonly PlatformEnvironment[] = [];
