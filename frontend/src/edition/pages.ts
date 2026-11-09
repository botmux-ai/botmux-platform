// Edition seam (pages). A private edition replaces this module through the
// @edition alias in vite.config.ts. main.tsx matches these pages before the
// platform's own and loads each in its own chunk, without the main app.
import type { ComponentType, LazyExoticComponent } from 'react';

export function editionPage(_path: string): LazyExoticComponent<ComponentType> | null {
  return null;
}
