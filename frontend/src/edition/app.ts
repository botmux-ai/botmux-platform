// Edition seam (main app). A private edition replaces this module through the
// @edition alias in vite.config.ts; it is loaded with App only.

/** Called once the signed-in user is known. */
export function identifyUser(_unionId: string, _name?: string): void {}

/** The one-line installer shown in the install dialog. */
export function installCommand(origin: string): string {
  return `curl -fsSL --connect-timeout 5 --max-time 20 --retry 5 --retry-delay 1 --retry-max-time 60 ${origin}/install.sh | BOTMUX_PLATFORM_URL=${origin} sh && export PATH="$HOME/.local/bin:$PATH"`;
}

export const INSTALL_HINT = '安装过程中按提示完成两次扫码授权即可。';

/** Where the platform's source lives, linked from the header. */
export const SOURCE_LINK: { href: string; host: 'github' | 'gitlab' } = {
  href: 'https://github.com/botmux-ai/botmux-platform',
  host: 'github',
};
