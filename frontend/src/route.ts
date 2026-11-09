/** 现有首页在窄屏下使用本期 mobile 壳；邀请深链和显式 desktop=1 保留完整平台。 */
export function shouldUseMobileShell(pathname: string, search: string, narrowViewport: boolean): boolean {
  if (pathname === '/mobile' || pathname === '/mobile/') return true;
  if (pathname !== '/' || !narrowViewport) return false;
  const q = new URLSearchParams(search);
  return !q.has('invite') && q.get('desktop') !== '1';
}

