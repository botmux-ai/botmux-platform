export interface InviteAcceptResult {
  status: number;
  teamName?: string;
}

/** 清理邀请参数只能发生在服务端确认接受成功之后；失败或重登都保留原链接以便续接。 */
export async function acceptInviteAndClearOnSuccess<T extends InviteAcceptResult>(
  request: () => Promise<T>,
  clearInvite: () => void,
): Promise<T> {
  const result = await request();
  if (result.status === 200) clearInvite();
  return result;
}

/** 仅移除 invite，保留其它查询参数与 hash 状态。 */
export function urlWithoutInvite(locationLike: {
  pathname: string;
  search: string;
  hash: string;
}): string {
  const search = new URLSearchParams(locationLike.search);
  search.delete('invite');
  const query = search.toString();
  return locationLike.pathname + (query ? `?${query}` : '') + locationLike.hash;
}
