// 设备页 API：只走同源 SSO cookie。设备 access/refresh token 不进入浏览器代码、日志或持久化。

import { loginHref } from './api';

export type DeviceScope =
  | 'machines:read'
  | 'sessions:open'
  | 'terminal:control'
  | 'dashboard:manage'
  | 'self:refresh';

export type GrantStatus = 'pending' | 'approved' | 'denied' | 'expired' | 'consumed';

export interface DeviceGrantView {
  grantId: string;
  deviceKind: string;
  deviceName: string;
  machineId: string;
  machineName: string;
  scopes: DeviceScope[];
  status: GrantStatus;
  createdAt: number;
  expiresAt: number;
}

export interface ManagedDevice {
  deviceId: string;
  deviceKind: string;
  deviceName: string;
  status: 'active' | 'revoked';
  scopes: DeviceScope[];
  enrolledAt: number;
  lastSeenAt: number;
  deviceExp: number;
}

export class DeviceApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly loginUrl?: string;

  constructor(status: number, code: string, loginUrl?: string) {
    super(code);
    this.name = 'DeviceApiError';
    this.status = status;
    this.code = code;
    this.loginUrl = loginUrl;
  }
}

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

async function responseJson<T>(r: Response): Promise<T> {
  const body = (await r.json().catch(() => ({}))) as T & { error?: string; loginUrl?: string };
  if (!r.ok) throw new DeviceApiError(r.status, body.error || 'request_failed', body.loginUrl);
  return body;
}

export function createDeviceApi(fetchImpl: FetchLike) {
  const request = (path: string, init?: RequestInit) =>
    fetchImpl(path, { credentials: 'same-origin', cache: 'no-store', ...init });

  return {
    async getGrant(grantId: string): Promise<DeviceGrantView> {
      return responseJson<DeviceGrantView>(
        await request(`/api/devices/grants/${encodeURIComponent(grantId)}`),
      );
    },

    async decideGrant(grantId: string, action: 'approve' | 'deny'): Promise<{ status: GrantStatus }> {
      return responseJson<{ status: GrantStatus }>(
        await request(`/api/devices/grants/${encodeURIComponent(grantId)}/${action}`, {
          method: 'POST',
        }),
      );
    },

    async listDevices(): Promise<ManagedDevice[]> {
      const body = await responseJson<{ devices: ManagedDevice[] }>(await request('/api/devices'));
      return body.devices;
    },

    async revokeDevice(deviceId: string): Promise<void> {
      await responseJson<{ ok: true }>(
        await request(`/api/devices/${encodeURIComponent(deviceId)}/revoke`, { method: 'POST' }),
      );
    },
  };
}

export const deviceApi = createDeviceApi((input, init) => fetch(input, init));

export function freshLoginHref(): string {
  return loginHref();
}
