import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, apiRequest, clearStoredAuthToken, setStoredAuthToken } from './client';

function buildToken(payload: Record<string, unknown>): string {
  const encode = (value: Record<string, unknown>) => btoa(JSON.stringify(value))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.signature`;
}

describe('api client auth headers', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    clearStoredAuthToken();
  });

  it('uses bearer auth for audit export when a session token is present', async () => {
    setStoredAuthToken('jwt-for-preprod');
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('id,action\n', {
      status: 200,
      headers: {
        'content-type': 'text/csv',
        'content-disposition': 'attachment; filename="audit.csv"'
      }
    }));

    await api.exportAuditEventsCsv();

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(headers.get('Authorization')).toBe('Bearer jwt-for-preprod');
    expect(headers.has('X-API-Key')).toBe(false);
  });

  it('adds platform-owner confirmation headers for tenant-scoped sensitive writes', async () => {
    setStoredAuthToken(buildToken({
      sub: 'owner@example.com',
      roles: ['PLATFORM_OWNER'],
      active_tenant_id: 'tenant-123'
    }));
    vi.spyOn(window, 'confirm').mockReturnValue(true);
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: {
        'content-type': 'application/json'
      }
    }));

    await apiRequest('/findings', {
      method: 'POST',
      body: JSON.stringify({ action: 'update' })
    });

    const [, init] = fetchSpy.mock.calls[0];
    const headers = new Headers(init?.headers);
    expect(window.confirm).toHaveBeenCalled();
    expect(headers.get('X-Platform-Action-Confirm')).toBe('true');
    expect(headers.get('X-Platform-Action-Tenant')).toBe('tenant-123');
    expect(headers.get('X-Platform-Action-Time')).toBeTruthy();
  });
});
