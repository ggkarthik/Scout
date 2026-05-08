import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiRequestError, api, clearStoredAuthToken, setStoredAuthToken } from './client';

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

  it('redirects suspended demo sessions to the expired page', async () => {
    const removeSpy = vi.spyOn(Storage.prototype, 'removeItem');
    setStoredAuthToken('demo-token');
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(JSON.stringify({
      code: 'TENANT_SUSPENDED',
      error: 'Tenant is not active'
    }), {
      status: 423,
      headers: {
        'content-type': 'application/json'
      }
    }));

    await expect(api.getDashboard()).rejects.toMatchObject({
      status: 423,
      code: 'TENANT_SUSPENDED'
    } satisfies Partial<ApiRequestError>);
    expect(removeSpy).toHaveBeenCalled();
  });
});
