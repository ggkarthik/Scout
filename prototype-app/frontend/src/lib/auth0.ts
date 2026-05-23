import {
  createAuth0Client,
  type Auth0Client,
  type RedirectLoginOptions,
  type LogoutOptions,
  type User
} from '@auth0/auth0-spa-js';

const AUTH0_DOMAIN = (import.meta.env.VITE_AUTH0_DOMAIN ?? '').trim();
const AUTH0_CLIENT_ID = (import.meta.env.VITE_AUTH0_CLIENT_ID ?? '').trim();
const AUTH0_SCOPE = (import.meta.env.VITE_AUTH0_SCOPE ?? 'openid profile email').trim();
const AUTH0_AUDIENCE = (import.meta.env.VITE_AUTH0_AUDIENCE ?? '').trim();

let auth0ClientPromise: Promise<Auth0Client> | null = null;
let pendingCallbackPromise: Promise<boolean> | null = null;

function hasText(value: string): boolean {
  return value.trim().length > 0;
}

function buildAuthorizationParams() {
  return {
    redirect_uri: `${window.location.origin}/login`,
    scope: AUTH0_SCOPE,
    ...(hasText(AUTH0_AUDIENCE) ? { audience: AUTH0_AUDIENCE } : {})
  };
}

export function isAuth0Configured(): boolean {
  return hasText(AUTH0_DOMAIN) && hasText(AUTH0_CLIENT_ID);
}

export async function getAuth0Client(): Promise<Auth0Client | null> {
  if (!isAuth0Configured()) {
    return null;
  }
  if (!auth0ClientPromise) {
    auth0ClientPromise = createAuth0Client({
      domain: AUTH0_DOMAIN,
      clientId: AUTH0_CLIENT_ID,
      authorizationParams: buildAuthorizationParams(),
      useRefreshTokens: true,
      cacheLocation: 'localstorage'
    });
  }
  return auth0ClientPromise;
}

export async function loginWithAuth0(options?: RedirectLoginOptions): Promise<void> {
  const client = await getAuth0Client();
  if (!client) {
    throw new Error('Auth0 is not configured');
  }
  await client.loginWithRedirect(options);
}

export async function handleAuth0RedirectCallbackIfNeeded(): Promise<boolean> {
  const client = await getAuth0Client();
  if (!client) {
    return false;
  }
  const search = window.location.search;
  if (!search.includes('code=') || !search.includes('state=')) {
    return false;
  }
  // Deduplicate concurrent invocations from React StrictMode's double effect run.
  // Both calls share the same promise so the PKCE state is consumed exactly once.
  if (pendingCallbackPromise) {
    return pendingCallbackPromise;
  }
  pendingCallbackPromise = (async () => {
    try {
      await client.handleRedirectCallback();
      window.history.replaceState({}, '', window.location.pathname);
      return true;
    } finally {
      pendingCallbackPromise = null;
    }
  })();
  return pendingCallbackPromise;
}

export async function getAuth0AccessToken(): Promise<string | null> {
  const client = await getAuth0Client();
  if (!client) {
    return null;
  }
  return client.getTokenSilently();
}

export async function isAuthenticatedWithAuth0(): Promise<boolean> {
  const client = await getAuth0Client();
  if (!client) {
    return false;
  }
  return client.isAuthenticated();
}

export async function getAuth0User(): Promise<User | undefined> {
  const client = await getAuth0Client();
  if (!client) {
    return undefined;
  }
  return client.getUser();
}

export async function logoutWithAuth0(options?: LogoutOptions): Promise<void> {
  const client = await getAuth0Client();
  if (!client) {
    return;
  }
  await client.logout(options);
}
