import React from 'react';
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { api, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken } from '../api/client';
import { getAuthContextQueryKey } from '../features/auth/queries';
import type { ActorContext } from '../features/auth/types';
import {
  getAuth0AccessToken,
  getAuth0User,
  handleAuth0RedirectCallbackIfNeeded,
  isAuthenticatedWithAuth0,
  isAuth0Configured,
  loginWithAuth0,
  logoutWithAuth0
} from '../lib/auth0';

const HOSTED_LOGIN_ENABLED = isAuth0Configured();
const TEST_PERSONAS_ENABLED = import.meta.env.VITE_ENABLE_TEST_PERSONAS === 'true';

export function DemoLandingPage() {
  return (
    <PublicDemoShell>
      <section className="demo-hero">
        <div className="demo-hero-copy">
          <span className="demo-kicker">7-day hosted validation</span>
          <h1>Scout.ai</h1>
          <p>
            Validate vulnerability exposure, SBOM ingestion, finding workflow, and tenant-ready reporting in a
            dedicated demo workspace.
          </p>
          <div className="button-row">
            <Link className="btn btn-primary" to="/demo/request">Request demo instance</Link>
            <Link className="btn btn-secondary" to="/login">Log in</Link>
          </div>
        </div>
        <div className="demo-product-signal" aria-label="Product preview">
          <div><strong>Unified Records</strong><span>Prioritized CVEs</span></div>
          <div><strong>SBOM Upload</strong><span>Limited demo ingestion</span></div>
          <div><strong>Findings</strong><span>Workflow-ready evidence</span></div>
        </div>
      </section>
      <section className="demo-feature-grid" aria-label="Demo capabilities">
        {[
          ['Correlate', 'See vulnerable software mapped to inventory with deterministic evidence.'],
          ['Prioritize', 'Use exploit, EOL, blast radius, and workflow signals to focus analyst time.'],
          ['Validate', 'Upload a small SBOM and inspect how exposure records and findings respond.']
        ].map(([title, body]) => (
          <article key={title} className="demo-feature">
            <h2>{title}</h2>
            <p>{body}</p>
          </article>
        ))}
      </section>
    </PublicDemoShell>
  );
}

export function DemoRequestPage() {
  const navigate = useNavigate();
  const [formError, setFormError] = React.useState<string | null>(null);
  const requestDemo = useMutation({
    mutationFn: api.createDemoRequest,
    onSuccess: () => navigate('/demo/request/success')
  });

  const submit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setFormError(null);
    const formData = new FormData(event.currentTarget);
    const acceptedTerms = formData.get('acceptedTerms') === 'on';
    if (!acceptedTerms) {
      setFormError('Accept the demo terms to request access.');
      return;
    }
    requestDemo.mutate({
      fullName: String(formData.get('fullName') ?? '').trim(),
      email: String(formData.get('email') ?? '').trim(),
      company: String(formData.get('company') ?? '').trim(),
      roleTitle: String(formData.get('roleTitle') ?? '').trim(),
      companySize: String(formData.get('companySize') ?? '').trim(),
      useCase: String(formData.get('useCase') ?? '').trim(),
      notes: String(formData.get('notes') ?? '').trim(),
      acceptedTerms
    });
  };

  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <div className="panel-header">
          <div>
            <h1>Request a demo instance</h1>
            <div className="panel-caption">We review requests before provisioning an isolated 7-day workspace.</div>
          </div>
        </div>
        <form className="demo-request-form" onSubmit={submit}>
          <label>Full name<input name="fullName" required maxLength={255} /></label>
          <label>Work email<input name="email" type="email" required maxLength={255} /></label>
          <label>Company<input name="company" required maxLength={255} /></label>
          <label>Role<input name="roleTitle" maxLength={255} /></label>
          <label>Company size
            <select name="companySize" defaultValue="">
              <option value="" disabled>Select size</option>
              <option value="1-100">1-100</option>
              <option value="101-1000">101-1,000</option>
              <option value="1001-5000">1,001-5,000</option>
              <option value="5000+">5,000+</option>
            </select>
          </label>
          <label>Primary use case
            <select name="useCase" defaultValue="">
              <option value="" disabled>Select use case</option>
              <option value="SBOM validation">SBOM validation</option>
              <option value="Vulnerability prioritization">Vulnerability prioritization</option>
              <option value="Finding workflow">Finding workflow</option>
              <option value="Executive reporting">Executive reporting</option>
            </select>
          </label>
          <label className="full-width">Notes<textarea name="notes" rows={4} maxLength={2000} /></label>
          <label className="demo-terms full-width">
            <input name="acceptedTerms" type="checkbox" />
            <span>I understand the demo allows sample data and limited SBOM upload; live connectors are disabled.</span>
          </label>
          {(formError || requestDemo.isError) && (
            <div className="notice error full-width" role="alert">
              {formError ?? (requestDemo.error instanceof Error ? requestDemo.error.message : 'Demo request failed')}
            </div>
          )}
          <button className="btn btn-primary" type="submit" disabled={requestDemo.isPending}>
            {requestDemo.isPending ? 'Submitting...' : 'Submit request'}
          </button>
        </form>
      </section>
    </PublicDemoShell>
  );
}

export function DemoRequestSuccessPage() {
  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Request received</h1>
        <p>We’ll review the request and send an invite link after the demo workspace is provisioned.</p>
        <Link className="btn btn-secondary" to="/demo">Back to demo overview</Link>
      </section>
    </PublicDemoShell>
  );
}

export function DemoInvitePage() {
  const { token = '' } = useParams();
  const navigate = useNavigate();
  const inviteQuery = useQuery({
    queryKey: ['demo-invite', token],
    queryFn: () => api.validateDemoInvite(token),
    enabled: token.length > 0
  });
  const acceptInvite = useMutation({
    mutationFn: () => api.acceptDemoInvite(token),
    onSuccess: (response) => {
      if (response.setupToken) {
        navigate(`/login?setup=${encodeURIComponent(response.setupToken)}`);
      }
    }
  });

  const invite = inviteQuery.data;
  const deliveryFailed = invite?.status === 'DELIVERY_ERROR';
  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Demo invite</h1>
        {inviteQuery.isLoading ? (
          <p>Checking invite...</p>
        ) : inviteQuery.isError ? (
          <div className="notice error">{inviteQuery.error instanceof Error ? inviteQuery.error.message : 'Invite is invalid'}</div>
        ) : invite ? (
          <>
            <div className={`notice ${deliveryFailed ? 'error' : 'success'}`}>
              {invite.message}
            </div>
            {deliveryFailed && (
              <p>
                The workspace was provisioned, but Scout.ai could not deliver the email automatically.
                You can still accept this invite and continue with manual password setup.
              </p>
            )}
            <dl className="demo-invite-details">
              <div><dt>Workspace</dt><dd>{invite.tenantName}</dd></div>
              <div><dt>Email</dt><dd>{invite.email}</dd></div>
              <div><dt>Demo expires</dt><dd>{new Date(invite.demoExpiresAt).toLocaleString()}</dd></div>
            </dl>
            <div className="button-row">
              <button
                className="btn btn-primary"
                type="button"
                disabled={!invite.valid || acceptInvite.isPending}
                onClick={() => acceptInvite.mutate()}
              >
                {acceptInvite.isPending ? 'Activating...' : 'Activate your workspace'}
              </button>
            </div>
            {acceptInvite.isError && <div className="notice error">{acceptInvite.error instanceof Error ? acceptInvite.error.message : 'Accept failed'}</div>}
          </>
        ) : null}
      </section>
    </PublicDemoShell>
  );
}

export function LoginPage() {
  const [searchParams] = useSearchParams();
  const invite = searchParams.get('invite');
  const setupToken = searchParams.get('setup');
  const [email, setEmail] = React.useState('');
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
  const [hostedLoginPending, setHostedLoginPending] = React.useState(false);
  const [_auth0CallbackPending, setAuth0CallbackPending] = React.useState(false);
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const personasQuery = useQuery({
    queryKey: ['login-test-personas'],
    queryFn: api.listTestPersonas,
    enabled: TEST_PERSONAS_ENABLED
  });

  const navigateAfterAuth = React.useCallback((actor: ActorContext) => {
    if (actor.roles.some((role) => role.replace(/^ROLE_/, '') === 'PLATFORM_OWNER') && actor.platformScope) {
      navigate('/platform/tenants', { replace: true });
      return;
    }
    navigate('/exposure', { replace: true });
  }, [navigate]);

  const startHostedLogin = () => {
    void (async () => {
      try {
        setError(null);
        setHostedLoginPending(true);
        await loginWithAuth0(
          invite
            ? { appState: { invite } }
            : undefined
        );
      } catch (hostedLoginError) {
        setHostedLoginPending(false);
        setError(hostedLoginError instanceof Error ? hostedLoginError.message : 'Auth0 login failed to initialize');
      }
    })();
  };

  const applyToken = React.useCallback(async (token: string) => {
    setStoredAuthToken(token);
    const actor = await api.getAuthContext();
    queryClient.setQueryData(getAuthContextQueryKey(token), actor);
    navigateAfterAuth(actor);
  }, [navigateAfterAuth, queryClient]);

  const loginMutation = useMutation({
    mutationFn: async () => {
      const response = await api.login(email, password);
      await applyToken(response.token);
      return response;
    },
    onError: (mutationError) => {
      setError(mutationError instanceof Error ? mutationError.message : 'Login failed');
    }
  });

  const setupPasswordMutation = useMutation({
    mutationFn: async () => {
      if (!setupToken) {
        throw new Error('Password setup token is missing');
      }
      const response = await api.setupPassword(setupToken, password);
      await applyToken(response.token);
      return response;
    },
    onError: (mutationError) => {
      setError(mutationError instanceof Error ? mutationError.message : 'Password setup failed');
    }
  });

  const issuePersonaToken = useMutation({
    mutationFn: async (personaKey: string) => {
      const response = await api.issueTestPersonaToken(personaKey);
      await applyToken(response.token);
      return response;
    },
    onError: (mutationError) => {
      setError(mutationError instanceof Error ? mutationError.message : 'Test persona login failed');
    }
  });

  const submitLogin = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    if (setupToken) {
      setupPasswordMutation.mutate();
      return;
    }
    loginMutation.mutate();
  };

  React.useEffect(() => {
    if (!HOSTED_LOGIN_ENABLED || setupToken) {
      return;
    }
    let cancelled = false;
    // Only block the button when we're actively processing a redirect callback from Auth0.
    // The background "already authenticated?" check must never disable the button.
    const isRedirectCallback = searchParams.has('code') && searchParams.has('state');
    const isErrorCallback = !!searchParams.get('error');
    if (isRedirectCallback || isErrorCallback) {
      setHostedLoginPending(true);
    } else {
      setAuth0CallbackPending(true);
    }
    setError(null);

    void (async () => {
      try {
        if (isErrorCallback) {
          throw new Error(
            `Auth0 error: ${searchParams.get('error')} - ${searchParams.get('error_description') ?? 'Unknown error'}`
          );
        }

        await handleAuth0RedirectCallbackIfNeeded();

        if (!(await isAuthenticatedWithAuth0())) {
          if (!cancelled) {
            setHostedLoginPending(false);
            setAuth0CallbackPending(false);
          }
          return;
        }

        const accessToken = await getAuth0AccessToken();
        if (!accessToken) {
          const user = await getAuth0User();
          throw new Error(
            user?.email
              ? `Auth0 login succeeded for ${user.email}, but no API access token is available yet. Configure an Auth0 API audience before using hosted login with the backend.`
              : 'Auth0 login succeeded, but no API access token is available yet. Configure an Auth0 API audience before using hosted login with the backend.'
          );
        }
        if (!cancelled) {
          await applyToken(accessToken);
        }
      } catch (hostedLoginError) {
        if (!cancelled) {
          setError(hostedLoginError instanceof Error ? hostedLoginError.message : 'Auth0 login failed');
          setHostedLoginPending(false);
          setAuth0CallbackPending(false);
        }
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [applyToken, searchParams, setupToken]);

  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Log in to Scout.ai</h1>
        <p>
          {setupToken
            ? 'Set a password for your tenant workspace. You will be signed in as soon as the password is saved.'
            : 'Use your email and password to access your tenant workspace or the platform console.'}
        </p>
        {!setupToken && (
          <form className="auth-token-form dev-token-form" onSubmit={submitLogin}>
            <label>Work email<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
            <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
            <button className="btn btn-primary" type="submit" disabled={loginMutation.isPending || !email.trim() || !password.trim()}>
              {loginMutation.isPending ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        )}
        {setupToken && (
          <form className="auth-token-form dev-token-form" onSubmit={submitLogin}>
            <label>New password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
            <button className="btn btn-primary" type="submit" disabled={setupPasswordMutation.isPending || password.trim().length < 8}>
              {setupPasswordMutation.isPending ? 'Saving...' : 'Set password'}
            </button>
          </form>
        )}
        {error && <div className="notice error" role="alert">{error}</div>}
        {!setupToken && (
          <>
            <button
              className="btn btn-secondary"
              type="button"
              onClick={startHostedLogin}
              disabled={hostedLoginPending || !HOSTED_LOGIN_ENABLED}
            >
              {hostedLoginPending ? 'Connecting to Auth0...' : 'Continue with SSO'}
            </button>
            {!HOSTED_LOGIN_ENABLED && (
              <div className="panel-caption">
                SSO is not configured for this deployment yet. Set the Auth0 frontend environment values to enable hosted login.
              </div>
            )}
          </>
        )}
        {TEST_PERSONAS_ENABLED && (
          <div className="section-block">
            <h2 style={{ fontSize: '1rem', marginBottom: '0.75rem' }}>Non-production test personas</h2>
            {personasQuery.isLoading ? (
              <p>Loading personas...</p>
            ) : personasQuery.isError ? (
              <div className="notice error" role="alert">
                {personasQuery.error instanceof Error ? personasQuery.error.message : 'Failed to load personas'}
              </div>
            ) : (
              <div className="button-row">
                {(personasQuery.data ?? []).map((persona) => (
                  <button
                    key={persona.key}
                    className="btn btn-secondary"
                    type="button"
                    onClick={() => {
                      setError(null);
                      issuePersonaToken.mutate(persona.key);
                    }}
                    disabled={issuePersonaToken.isPending}
                  >
                    {persona.label}
                  </button>
                ))}
              </div>
            )}
          </div>
        )}
      </section>
    </PublicDemoShell>
  );
}

export function DemoExpiredPage() {
  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Demo expired</h1>
        <p>This 7-day demo workspace is no longer active. Contact the team if you need more time or want to continue validation.</p>
        <Link className="btn btn-primary" to="/demo/request">Request another demo</Link>
      </section>
    </PublicDemoShell>
  );
}

function PublicDemoShell({ children, compact = false }: { children: React.ReactNode; compact?: boolean }) {
  const location = useLocation();
  const navigate = useNavigate();
  const [hasStoredToken, setHasStoredToken] = React.useState(() => getStoredAuthToken().trim().length > 0);

  React.useEffect(() => {
    setHasStoredToken(getStoredAuthToken().trim().length > 0);
  }, [location.pathname, location.search]);

  const logout = React.useCallback(() => {
    void (async () => {
      clearStoredAuthToken();
      setHasStoredToken(false);
      if (HOSTED_LOGIN_ENABLED && await isAuthenticatedWithAuth0()) {
        await logoutWithAuth0({
          logoutParams: {
            returnTo: window.location.origin
          }
        });
        return;
      }
      navigate('/login', { replace: true });
    })();
  }, [navigate]);

  return (
    <main className={compact ? 'public-demo-shell compact' : 'public-demo-shell'}>
      <nav className="public-demo-nav">
        <Link to="/demo" className="public-demo-brand"><span className="brand-mark">SA</span><strong>Scout.ai</strong></Link>
        <div className="public-demo-links">
          <Link to="/demo/request">Request demo</Link>
          <Link to="/login">Log in</Link>
          {hasStoredToken && (
            <button className="btn btn-secondary" type="button" onClick={logout}>
              Log out
            </button>
          )}
        </div>
      </nav>
      {children}
    </main>
  );
}
