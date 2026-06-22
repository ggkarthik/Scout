import React from 'react';
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { pathForConnectView } from '../app/routes';
import { api, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken } from '../api/client';
import { getAuthContextQueryKey } from '../features/auth/queries';
import { canManageRiskPolicy } from '../features/auth/roles';
import type { ActorContext } from '../features/auth/types';
const TEST_PERSONAS_ENABLED = import.meta.env.VITE_ENABLE_TEST_PERSONAS === 'true';
const SHARED_LOCALHOST_LOGIN_HINTS_ENABLED = typeof window !== 'undefined'
  && ['localhost', '127.0.0.1', '::1'].includes(window.location.hostname);

export function DemoLandingPage() {
  return (
    <PublicDemoShell>
      <section className="sg-hero">
        <div className="sg-hero-copy">
          <span className="demo-kicker">securityGrid product portfolio</span>
          <h1>NoScan gives customers a working risk operations stack, not just another dashboard.</h1>
          <p>
            securityGrid combines infrastructure inventory, SBOM intelligence, cloud posture, vulnerability evidence,
            and workflow-driven remediation into one operating model. The portfolio is organized into focused product
            grids so buyers can understand where to start and how the platform expands.
          </p>
          <div className="button-row">
            <a className="btn btn-primary" href="#products">Explore products</a>
            <Link className="btn btn-secondary" to="/demo/request">Request customer briefing</Link>
          </div>
          <div className="sg-hero-metrics" aria-label="Portfolio signals">
            {[
              ['Products', 'InfraGrid, SBOM Grid, Cloud Grid, AI Grid'],
              ['Core workflows', 'Inventory, correlation, findings, remediation'],
              ['Buyer outcome', 'Faster exposure triage with evidence-backed action']
            ].map(([label, value]) => (
              <div key={label} className="sg-hero-metric">
                <strong>{label}</strong>
                <span>{value}</span>
              </div>
            ))}
          </div>
        </div>
        <div className="sg-hero-visual" aria-label="NoScan product preview">
          <article className="sg-preview-panel sg-preview-panel--primary">
            <header>
              <strong>NoScan Command View</strong>
              <span>Unified vulnerability, asset, and software posture</span>
            </header>
            <div className="sg-preview-grid">
              <div className="sg-preview-stat">
                <span>Assets mapped</span>
                <strong>1,181</strong>
              </div>
              <div className="sg-preview-stat">
                <span>Applicable CVEs</span>
                <strong>38</strong>
              </div>
              <div className="sg-preview-stat">
                <span>Open findings</span>
                <strong>9</strong>
              </div>
              <div className="sg-preview-stat">
                <span>SBOM components</span>
                <strong>8,319</strong>
              </div>
            </div>
          </article>
          <article className="sg-preview-panel">
            <header>
              <strong>AI Grid mock</strong>
              <span>Analyst copilots, guided triage, and remediation drafts</span>
            </header>
            <ul className="sg-preview-list">
              <li>Impact-aware CVE assessment summaries</li>
              <li>Recommended workflow branching by evidence state</li>
              <li>Draft remediation narratives for operations teams</li>
            </ul>
          </article>
          <article className="sg-preview-panel">
            <header>
              <strong>Customer operating model</strong>
              <span>Connectors, correlation, investigations, findings, reporting</span>
            </header>
            <div className="sg-preview-flow">
              <span>Connect</span>
              <span>Correlate</span>
              <span>Investigate</span>
              <span>Remediate</span>
            </div>
          </article>
        </div>
      </section>

      <section id="products" className="sg-section">
        <div className="sg-section-heading">
          <span className="demo-kicker">Products</span>
          <h2>Purpose-built grids for each part of the exposure problem</h2>
          <p>Each grid can stand on its own, but the value compounds when they share the same evidence model.</p>
        </div>
        <div className="sg-product-grid">
          {[
            {
              name: 'InfraGrid',
              body: 'Build a normalized host and software inventory, map vulnerabilities to deployed software, and drive evidence-backed findings from infrastructure records.',
              bullets: ['Host inventory and ownership signals', 'Applicable CVE correlation', 'Finding workflow and SLA routing']
            },
            {
              name: 'SBOM Grid',
              body: 'Ingest application and component BOM data, correlate packages to advisories, and expose software supply chain risk at product, version, and asset levels.',
              bullets: ['SBOM import and component normalization', 'Package-to-advisory matching', 'Application and component drilldowns']
            },
            {
              name: 'Cloud Grid',
              body: 'Connect cloud accounts and runtime inventory so cloud assets, external exposure, and software evidence are visible in the same risk model.',
              bullets: ['Account and region onboarding', 'Runtime inventory alignment', 'Exposure-driven cloud prioritization']
            },
            {
              name: 'AI Grid',
              body: 'Mocked in this site as the orchestration layer for analyst assistance, workflow recommendations, remediation drafting, and reporting acceleration.',
              bullets: ['Investigation copilots', 'Recommendation generation', 'Executive and operator narratives']
            }
          ].map((product) => (
            <article key={product.name} className="sg-product-card">
              <div className="sg-product-badge">{product.name}</div>
              <p>{product.body}</p>
              <ul>
                {product.bullets.map((bullet) => <li key={bullet}>{bullet}</li>)}
              </ul>
            </article>
          ))}
        </div>
      </section>

      <section id="solutions" className="sg-section">
        <div className="sg-section-heading">
          <span className="demo-kicker">Solutions</span>
          <h2>What customers can solve with the portfolio</h2>
        </div>
        <div className="sg-solution-grid">
          {[
            ['Exposure operations', 'Run a repeatable process from CVE intake to impacted asset evidence, ownership routing, and finding generation.'],
            ['Application supply chain visibility', 'Correlate SBOM components with advisories, EOL signals, and software identity metadata.'],
            ['Cloud-first remediation', 'Prioritize external-facing and internet-reachable assets with contextual software risk.'],
            ['Executive reporting', 'Give security and IT leaders a single narrative for what is affected, what is exploitable, and what action is underway.']
          ].map(([title, body]) => (
            <article key={title} className="sg-solution-card">
              <h3>{title}</h3>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="use-cases" className="sg-section">
        <div className="sg-section-heading">
          <span className="demo-kicker">Use cases</span>
          <h2>Concrete buyer journeys</h2>
        </div>
        <div className="sg-usecase-grid">
          {[
            ['Vulnerability management teams', 'Correlate NVD, KEV, EUVD, and vendor intelligence with real software evidence before opening tickets.'],
            ['Infrastructure operations', 'See exactly which hosts, software versions, and owners are affected before remediation windows are committed.'],
            ['Application security', 'Use SBOM Grid to map open source and third-party components to advisory feeds and EOL coverage gaps.'],
            ['Cloud engineering', 'Use Cloud Grid to focus on internet-facing and high-blast-radius assets instead of flat CVE counts.']
          ].map(([title, body]) => (
            <article key={title} className="sg-usecase-card">
              <h3>{title}</h3>
              <p>{body}</p>
            </article>
          ))}
        </div>
      </section>

      <section id="workflows" className="sg-section">
        <div className="sg-section-heading">
          <span className="demo-kicker">Workflow narratives</span>
          <h2>How the portfolio works in practice</h2>
        </div>
        <div className="sg-workflow-stack">
          {[
            {
              title: 'InfraGrid workflow',
              steps: [
                'Connect host and software inventory from existing enterprise systems.',
                'Correlate deployed software to vulnerability intelligence and EOL signals.',
                'Assess applicability and impact, then open findings only where evidence supports action.'
              ]
            },
            {
              title: 'SBOM Grid workflow',
              steps: [
                'Import BOMs for applications or products and normalize component identities.',
                'Link packages to advisory feeds, vulnerabilities, and lifecycle coverage.',
                'Surface risky components, missing metadata, and remediation candidates per application.'
              ]
            },
            {
              title: 'Cloud Grid workflow',
              steps: [
                'Onboard cloud accounts, regions, and instance-level inventory.',
                'Identify externally exposed compute and software hotspots across runtime assets.',
                'Push prioritized findings into remediation queues with ownership and SLA context.'
              ]
            },
            {
              title: 'AI Grid workflow mock',
              steps: [
                'Generate investigation summaries and remediation narratives from the same evidence model.',
                'Recommend next workflow steps based on exploitability, impact, and asset criticality.',
                'Draft operator-ready actions while preserving analyst approval checkpoints.'
              ]
            }
          ].map((workflow) => (
            <article key={workflow.title} className="sg-workflow-card">
              <h3>{workflow.title}</h3>
              <ol>
                {workflow.steps.map((step) => <li key={step}>{step}</li>)}
              </ol>
            </article>
          ))}
        </div>
      </section>

      <section className="sg-section">
        <div className="sg-section-heading">
          <span className="demo-kicker">Portfolio map</span>
          <h2>How the grids fit together</h2>
        </div>
        <div className="sg-portfolio-band">
          <div className="sg-portfolio-step">
            <strong>Connectors</strong>
            <span>ServiceNow, SBOM uploads, cloud accounts, vulnerability feeds</span>
          </div>
          <div className="sg-portfolio-step">
            <strong>Correlation</strong>
            <span>Hosts, software identities, packages, CVEs, advisories, lifecycle data</span>
          </div>
          <div className="sg-portfolio-step">
            <strong>Workflow</strong>
            <span>Investigation, findings, ownership, SLA, reporting</span>
          </div>
          <div className="sg-portfolio-step">
            <strong>AI Grid mock</strong>
            <span>Recommendations, summaries, narratives, next-step guidance</span>
          </div>
        </div>
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
            <h1>Request a NoScan product demo</h1>
            <div className="panel-caption">We review requests before provisioning an isolated 7-day workspace with the full guided product experience.</div>
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
            <span>I understand the demo is time-boxed, uses isolated sample-friendly workflows, and may include demo-specific usage limits.</span>
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
        <p>We’ll review the request and send an invite link after the securityGrid demo workspace is provisioned with the full guided experience.</p>
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
        const nextParams = new URLSearchParams({
          setup: response.setupToken,
          email: response.email
        });
        navigate(`/login?${nextParams.toString()}`);
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
                The workspace was provisioned, but securityGrid could not deliver the email automatically.
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

export function TenantInvitePage() {
  const { token = '' } = useParams();
  const navigate = useNavigate();
  const inviteQuery = useQuery({
    queryKey: ['tenant-invite', token],
    queryFn: () => api.validateTenantInvite(token),
    enabled: token.length > 0
  });
  const acceptInvite = useMutation({
    mutationFn: () => api.acceptTenantInvite(token),
    onSuccess: (response) => {
      if (response.setupToken) {
        const nextParams = new URLSearchParams({
          setup: response.setupToken,
          email: response.email
        });
        navigate(`/login?${nextParams.toString()}`);
      }
    }
  });

  const invite = inviteQuery.data;
  const deliveryFailed = invite?.status === 'DELIVERY_ERROR';

  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Workspace invite</h1>
        {inviteQuery.isLoading ? (
          <p>Checking invite...</p>
        ) : inviteQuery.isError ? (
          <div className="notice error">{inviteQuery.error instanceof Error ? inviteQuery.error.message : 'Invite is invalid'}</div>
        ) : invite ? (
          <>
            <div className={`notice ${deliveryFailed ? 'error' : 'success'}`}>
              {invite.message}
            </div>
            {deliveryFailed ? (
              <p>The automatic email delivery failed, but this invite link is still valid.</p>
            ) : null}
            <dl className="demo-invite-details">
              <div><dt>Workspace</dt><dd>{invite.tenantName}</dd></div>
              <div><dt>Email</dt><dd>{invite.email}</dd></div>
              <div><dt>Role</dt><dd>{invite.role.replace(/_/g, ' ')}</dd></div>
              <div><dt>Invite expires</dt><dd>{new Date(invite.inviteExpiresAt).toLocaleString()}</dd></div>
            </dl>
            <div className="button-row">
              <button
                className="btn btn-primary"
                type="button"
                disabled={!invite.valid || acceptInvite.isPending}
                onClick={() => acceptInvite.mutate()}
              >
                {acceptInvite.isPending ? 'Activating...' : 'Accept invite'}
              </button>
            </div>
            {acceptInvite.isError ? <div className="notice error">{acceptInvite.error instanceof Error ? acceptInvite.error.message : 'Accept failed'}</div> : null}
          </>
        ) : null}
      </section>
    </PublicDemoShell>
  );
}

export function LoginPage() {
  const [searchParams] = useSearchParams();
  const setupToken = searchParams.get('setup');
  const loginEmailParam = searchParams.get('email') ?? '';
  const activationComplete = searchParams.get('activated') === '1';
  const [email, setEmail] = React.useState(loginEmailParam);
  const [password, setPassword] = React.useState('');
  const [error, setError] = React.useState<string | null>(null);
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
    if (canManageRiskPolicy(actor)) {
      navigate('/configurations', { replace: true });
      return;
    }
    if (actor.demo === true) {
      navigate(pathForConnectView('sources'), { replace: true });
      return;
    }
    navigate('/exposure', { replace: true });
  }, [navigate]);

  React.useEffect(() => {
    setEmail(loginEmailParam);
  }, [loginEmailParam]);

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
      return api.setupPassword(setupToken, password);
    },
    onSuccess: () => {
      const nextParams = new URLSearchParams({ activated: '1' });
      if (loginEmailParam.trim()) {
        nextParams.set('email', loginEmailParam.trim());
      }
      navigate(`/login?${nextParams.toString()}`, { replace: true });
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

  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Log in to securityGrid</h1>
        <p>
          {setupToken
            ? 'Set a password for your tenant workspace. After saving it, return to the login screen and sign in with your email and new password.'
            : 'Use your email and password to access your tenant workspace or the platform console.'}
        </p>
        {!setupToken && activationComplete && (
          <div className="notice success" role="status">
            Password created successfully. Sign in with your email and new password to continue.
          </div>
        )}
        {!setupToken && (
          <form className="auth-token-form dev-token-form" onSubmit={submitLogin}>
            <label>Email or username<input type="text" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
            <label>Password<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
            <button className="btn btn-primary" type="submit" disabled={loginMutation.isPending || !email.trim() || !password.trim()}>
              {loginMutation.isPending ? 'Signing in...' : 'Sign in'}
            </button>
          </form>
        )}
        {!setupToken && SHARED_LOCALHOST_LOGIN_HINTS_ENABLED && (
          <div className="notice success" aria-label="Shared localhost credentials">
            Localhost shared login:
            {' '}platform owner <strong>platform.owner@localhost</strong> / <strong>LocalDevPlatform123!</strong>
            {' '}and tenant admin <strong>admin</strong> / <strong>admin</strong>.
          </div>
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
    clearStoredAuthToken();
    setHasStoredToken(false);
    navigate('/login', { replace: true });
  }, [navigate]);

  return (
    <main className={compact ? 'public-demo-shell compact' : 'public-demo-shell'}>
      <nav className="public-demo-nav">
        <Link to="/demo" className="public-demo-brand"><span className="brand-mark">SG</span><strong>securityGrid</strong></Link>
        <div className="public-demo-links">
          <a href="/demo#products">Products</a>
          <a href="/demo#solutions">Solutions</a>
          <a href="/demo#use-cases">Use cases</a>
          <a href="/demo#workflows">Workflows</a>
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
