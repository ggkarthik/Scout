import React from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery } from '@tanstack/react-query';
import { api, setStoredAuthToken } from '../api/client';

const IDP_LOGIN_URL = import.meta.env.VITE_IDP_LOGIN_URL ?? '';

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
  const inviteQuery = useQuery({
    queryKey: ['demo-invite', token],
    queryFn: () => api.validateDemoInvite(token),
    enabled: token.length > 0
  });
  const acceptInvite = useMutation({
    mutationFn: () => api.acceptDemoInvite(token)
  });

  const invite = inviteQuery.data;
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
            <p>{invite.message}</p>
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
                {acceptInvite.isPending ? 'Accepting...' : 'Accept invite'}
              </button>
              <Link className="btn btn-secondary" to={`/login?invite=${encodeURIComponent(token)}`}>Continue to login</Link>
            </div>
            {acceptInvite.isSuccess && <div className="notice success">Invite accepted. Continue to login.</div>}
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
  const [token, setToken] = React.useState('');
  const navigate = useNavigate();

  const startHostedLogin = () => {
    const returnTo = `${window.location.origin}/`;
    const invitePart = invite ? `&invite=${encodeURIComponent(invite)}` : '';
    window.location.href = IDP_LOGIN_URL
      ? `${IDP_LOGIN_URL}${IDP_LOGIN_URL.includes('?') ? '&' : '?'}returnTo=${encodeURIComponent(returnTo)}${invitePart}`
      : '/demo';
  };

  const submitDevToken = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setStoredAuthToken(token);
    navigate('/');
  };

  return (
    <PublicDemoShell compact>
      <section className="public-form-panel">
        <h1>Log in to Scout.ai</h1>
        <p>Customer demo access uses the hosted identity provider configured for this environment.</p>
        <button className="btn btn-primary" type="button" onClick={startHostedLogin}>
          Continue with hosted login
        </button>
        {import.meta.env.VITE_SHOW_TOKEN_LOGIN === 'true' && (
          <form className="auth-token-form dev-token-form" onSubmit={submitDevToken}>
            <label>Development bearer token<input type="password" value={token} onChange={(event) => setToken(event.target.value)} /></label>
            <button className="btn btn-secondary" type="submit" disabled={!token.trim()}>Use token</button>
          </form>
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
  return (
    <main className={compact ? 'public-demo-shell compact' : 'public-demo-shell'}>
      <nav className="public-demo-nav">
        <Link to="/demo" className="public-demo-brand"><span className="brand-mark">SA</span><strong>Scout.ai</strong></Link>
        <div className="public-demo-links">
          <Link to="/demo/request">Request demo</Link>
          <Link to="/login">Log in</Link>
        </div>
      </nav>
      {children}
    </main>
  );
}
