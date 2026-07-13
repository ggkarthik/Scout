import React from 'react';
import { Link, useLocation, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { pathForConnectView } from '../app/routes';
import { api, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken } from '../api/client';
import { getAuthContextQueryKey } from '../features/auth/queries';
import { canManageRiskPolicy } from '../features/auth/roles';
import type { ActorContext } from '../features/auth/types';
const TEST_PERSONAS_ENABLED = import.meta.env.VITE_ENABLE_TEST_PERSONAS === 'true';

const GRID_CARDS: Array<{
  id: string;
  variant: 'blue' | 'cyan' | 'purple' | 'orange';
  icon: string;
  title: string;
  desc: string;
  chips: string[];
  linkLabel?: string;
  comingSoon?: boolean;
}> = [
  {
    id: 'infra-grid',
    variant: 'blue',
    icon: '🖥️',
    title: 'Infrastructure Grid',
    desc: 'Full-spectrum vulnerability assessment across your on-premises and data-center footprint. Scout fingerprints every host, OS, and running service — no agent installation, no network disruption, no credentials required.',
    chips: ['Host Discovery', 'OS / Application Fingerprinting', 'Agentless', 'SLA Enforcement'],
    linkLabel: 'Explore Infrastructure Risk'
  },
  {
    id: 'cloud-grid',
    variant: 'cyan',
    icon: '☁️',
    title: 'Cloud Grid',
    desc: 'Discover and assess every cloud workload — EC2, containers, serverless, and managed services. Scout maps cloud-native attack paths and correlates findings with your live SBOM inventory, giving you context no cloud-native tool can match.',
    chips: ['Cloud Resources', 'Container Images', 'Critical prioritization'],
    linkLabel: 'Explore Cloud Security'
  },
  {
    id: 'bom-grid',
    variant: 'purple',
    icon: '📦',
    title: 'BOM Grid',
    desc: 'BOM Grid gives security teams a unified BOM control plane for applications, cloud workloads, and AI systems. Suppress false positives for organizations and prioritize real risk across applications, cloud, and AI.',
    chips: ['CycloneDX / SPDX', 'GitHub SBOM', 'EOL Tracking', 'Vendor Assertions'],
    linkLabel: 'Explore BOM Security Grid'
  },
  {
    id: 'ai-grid-card',
    variant: 'orange',
    icon: '🤖',
    title: 'AI Grid',
    desc: 'Discover, inventory, and secure every AI asset in your environment — LLM deployments, AI agents, MCP servers, vector databases, and fine-tuned models. Identify prompt injection risk, data leakage exposure, and over-privileged agent capabilities.',
    chips: ['AI Model Discovery', 'Agent Risk Scoring', 'MCP Surface Mapping', 'AI-BOM', 'LLM CVE Coverage'],
    comingSoon: true
  }
];

const INTEL_FEEDS: Array<{ icon: string; name: string; desc: string }> = [
  { icon: '🏛️', name: 'National Vulnerability Databases', desc: 'Continuously track CVEs, severity, weaknesses, and affected software.' },
  { icon: '🔥', name: 'Active Exploitation Catalogs', desc: 'Identify vulnerabilities confirmed to be exploited in the wild.' },
  { icon: '🐙', name: 'Open Source Ecosystem Advisories', desc: 'Monitor package-level advisories across major open source ecosystems.' },
  { icon: '📊', name: 'Exploit Likelihood Models', desc: 'Score CVEs by real-world weaponization probability.' },
  { icon: '📋', name: 'Vendor Applicability Guidance', desc: 'Use vendor guidance to suppress non-applicable findings with precision.' },
  { icon: '📅', name: 'Product Lifecycle Intelligence', desc: 'Track end-of-life and end-of-support timelines across your software inventory.' }
];

const AI_CAPABILITIES: Array<{ icon: string; name: string; desc: string }> = [
  { icon: '🤖', name: 'AI Model Discovery', desc: 'Discover every LLM, ML model, and fine-tuned deployment across cloud, code, and APIs.' },
  { icon: '🕸️', name: 'Agent Risk Mapping', desc: 'Map agent access, internet reach, and code execution risk before abuse.' },
  { icon: '🔌', name: 'MCP Surface Analysis', desc: 'Identify exposed MCP servers, tools, and sensitive system access.' },
  { icon: '🗄️', name: 'Vector DB Risk Scoring', desc: 'Assess RAG and vector data stores for sensitivity and access risk.' },
  { icon: '💉', name: 'Prompt Injection Detection', desc: 'Detect prompt injection, jailbreak, and indirect injection exposure.' },
  { icon: '📋', name: 'AI-BOM Generation', desc: 'Generate a complete AI inventory of models, frameworks, datasets, and dependencies.' }
];

function VisualPanel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="visual-panel">
      <div className="panel-header">
        <span className="panel-dot panel-dot--red" />
        <span className="panel-dot panel-dot--amber" />
        <span className="panel-dot panel-dot--green" />
        <span className="panel-title">{title}</span>
      </div>
      <div className="panel-body">{children}</div>
    </div>
  );
}

function FeatureList({ items }: { items: Array<{ title: string; body: string }> }) {
  return (
    <ul className="feature-list">
      {items.map((item) => (
        <li key={item.title} className="feature-item">
          <span className="feature-dot" aria-hidden="true" />
          <div>
            <div className="feature-item-title">{item.title}</div>
            <div className="feature-item-desc">{item.body}</div>
          </div>
        </li>
      ))}
    </ul>
  );
}

export function DemoLandingPage() {
  return (
    <PublicDemoShell>
      <section className="scout-hero">
        <div className="scout-hero-grid" aria-hidden="true" />
        <div className="scout-hero-glow scout-hero-glow--red" aria-hidden="true" />
        <div className="scout-hero-glow scout-hero-glow--cyan" aria-hidden="true" />
        <div className="scout-hero-content">
          <span className="scout-eyebrow">✦ Exposure Management Platform</span>
          <h1>See every threat. Secure every <span className="hero-accent">surface.</span></h1>
          <p>
            Scout delivers agentless vulnerability assessment across your entire infrastructure — Infra, Cloud,
            BOM, and AI. Powered by real-time intelligence feeds, AI-driven prioritization, and precision noise
            reduction for every security alert in your stack.
          </p>
          <div className="hero-actions">
            <Link className="btn btn-primary" to="/demo/request">Get a demo</Link>
            <a className="btn btn-outline" href="#platform">Explore the platform</a>
          </div>
          <div className="scout-stats" aria-label="Portfolio signals">
            {[
              ['4×', 'Faster Triage'],
              ['0', 'Agents Required'],
              ['< 24h', '0-Day Response']
            ].map(([label, value]) => (
              <div key={value} className="scout-stat">
                <strong>{label}</strong>
                <span>{value}</span>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section id="platform" className="sg-section">
        <div className="sg-section-heading centered">
          <span className="sg-eyebrow">The Platform</span>
          <h2>One platform. Four grids. Every attack surface covered.</h2>
          <p>
            Scout is an exposure management platform built on four grids — covering every attack surface from
            on-premises infrastructure to cloud workloads, open-source dependencies, and AI models — without a
            single agent deployed.
          </p>
        </div>
        <div className="grid-cards">
          {GRID_CARDS.map((card) => (
            <article key={card.id} id={card.id} className={`grid-card grid-card--${card.variant}`}>
              <div className="grid-card-icon" aria-hidden="true">{card.icon}</div>
              <span className={`badge badge--${card.variant}`}>{card.title.replace('Infrastructure', 'Infra')}</span>
              <h3 className="grid-card-title">{card.title}</h3>
              <p className="grid-card-desc">{card.desc}</p>
              <div className="grid-card-chips">
                {card.chips.map((chip) => <span key={chip} className="chip">{chip}</span>)}
              </div>
              {card.comingSoon ? (
                <div className="coming-soon-overlay">
                  <span className="coming-soon-tag">Coming Soon</span>
                  <p className="coming-soon-text">AI Grid is in active development.<br />Join the early access program.</p>
                  <Link className="btn btn-outline" to="/demo/request">Request early access</Link>
                </div>
              ) : (
                <a className="grid-card-link" href="#solutions">{card.linkLabel} →</a>
              )}
            </article>
          ))}
        </div>
      </section>

      <section id="intelligence" className="sg-section">
        <div className="sg-section-heading centered">
          <span className="sg-eyebrow">Vuln Intelligence Layer</span>
          <h2>One intelligence layer. Every source that matters.</h2>
        </div>
        <div className="intel-feeds">
          {INTEL_FEEDS.map((feed) => (
            <article key={feed.name} className="feed-card">
              <div className="feed-icon" aria-hidden="true">{feed.icon}</div>
              <div>
                <div className="feed-name">{feed.name}</div>
                <div className="feed-desc">{feed.desc}</div>
              </div>
            </article>
          ))}
        </div>
      </section>

      <section id="solutions" className="sg-section feature-section">
        <div className="feature-grid">
          <div className="feature-content">
            <span className="sg-eyebrow">Agentless Assessment</span>
            <h2>Agentless. No blind spots. Actionable.</h2>
            <FeatureList
              items={[
                { title: 'Zero deployment friction', body: 'No agent packages to maintain, no OS compatibility matrix to manage. Assessment begins the moment you connect to Scout.' },
                { title: 'OT and legacy safe', body: 'Passive fingerprinting protects fragile industrial and legacy systems that cannot tolerate agent installation or active scanning.' },
                { title: 'Continuous, not point-in-time', body: 'Scout maintains a live asset inventory that updates as your environment changes — new workloads are assessed automatically.' },
                { title: 'Prioritized, not just detected', body: 'Every finding arrives ranked by real-world exploitability and business impact, so teams fix what matters first instead of drowning in raw results.' }
              ]}
            />
          </div>
          <VisualPanel title="Scout — Asset Discovery">
            <div className="panel-body-header">
              <span className="panel-body-label">Live Inventory</span>
              <span className="badge badge--green">● Active</span>
            </div>
            <div className="risk-rows">
              {[
                ['🖥️', 'prod-web-01.corp', 'Host', 'blue'],
                ['☁️', 'i-0a3f8c29d41e', 'EC2', 'cyan'],
                ['📦', 'payment-service:v2.1', 'Container', 'purple'],
                ['🔧', 'legacy-erp-03', 'Legacy', 'orange'],
                ['☁️', 'api-gateway-prod', 'Lambda', 'cyan']
              ].map(([icon, name, tag, variant]) => (
                <div key={name} className="risk-row">
                  <span aria-hidden="true">{icon}</span>
                  <span className="risk-name">{name}</span>
                  <span className={`badge badge--${variant}`}>{tag}</span>
                  <span className="risk-status">✓ Assessed</span>
                </div>
              ))}
            </div>
            <div className="panel-summary">
              <span className="panel-summary-label">Coverage Summary</span>
              <div className="panel-summary-row">
                <span>1,247 assets discovered</span>
                <span className="panel-summary-good">100% agentless</span>
              </div>
            </div>
          </VisualPanel>
        </div>
      </section>

      <section id="ai-prioritization" className="sg-section feature-section alt">
        <div className="feature-grid reverse">
          <div className="feature-content">
            <span className="sg-eyebrow">AI-Powered Prioritization</span>
            <h2>Fix what matters. Ignore the rest.</h2>
            <FeatureList
              items={[
                { title: 'Contextual remediation guidance', body: 'AI-generated fix recommendations surfaced alongside each finding — patch version, workaround steps, and affected component context.' },
                { title: 'Single prioritized action queue', body: 'Every finding across infra, cloud, BOM, and AI collapses into one ranked queue, so teams always know what to fix next.' },
                { title: 'Scored beyond CVSS', body: 'The Scout Score weighs real-world exploitability, asset criticality, and business context — not just raw severity.' }
              ]}
            />
          </div>
          <VisualPanel title="Scout — AI Priority Queue">
            <div className="priority-header">
              <span>CVE</span>
              <span>CVSS</span>
              <span>EPSS</span>
              <span className="priority-header-score">Scout Score</span>
            </div>
            {[
              { cve: 'CVE-2024-3094', label: 'XZ Utils · RCE', cvss: '9.8', epss: '0.94', score: '9.4', highlight: true },
              { cve: 'CVE-2021-44228', label: 'Log4Shell · RCE', cvss: '10.0', epss: '0.97', score: '9.1', highlight: false },
              { cve: 'CVE-2023-44487', label: 'HTTP/2 Rapid Reset · DoS', cvss: '7.5', epss: '0.88', score: '8.2', highlight: false },
              { cve: 'CVE-2024-21626', label: 'runc · Container Escape', cvss: '8.6', epss: '0.76', score: '7.8', highlight: false },
              { cve: 'CVE-2022-22965', label: 'Spring4Shell · RCE', cvss: '9.8', epss: '0.61', score: '7.3', highlight: false }
            ].map(({ cve, label, cvss, epss, score, highlight }) => (
              <div key={cve} className={highlight ? 'priority-row priority-row--highlight' : 'priority-row'}>
                <div>
                  <div className="priority-cve">{cve}</div>
                  <div className="priority-label">{label}</div>
                </div>
                <span className="priority-metric">{cvss}</span>
                <span className="priority-metric">{epss}</span>
                <span className="priority-score">{score}</span>
              </div>
            ))}
            <div className="panel-summary-row panel-footer-row">
              <span>Scout Score weighs real-world context beyond CVSS</span>
              <span className="badge badge--red">● Live</span>
            </div>
          </VisualPanel>
        </div>
      </section>

      <section id="noise-reduction" className="sg-section feature-section">
        <div className="feature-grid">
          <div className="feature-content">
            <span className="sg-eyebrow">Noise Reduction</span>
            <h2>Fewer findings. No worries. Surface real risk.</h2>
            <FeatureList
              items={[
                { title: 'Accurate applicability assessment', body: "Confirms whether a vulnerability actually affects your environment — eliminating alerts that don't apply to you." },
                { title: 'Flexible suppression controls', body: 'Define rules to suppress known-safe findings with built-in expiration and audit trails.' },
                { title: 'Deduplication & auto-close', body: 'Findings are consolidated into a single actionable record and automatically closed when risk is resolved.' }
              ]}
            />
          </div>
          <VisualPanel title="Scout — Noise Reduction Engine">
            <div className="noise-comparison">
              <div>
                <div className="noise-col-label noise-col-label--bad">Before Scout</div>
                {['CVE-2023-44487 · HTTP/2', 'CVE-2023-2976 · Guava', 'CVE-2022-1471 · SnakeYAML', 'CVE-2023-34453 · snappy', 'CVE-2021-37136 · Netty'].map((item) => (
                  <div key={item} className="noise-item noise-item--bad">{item}</div>
                ))}
                <div className="noise-total noise-total--bad">4,812 raw findings</div>
              </div>
              <div>
                <div className="noise-col-label noise-col-label--good">After Scout</div>
                <div className="noise-item noise-item--good">CVE-2023-44487 · HTTP/2</div>
                {['CVE-2023-2976 — vendor: not affected', 'CVE-2022-1471 — version patched', 'CVE-2023-34453 — suppressed', 'CVE-2021-37136 — not applicable'].map((item) => (
                  <div key={item} className="noise-item noise-item--suppressed">{item}</div>
                ))}
                <div className="noise-total noise-total--good">187 actionable findings</div>
              </div>
            </div>
          </VisualPanel>
        </div>
      </section>

      <section id="zero-day" className="sg-section feature-section alt">
        <div className="feature-grid reverse">
          <div className="feature-content">
            <span className="sg-eyebrow">Zero-Day Management</span>
            <h2>When the world learns about it — you already know your exposure.</h2>
            <FeatureList
              items={[
                { title: 'Real-time KEV and NVD watch', body: 'The moment CISA adds a CVE to the KEV catalog or NVD publishes a new record, Scout re-scores every correlated finding in your environment.' },
                { title: 'Instant blast-radius analysis', body: 'Within minutes of disclosure, see every affected host, container, and cloud workload of a new 0-day disclosure — with asset criticality context included.' },
                { title: 'Automatic SLA escalation', body: 'KEV-listed CVEs automatically inherit critical SLA timelines and trigger immediate findings even outside scheduled scan windows.' },
                { title: 'EPSS-guided urgency scoring', body: 'EPSS scores refreshed daily separate the theoretical 0-days from those with active weaponization — so you respond to the right threat first.' }
              ]}
            />
          </div>
          <VisualPanel title="Scout — 0-Day Response Timeline">
            <div className="zeroday-timeline">
              {[
                ['T+0h', 'red', 'NVD publishes CVE-2024-XXXX', 'CVSS 9.8 · CRITICAL · RCE in widely-used library'],
                ['T+2m', 'orange', 'Scout ingests and correlates', '147 affected components matched across 3 grids'],
                ['T+4m', 'cyan', 'Blast radius computed', '89 hosts · 34 containers · 24 cloud workloads'],
                ['T+6m', 'purple', 'Findings created & SLAs set', 'Teams notified · ServiceNow incidents opened'],
                ['T+1h', 'green', 'CISA adds to KEV catalog', 'Scout auto-escalates priority · SLA shrinks to 24h']
              ].map(([time, color, title, sub]) => (
                <div key={time} className="zd-event">
                  <div className="zd-time">{time}</div>
                  <div className={`zd-dot zd-dot--${color}`} />
                  <div className="zd-info">
                    <div className="zd-title">{title}</div>
                    <div className="zd-sub">{sub}</div>
                  </div>
                </div>
              ))}
            </div>
          </VisualPanel>
        </div>
      </section>

      <div className="callout-strip">
        <div className="callout-inner">
          <div className="callout-text">
            <div className="callout-title">Your scanners find everything.<br />Scout tells you what to fix first.</div>
            <div className="callout-sub">One platform. Every grid. Zero agents required.</div>
          </div>
          <Link className="btn btn-primary" to="/demo/request">Get a demo →</Link>
        </div>
      </div>

      <section id="app-risk" className="sg-section feature-section alt">
        <div className="feature-grid">
          <div className="feature-content">
            <span className="sg-eyebrow">Application Risk Intelligence</span>
            <h2>Know which apps are one CVE away from a breach.</h2>
            <FeatureList
              items={[
                { title: 'Composite application risk score', body: 'Per-application risk score combining open critical findings, KEV exposure, owner assignment gaps, and EOL component density.' },
                { title: 'Owner-aware triage queues', body: 'Findings automatically routed to application owners via ownership rules — with escalation paths when ownership is undefined.' },
                { title: 'Executive risk register', body: 'Board-ready risk summaries with application-level exposure ranking, SLA compliance rates, and remediation velocity trends.' }
              ]}
            />
          </div>
          <VisualPanel title="Scout — Application Risk Register">
            <div className="panel-body-label">Highest Risk Applications</div>
            <div className="app-risk-rows">
              {[
                ['payment-processor', 9.5],
                ['auth-service', 8.7],
                ['order-api', 7.2],
                ['public-portal', 6.5],
                ['analytics-pipeline', 4.8]
              ].map(([name, score]) => (
                <div key={name} className="app-risk-row">
                  <span className="app-risk-name">{name}</span>
                  <div className="app-risk-bar-wrap">
                    <div className="app-risk-bar" style={{ width: `${(Number(score) / 10) * 100}%` }} />
                  </div>
                  <span className="app-risk-score">{score}</span>
                </div>
              ))}
            </div>
            <div className="panel-summary-row panel-footer-row">
              <span>14 Critical CVEs</span>
              <span>3 SLA Breached</span>
            </div>
          </VisualPanel>
        </div>
      </section>

      <section id="ai-grid" className="ai-teaser">
        <div className="ai-teaser-card">
          <div className="ai-teaser-badges">
            <span className="badge badge--orange">Coming Soon</span>
            <span className="ai-teaser-meta">Early Access Q3 2026</span>
          </div>
          <h2 className="ai-teaser-title">AI Grid</h2>
          <p className="ai-teaser-copy">
            AI is your fastest-growing attack surface — and your least visible. Scout&rsquo;s AI Grid discovers,
            inventories, and secures every AI asset — from LLM APIs and autonomous agents to vector databases —
            bringing the rigor of the Infra, Cloud, and BOM Grids to a surface traditional tools can&rsquo;t see.
          </p>
          <div className="ai-capabilities">
            {AI_CAPABILITIES.map((cap) => (
              <div key={cap.name} className="ai-cap">
                <div className="ai-cap-icon" aria-hidden="true">{cap.icon}</div>
                <div className="ai-cap-name">{cap.name}</div>
                <div className="ai-cap-desc">{cap.desc}</div>
              </div>
            ))}
          </div>
          <div className="ai-teaser-cta">
            <Link className="btn btn-primary" to="/demo/request">Request early access</Link>
            <span>Be among the first to secure your AI attack surface.</span>
          </div>
        </div>
      </section>

      <section id="cta" className="sg-section cta-section">
        <div className="cta-box">
          <span className="badge badge--red">Ready to see Scout?</span>
          <h2>Eliminate blind trust in your security posture.</h2>
          <p>
            See how Scout maps your full attack surface, prioritizes what actually matters, and cuts vulnerability
            noise — in a live demo tailored to your environment.
          </p>
          <div className="cta-actions">
            <Link className="btn btn-primary" to="/demo/request">Schedule a demo</Link>
            <Link className="btn btn-outline" to="/login">Talk to an expert</Link>
          </div>
          <div className="cta-trust">
            <span>✓ No agents required</span>
            <span>✓ Up and running in minutes</span>
            <span>✓ Works with your existing scanners</span>
          </div>
        </div>
      </section>

      <footer className="scout-footer">
        <div className="footer-grid">
          <div className="footer-brand">
            <div className="footer-brand-name">
              <span className="brand-mark">S</span>
              Scout
            </div>
            <p className="footer-tagline">
              See every threat. Secure every surface. Agentless vulnerability intelligence across Infra, Cloud,
              BOM, and AI.
            </p>
          </div>
          <div className="footer-col">
            <div className="footer-col-title">Platform</div>
            <a href="#infra-grid">Infra Grid</a>
            <a href="#cloud-grid">Cloud Grid</a>
            <a href="#bom-grid">BOM Grid</a>
            <a href="#ai-grid">AI Grid</a>
            <a href="#intelligence">Vuln Intelligence</a>
          </div>
          <div className="footer-col">
            <div className="footer-col-title">Solutions</div>
            <a href="#solutions">Agentless Assessment</a>
            <a href="#zero-day">0-Day Response</a>
            <a href="#noise-reduction">Noise Reduction</a>
            <a href="#ai-prioritization">AI Prioritization</a>
            <a href="#app-risk">Executive Reporting</a>
          </div>
          <div className="footer-col">
            <div className="footer-col-title">Get started</div>
            <Link to="/demo/request">Request a demo</Link>
            <Link to="/login">Log in</Link>
          </div>
        </div>
        <div className="footer-bottom">
          <span>© 2026 Scout Security, Inc. All rights reserved.</span>
          <span>Built for the AI-attack era.</span>
        </div>
      </footer>
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
          <div className="panel-actions">
            <Link to="/demo">Back to overview</Link>
            <Link to="/login">Already have access? Log in</Link>
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
        <div className="panel-actions panel-actions--stacked">
          <Link to="/demo">Back to overview</Link>
          <Link to="/demo/request">Need access? Request a demo</Link>
        </div>
        {!setupToken && activationComplete && (
          <div className="notice success" role="status">
            Password created successfully. Sign in with your email and new password to continue.
          </div>
        )}
        {!setupToken && (
          <form className="auth-token-form dev-token-form" onSubmit={submitLogin}>
            <label>Email<input type="text" value={email} onChange={(event) => setEmail(event.target.value)} /></label>
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
        <div className="public-demo-nav-inner">
          <Link to="/demo" className="public-demo-brand">
            <span className="brand-mark">S</span>
            <strong>Scout</strong>
          </Link>
          <div className="public-demo-links">
            <a href="/demo#platform">Platform</a>
            <a href="/demo#intelligence">Intelligence</a>
            <a href="/demo#solutions">Solutions</a>
            <a href="/demo#ai-grid">AI Grid</a>
            <Link className="nav-link-cta" to="/demo/request">Request demo</Link>
            <Link className="nav-link-outline" to="/login">Log in</Link>
            {hasStoredToken && (
              <button className="btn btn-secondary" type="button" onClick={logout}>
                Log out
              </button>
            )}
          </div>
        </div>
      </nav>
      {children}
    </main>
  );
}
