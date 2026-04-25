import React from 'react';
import { Navigate, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import type { InventoryViewKey } from './features/inventory/types';
import type { AppTab, ConnectRouteView, VulnerabilityIntelRouteView } from './app/routes';
import {
  activeTabForPath,
  buildLegacyCompatiblePath,
  normalizeConnectRouteView,
  normalizeInventoryRouteView,
  normalizeOperationsRouteView,
  pathForConnectView,
  pathForInventoryView,
  pathForOperationsView,
  pathForTab,
  pathForVulnRepoView,
  titleForTab
} from './app/routes';
import { ActorProvider } from './features/auth/provider';
import './styles/index.css';
import './styles/finding-detail.css';

const DashboardPage = React.lazy(async () => ({
  default: (await import('./pages/DashboardPage')).DashboardPage
}));
const FindingsPage = React.lazy(async () => ({
  default: (await import('./pages/FindingsPage')).FindingsPage
}));
const FindingDetailPage = React.lazy(async () => ({
  default: (await import('./pages/FindingDetailPage')).FindingDetailPage
}));
const OperationalDashboardPage = React.lazy(async () => ({
  default: (await import('./pages/OperationalDashboardPage')).OperationalDashboardPage
}));
const VulnRepoDashboardPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoDashboardPage')).VulnRepoDashboardPage
}));
const VulnRepoVulnerabilitiesPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoVulnerabilitiesPage')).VulnRepoVulnerabilitiesPage
}));
const VulnRepoOrgCvePage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoOrgCvePage')).VulnRepoOrgCvePage
}));
const VulnRepoCveAssetsPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoCveAssetsPage')).VulnRepoCveAssetsPage
}));
const VulnRepoCveSoftwarePage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoCveSoftwarePage')).VulnRepoCveSoftwarePage
}));
const VulnRepoSoftwareAssetsPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoSoftwareAssetsPage')).VulnRepoSoftwareAssetsPage
}));
const HostAssetDetailPage = React.lazy(async () => ({
  default: (await import('./pages/HostAssetDetailPage')).HostAssetDetailPage
}));
const InventoryPage = React.lazy(async () => ({
  default: (await import('./pages/InventoryPage')).InventoryPage
}));
const InventoryComponentViewsPage = React.lazy(async () => ({
  default: (await import('./pages/InventoryComponentViewsPage')).InventoryComponentViewsPage
}));
const InventoryOverviewPage = React.lazy(async () => ({
  default: (await import('./pages/InventoryOverviewPage')).InventoryOverviewPage
}));
const SoftwareIdentitiesPage = React.lazy(async () => ({
  default: (await import('./pages/SoftwareIdentitiesPage')).SoftwareIdentitiesPage
}));
const EolPage = React.lazy(async () => ({
  default: (await import('./pages/EolPage')).EolPage
}));
const ConnectPage = React.lazy(async () => ({
  default: (await import('./pages/ConnectPage')).ConnectPage
}));
const ConfigurationsPage = React.lazy(async () => ({
  default: (await import('./pages/ConfigurationsPage')).ConfigurationsPage
}));

type Theme = 'light' | 'dark';

const THEME_STORAGE_KEY = 'scoutai-theme';
const PRIMARY_NAV_TABS: AppTab[] = [
  'dashboard',
  'findings',
  'operations',
  'vuln-repo',
  'inventory',
  'end-of-life'
];
const BOTTOM_NAV_TABS: AppTab[] = ['connect', 'configurations'];
const INVENTORY_FLYOUT_GROUPS: Array<{ title: string; items: Array<{ key: InventoryViewKey; label: string }> }> = [
  {
    title: 'Summary',
    items: [
      { key: 'overview', label: 'Overview' },
      { key: 'software-identities', label: 'Software Identities' }
    ]
  },
  {
    title: 'Applications',
    items: [
      { key: 'sbom', label: 'Applications' }
    ]
  },
  {
    title: 'Infrastructure',
    items: [
      { key: 'hosts', label: 'Hosts' }
    ]
  },
  {
    title: 'Cloud',
    items: [
      { key: 'container-images', label: 'Container Images' }
    ]
  }
];
const OPERATIONS_NAV_ITEMS = [
  { key: 'pipeline', label: 'Pipeline' },
  { key: 'platform-health', label: 'Platform Health' }
] as const;
const VULN_REPO_NAV_ITEMS: Array<{ key: VulnerabilityIntelRouteView; label: string }> = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'org-cves', label: 'Unified Records' },
  { key: 'vulnerabilities', label: 'Intelligence' },
];

function getInitialTheme(): Theme {
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  if (saved === 'light' || saved === 'dark') {
    return saved;
  }
  return 'dark';
}

function TabIcon({ tab }: { tab: AppTab }) {
  if (tab === 'dashboard') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <rect x="3" y="3" width="7" height="7" rx="1.5" />
        <rect x="14" y="3" width="7" height="5" rx="1.5" />
        <rect x="3" y="14" width="7" height="7" rx="1.5" />
        <rect x="14" y="10" width="7" height="11" rx="1.5" />
      </svg>
    );
  }
  if (tab === 'vuln-repo') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M6 4.5h9.8L19.5 8v11.5H6z" />
        <path d="M15.8 4.5V8h3.7" />
        <path d="M9 12h7M9 15.5h7" />
      </svg>
    );
  }
  if (tab === 'findings') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M5 5h14v14H5z" />
        <path d="M8 9h8M8 12h8M8 15h5" />
      </svg>
    );
  }
  if (tab === 'inventory') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <rect x="4" y="4" width="16" height="6" rx="1.5" />
        <rect x="4" y="14" width="16" height="6" rx="1.5" />
        <path d="M7.5 7h.01M7.5 17h.01" />
        <path d="M11 7h6M11 17h6" />
      </svg>
    );
  }
  if (tab === 'end-of-life') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="8.5" />
        <path d="M12 7v5" />
        <circle cx="12" cy="16" r="0.8" fill="currentColor" />
      </svg>
    );
  }
  if (tab === 'configurations') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <path d="M12 3.5v3" />
        <path d="M12 17.5v3" />
        <path d="M3.5 12h3" />
        <path d="M17.5 12h3" />
        <circle cx="12" cy="12" r="3.2" />
        <path d="m5.6 5.6 2.1 2.1" />
        <path d="m16.3 16.3 2.1 2.1" />
        <path d="m18.4 5.6-2.1 2.1" />
        <path d="m7.7 16.3-2.1 2.1" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 3.5v9.2" />
      <path d="m8 9 4 4 4-4" />
      <path d="M6 15.8v3A1.2 1.2 0 0 0 7.2 20h9.6a1.2 1.2 0 0 0 1.2-1.2v-3" />
      <path d="M4 20h16" />
    </svg>
  );
}

function SunIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2v2M12 20v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M2 12h2M20 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42" />
    </svg>
  );
}

function MoonIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
    </svg>
  );
}

function LegacyQueryRedirect() {
  const location = useLocation();
  const navigate = useNavigate();

  React.useEffect(() => {
    if (location.pathname !== '/') {
      return;
    }
    const nextPath = buildLegacyCompatiblePath(location.search);
    if (nextPath && nextPath !== `${location.pathname}${location.search}`) {
      navigate(nextPath, { replace: true });
    }
  }, [location.pathname, location.search, navigate]);

  return null;
}

function DashboardRoute() {
  const navigate = useNavigate();
  return <DashboardPage onViewEol={() => navigate('/end-of-life')} />;
}

function FindingsRoute() {
  const navigate = useNavigate();
  return (
    <FindingsPage
      onOpenCveWorkbench={(vulnerabilityId) => navigate(pathForVulnRepoView('org-cves', vulnerabilityId))}
    />
  );
}

function FindingDetailRoute() {
  const params = useParams<{ displayId?: string }>();
  const displayId = params.displayId ? decodeURIComponent(params.displayId) : null;
  if (!displayId) {
    return <Navigate to="/findings" replace />;
  }
  return <FindingDetailPage />;
}

function OperationsRoute() {
  const params = useParams<{ operationsView?: string }>();
  const location = useLocation();
  return <OperationalDashboardPage selectedView={normalizeOperationsRouteView(params.operationsView)} redirectSearch={location.search} />;
}

function inventoryManageSoftwareRedirectPath(search: string): string {
  const nextParams = new URLSearchParams(search);
  const domain = (nextParams.get('domain') ?? '').trim().toUpperCase();
  const tab = domain === 'CORRELATION'
    ? 'quality-correlation'
    : domain === 'EOL'
      ? 'quality-eol'
      : domain === 'VEX'
        ? 'quality-vex'
        : 'quality-normalization';

  nextParams.delete('domain');
  nextParams.set('inventoryTabs', tab);
  nextParams.set('inventoryActiveTab', tab);
  const nextSearch = nextParams.toString();
  return `/inventory${nextSearch ? `?${nextSearch}` : ''}`;
}

function LegacyVulnerabilityIntelVulnerabilitiesRoute() {
  const location = useLocation();
  return <Navigate to={`${pathForVulnRepoView('vulnerabilities')}${location.search}`} replace />;
}

function LegacyVulnerabilityIntelWorkbenchRoute() {
  const location = useLocation();
  const params = useParams<{ cveId?: string }>();
  return <Navigate to={`${pathForVulnRepoView('org-cves', params.cveId)}${location.search}`} replace />;
}

function VulnRepoDashboardRoute() {
  return <VulnRepoDashboardPage />;
}

function VulnRepoWorkbenchRoute() {
  const navigate = useNavigate();
  const location = useLocation();
  const params = useParams<{ cveId?: string }>();
  const hasOpenedDirectRecordRef = React.useRef(false);
  const returnTo = typeof location.state === 'object' && location.state && 'returnTo' in location.state
    ? String((location.state as { returnTo?: string }).returnTo ?? '').trim()
    : '';
  return (
    <VulnRepoOrgCvePage
      initialCveId={params.cveId}
      returnTo={returnTo || undefined}
      onSelectedCveChange={(cveId) => {
        if (cveId) {
          hasOpenedDirectRecordRef.current = true;
          if (params.cveId !== cveId) {
            navigate(pathForVulnRepoView('org-cves', cveId), { replace: true });
          }
          return;
        }
        if (params.cveId && hasOpenedDirectRecordRef.current) {
          navigate(pathForVulnRepoView('org-cves'), { replace: true });
        }
      }}
    />
  );
}

function VulnRepoHostAssetRoute() {
  const params = useParams<{ assetId?: string }>();
  const assetId = params.assetId ? decodeURIComponent(params.assetId) : null;

  if (!assetId) {
    return <Navigate to={pathForVulnRepoView('dashboard')} replace />;
  }

  return <HostAssetDetailPage assetId={assetId} />;
}

function InventoryHostAssetRoute() {
  const params = useParams<{ assetId?: string }>();
  const assetId = params.assetId ? decodeURIComponent(params.assetId) : null;

  if (!assetId) {
    return <Navigate to={pathForInventoryView('hosts')} replace />;
  }

  return <HostAssetDetailPage assetId={assetId} />;
}

function InventoryRoute() {
  const params = useParams<{ inventoryView?: string }>();
  const location = useLocation();
  const selectedView = normalizeInventoryRouteView(params.inventoryView);
  if (selectedView === 'overview') {
    return <InventoryOverviewPage />;
  }
  if (selectedView === 'software-identities') {
    return <SoftwareIdentitiesPage />;
  }
  if (selectedView === 'manage-software') {
    return <Navigate to={inventoryManageSoftwareRedirectPath(location.search)} replace />;
  }
  if (selectedView === 'hosts') {
    return <InventoryPage selectedView={selectedView} />;
  }
  return <InventoryComponentViewsPage selectedView={selectedView} />;
}

function ConnectRoute() {
  const navigate = useNavigate();
  const params = useParams<{ connectView?: string }>();
  return (
    <ConnectPage
      initialView={normalizeConnectRouteView(params.connectView)}
      onViewChange={(view: ConnectRouteView) => navigate(pathForConnectView(view), { replace: true })}
    />
  );
}

function routeLoadingFallback() {
  return (
    <div className="page-grid">
      <section className="panel">
        <div className="notice">Loading page...</div>
      </section>
    </div>
  );
}

export default function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const [theme, setTheme] = React.useState<Theme>(() => getInitialTheme());
  const [navOpen, setNavOpen] = React.useState(false);
  const [inventoryFlyoutOpen, setInventoryFlyoutOpen] = React.useState(false);
  const [operationsFlyoutOpen, setOperationsFlyoutOpen] = React.useState(false);
  const inventoryFlyoutTimer = React.useRef<number | null>(null);
  const operationsFlyoutTimer = React.useRef<number | null>(null);

  const activeTab = activeTabForPath(location.pathname);
  const activeTitle = titleForTab(activeTab);
  const pathSegments = location.pathname.split('/').filter(Boolean);
  const activeInventoryView = normalizeInventoryRouteView(pathSegments[1]);
  const activeOperationsView = normalizeOperationsRouteView(pathSegments[1]);
  const vulnRepoSegment = location.pathname.startsWith('/vuln-repo')
    ? pathSegments[1]
    : null;
  const activeVulnRepoView = vulnRepoSegment === 'vulnerabilities'
    ? 'vulnerabilities'
    : vulnRepoSegment === 'org-cves'
      ? 'org-cves'
      : 'dashboard';
  React.useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  React.useEffect(() => {
    setNavOpen(false);
  }, [location.pathname]);


  React.useEffect(() => () => {
    if (inventoryFlyoutTimer.current != null) {
      window.clearTimeout(inventoryFlyoutTimer.current);
    }
    if (operationsFlyoutTimer.current != null) {
      window.clearTimeout(operationsFlyoutTimer.current);
    }
  }, []);

  const openInventoryFlyout = (): void => {
    if (inventoryFlyoutTimer.current != null) {
      window.clearTimeout(inventoryFlyoutTimer.current);
      inventoryFlyoutTimer.current = null;
    }
    setInventoryFlyoutOpen(true);
  };

  const closeInventoryFlyoutWithDelay = (): void => {
    if (inventoryFlyoutTimer.current != null) {
      window.clearTimeout(inventoryFlyoutTimer.current);
    }
    inventoryFlyoutTimer.current = window.setTimeout(() => {
      setInventoryFlyoutOpen(false);
      inventoryFlyoutTimer.current = null;
    }, 180);
  };

  const openOperationsFlyout = (): void => {
    if (operationsFlyoutTimer.current != null) {
      window.clearTimeout(operationsFlyoutTimer.current);
      operationsFlyoutTimer.current = null;
    }
    setOperationsFlyoutOpen(true);
  };

  const closeOperationsFlyoutWithDelay = (): void => {
    if (operationsFlyoutTimer.current != null) {
      window.clearTimeout(operationsFlyoutTimer.current);
    }
    operationsFlyoutTimer.current = window.setTimeout(() => {
      setOperationsFlyoutOpen(false);
      operationsFlyoutTimer.current = null;
    }, 180);
  };

  const navigateToTab = (tab: AppTab): void => {
    navigate(pathForTab(tab));
    if (tab !== 'inventory') {
      setInventoryFlyoutOpen(false);
    }
    if (tab !== 'operations') {
      setOperationsFlyoutOpen(false);
    }
  };

  const renderNavButton = (tab: AppTab): React.ReactNode => (
    <button
      key={tab}
      className={activeTab === tab ? 'nav-btn active' : 'nav-btn'}
      onClick={() => navigateToTab(tab)}
    >
      <span className="nav-icon">
        <TabIcon tab={tab} />
      </span>
      <span className="nav-label">{titleForTab(tab)}</span>
    </button>
  );

  return (
    <ActorProvider>
      <LegacyQueryRedirect />
      <div className="app-shell">
        <aside className={navOpen ? 'sidebar open' : 'sidebar'}>
          <div className="brand-block compact">
            <div className="brand-mark">SA</div>
            <div className="brand">Scout.ai</div>
          </div>

          <div className="nav-main-section">
            {PRIMARY_NAV_TABS.map((tab) => {
              if (tab === 'operations') {
                return (
                  <div
                    key={tab}
                    className="operations-nav-wrap"
                    onMouseEnter={openOperationsFlyout}
                    onMouseLeave={closeOperationsFlyoutWithDelay}
                  >
                    <button
                      className={activeTab === tab ? 'nav-btn active' : 'nav-btn'}
                      onClick={() => {
                        navigate(pathForOperationsView(activeOperationsView));
                        setOperationsFlyoutOpen((open) => !open);
                      }}
                    >
                      <span className="nav-icon">
                        <TabIcon tab="operations" />
                      </span>
                      <span className="nav-label">Operations</span>
                    </button>

                    {operationsFlyoutOpen && (
                      <div
                        className="operations-flyout"
                        onMouseEnter={openOperationsFlyout}
                        onMouseLeave={closeOperationsFlyoutWithDelay}
                      >
                        <div className="operations-flyout-header">
                          <span>Operations</span>
                          <span aria-hidden="true">→</span>
                        </div>
                        <div className="operations-flyout-items">
                          {OPERATIONS_NAV_ITEMS.map((item) => (
                            <button
                              key={item.key}
                              type="button"
                              className={activeOperationsView === item.key ? 'operations-flyout-item active' : 'operations-flyout-item'}
                              onClick={() => {
                                navigate(pathForOperationsView(item.key));
                                setOperationsFlyoutOpen(false);
                              }}
                            >
                              <span>{item.label}</span>
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              }
              if (tab !== 'inventory') {
                return renderNavButton(tab);
              }
              return (
                <div
                  key={tab}
                  className="inventory-nav-wrap"
                  onMouseEnter={openInventoryFlyout}
                  onMouseLeave={closeInventoryFlyoutWithDelay}
                >
                  {renderNavButton(tab)}
                  {inventoryFlyoutOpen && (
                    <div
                      className="inventory-flyout"
                      onMouseEnter={openInventoryFlyout}
                      onMouseLeave={closeInventoryFlyoutWithDelay}
                    >
                      <div className="inventory-flyout-header">
                        <span>Inventory</span>
                        <span aria-hidden="true">→</span>
                      </div>
                      <div className="inventory-flyout-scroll">
                        {INVENTORY_FLYOUT_GROUPS.map((group) => (
                          <div key={group.title} className="inventory-flyout-group">
                            <div className="inventory-flyout-group-title">{group.title}</div>
                            <div className="inventory-flyout-items">
                              {group.items.map((item) => (
                                <button
                                  key={item.key}
                                  type="button"
                                  className={activeInventoryView === item.key ? 'inventory-flyout-item active' : 'inventory-flyout-item'}
                                  onClick={() => {
                                    navigate(pathForInventoryView(item.key));
                                    setInventoryFlyoutOpen(false);
                                  }}
                                >
                                  <span>{item.label}</span>
                                </button>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          <div className="nav-bottom-section">
            {BOTTOM_NAV_TABS.map((tab) => renderNavButton(tab))}
          </div>
        </aside>

        <main className="content">
          <header className="topbar">
            <div className="topbar-copy">
              <div className="eyebrow">Enterprise Vulnerability Operations</div>
              <h1>{activeTitle}</h1>
            </div>
            <div className="topbar-actions">
              <button
                className="btn btn-secondary nav-toggle"
                onClick={() => setNavOpen((current) => !current)}
              >
                {navOpen ? 'Close Menu' : 'Menu'}
              </button>
              <button
                className="btn btn-secondary theme-icon-btn"
                onClick={() => setTheme((current) => (current === 'dark' ? 'light' : 'dark'))}
                aria-label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'}
                title={theme === 'dark' ? 'Light theme' : 'Dark theme'}
              >
                {theme === 'dark' ? <SunIcon /> : <MoonIcon />}
              </button>
            </div>
          </header>

          {activeTab === 'vuln-repo' && (
            <div className="section-tab-row">
              {VULN_REPO_NAV_ITEMS.map((item) => (
                <button
                  key={item.key}
                  type="button"
                  className={activeVulnRepoView === item.key ? 'section-tab-btn active' : 'section-tab-btn'}
                  onClick={() => navigate(pathForVulnRepoView(item.key))}
                >
                  {item.label}
                </button>
              ))}
            </div>
          )}

          <React.Suspense fallback={routeLoadingFallback()}>
            <Routes>
              <Route path="/" element={<DashboardRoute />} />
              <Route path="/findings/:displayId" element={<FindingDetailRoute />} />
              <Route path="/findings" element={<FindingsRoute />} />
              <Route path="/operations/:operationsView?" element={<OperationsRoute />} />
              <Route path="/vulnerability-intelligence" element={<LegacyVulnerabilityIntelVulnerabilitiesRoute />} />
              <Route path="/vulnerability-intelligence/vulnerabilities" element={<LegacyVulnerabilityIntelVulnerabilitiesRoute />} />
              <Route path="/vulnerability-intelligence/org-cves/:cveId?" element={<LegacyVulnerabilityIntelWorkbenchRoute />} />
              <Route path="/vuln-repo" element={<VulnRepoDashboardRoute />} />
              <Route path="/vuln-repo/vulnerabilities" element={<VulnRepoVulnerabilitiesPage />} />
              <Route path="/vuln-repo/software-assets" element={<VulnRepoSoftwareAssetsPage />} />
              <Route path="/vuln-repo/host-assets/:assetId" element={<VulnRepoHostAssetRoute />} />
              <Route path="/vuln-repo/org-cves/:cveId/assets" element={<VulnRepoCveAssetsPage />} />
              <Route path="/vuln-repo/org-cves/:cveId/software" element={<VulnRepoCveSoftwarePage />} />
              <Route path="/vuln-repo/org-cves/:cveId?" element={<VulnRepoWorkbenchRoute />} />
              <Route path="/inventory/hosts/:assetId" element={<InventoryHostAssetRoute />} />
              <Route path="/inventory/:inventoryView?" element={<InventoryRoute />} />
              <Route path="/end-of-life" element={<EolPage />} />
              <Route path="/connect/:connectView?" element={<ConnectRoute />} />
              <Route path="/configurations" element={<ConfigurationsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </React.Suspense>
        </main>

        {navOpen && <button type="button" className="mobile-nav-backdrop" onClick={() => setNavOpen(false)} aria-label="Close navigation" />}
      </div>
    </ActorProvider>
  );
}
