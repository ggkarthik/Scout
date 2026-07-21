import React from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Navigate, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import { PerformanceInstrumentation } from './lib/performanceMonitoring';
import type { InventoryViewKey } from './features/inventory/types';
import type { AdminRouteView, AppTab, ConfigurationsRouteView, ConnectRouteView, VulnerabilityIntelRouteView } from './app/routes';
import {
  activeTabForPath,
  buildLegacyCompatiblePath,
  normalizeAdminRouteView,
  normalizeConfigurationsRouteView,
  normalizeConnectRouteView,
  normalizeInventoryRouteView,
  normalizeOperationsRouteView,
  normalizePlatformRouteView,
  pathForAdminView,
  pathForConfigurationsView,
  pathForConnectView,
  pathForInventoryView,
  pathForPlatformView,
  pathForTab,
  pathForVulnRepoView,
  titleForTab
} from './app/routes';
import { api, clearStoredAuthToken, getStoredAuthToken, setStoredAuthToken, type TestPersona } from './api/client';
import { ActorContextState, useActor } from './features/auth/context';
import { useActorQuery } from './features/auth/queries';
import type { ActorContext } from './features/auth/types';
import {
  canAccessPlatformConsole,
  canManageInventorySources,
  canManageRiskPolicy,
  canManageTenant,
  canManageUsers,
  canRunSecurityWorkflow,
  canViewReadOnly
} from './features/auth/roles';
import './styles/index.css';
import './styles/finding-detail.css';

const ExposureDashboardPage = React.lazy(async () => ({
  default: (await import('./pages/ExposureDashboardPage')).ExposureDashboardPage
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
const PlatformVulnIntelDetailPage = React.lazy(async () => ({
  default: (await import('./pages/PlatformVulnIntelDetailPage')).PlatformVulnIntelDetailPage
}));
const VulnRepoVulnerabilitiesPage = React.lazy(async () => ({
  default: (await import('./pages/VulnRepoVulnerabilitiesPage')).VulnRepoVulnerabilitiesPage
}));
const CampaignsPage = React.lazy(async () => ({
  default: (await import('./pages/CampaignsPage')).CampaignsPage
}));
const CampaignDetailPage = React.lazy(async () => ({
  default: (await import('./features/campaigns/CampaignDetailPage')).CampaignDetailPage
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
const BomInventoryPage = React.lazy(async () => ({
  default: (await import('./pages/BomInventoryPage')).BomInventoryPage
}));
const ApplicationsDashboard = React.lazy(async () => ({
  default: (await import('./features/inventory/ApplicationsDashboard')).ApplicationsDashboard
}));
// MOCKS — replace with real page imports when implementing
const BomComponents = React.lazy(async () => ({
  default: (await import('./features/inventory/BomComponents')).BomComponents
}));
const SoftwareIdentityDetailPage = React.lazy(async () => ({
  default: (await import('./pages/SoftwareIdentityDetailPage')).SoftwareIdentityDetailPage
}));
const ConnectPage = React.lazy(async () => ({
  default: (await import('./pages/ConnectPage')).ConnectPage
}));
const ConfigurationsPage = React.lazy(async () => ({
  default: (await import('./pages/ConfigurationsPage')).ConfigurationsPage
}));
const UserManagementPage = React.lazy(async () => ({
  default: (await import('./pages/UserManagementPage')).UserManagementPage
}));
const PlatformConsolePage = React.lazy(async () => ({
  default: (await import('./pages/PlatformConsolePage')).PlatformConsolePage
}));
const AuthorizedWorkspacesPage = React.lazy(async () => ({
  default: (await import('./pages/AuthorizedWorkspacesPage')).AuthorizedWorkspacesPage
}));
const DemoLandingPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoLandingPage
}));
const DemoRequestPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoRequestPage
}));
const DemoRequestSuccessPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoRequestSuccessPage
}));
const DemoInvitePage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoInvitePage
}));
const TenantInvitePage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).TenantInvitePage
}));
const LoginPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).LoginPage
}));
const DemoExpiredPage = React.lazy(async () => ({
  default: (await import('./pages/DemoPublicPages')).DemoExpiredPage
}));

type Theme = 'light' | 'dark';
type TestPersonaMode = 'backend' | 'preview';
type ActiveTestPersona = {
  mode: TestPersonaMode;
  persona: TestPersona;
};

type TestPersonaControls = {
  enabled: boolean;
  personas: TestPersona[];
  activePersona: ActiveTestPersona | null;
  loading: boolean;
  error: string | null;
  loadPersonas: () => void;
  impersonateBackend: (persona: TestPersona) => void;
  previewPersona: (persona: TestPersona) => void;
  resetPersona: () => void;
};

const THEME_STORAGE_KEY = 'scoutai-theme';
const TEST_PERSONAS_ENABLED = import.meta.env.VITE_ENABLE_TEST_PERSONAS === 'true';
const TEST_PERSONA_PREVIOUS_TOKEN_KEY = 'vulnwatch.testPersona.previousToken';
const EMPTY_TEST_PERSONA_CONTROLS: TestPersonaControls = {
  enabled: false,
  personas: [],
  activePersona: null,
  loading: false,
  error: null,
  loadPersonas: () => undefined,
  impersonateBackend: () => undefined,
  previewPersona: () => undefined,
  resetPersona: () => undefined
};
const TestPersonaControlsState = React.createContext<TestPersonaControls>(EMPTY_TEST_PERSONA_CONTROLS);
const BOTTOM_NAV_TABS: AppTab[] = [];
const INVENTORY_PILL_ORDER: Array<{ key: InventoryViewKey; label: string; countKey?: 'hosts' | 'software' | 'containerImages' | 'applications' | 'bomInventory' }> = [
  { key: 'overview', label: 'Overview' },
  { key: 'hosts', label: 'Hosts', countKey: 'hosts' },
  { key: 'software-identities', label: 'Software Entities', countKey: 'software' },
  { key: 'container-images', label: 'Container Images', countKey: 'containerImages' },
  { key: 'sbom', label: 'Applications', countKey: 'applications' },
  { key: 'bom-components', label: 'BOM Components', countKey: 'bomInventory' },
  { key: 'bom-inventory', label: 'BOM Inventory', countKey: 'bomInventory' }
];
const VULN_REPO_NAV_ITEMS: Array<{ key: VulnerabilityIntelRouteView; label: string }> = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'vulnerabilities', label: 'Intelligence' },
];
const ADMIN_PILL_ORDER: Array<{ key: AdminRouteView; label: string }> = [
  { key: 'users', label: 'Users' },
  { key: 'invites', label: 'Invites' },
  { key: 'roles', label: 'Roles & Permissions' },
  { key: 'service-accounts', label: 'Service Accounts' },
  { key: 'audit', label: 'Audit' }
];
const CONFIGURATIONS_PILL_ORDER: Array<{ key: ConfigurationsRouteView; label: string }> = [
  { key: 'sla', label: 'SLA & Remediation' },
  { key: 'triage', label: 'S.AI Prioritization' },
  { key: 'automation', label: 'Workflow Automation' },
  { key: 'ownership', label: 'Ownership' },
  { key: 'findings-score', label: 'Findings Score' },
  { key: 'suppress', label: 'Suppression Rules' },
  { key: 'auto-findings', label: 'Auto Investigation & Findings' }
];

function getInitialTheme(): Theme {
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  if (saved === 'light' || saved === 'dark') {
    return saved;
  }
  return 'dark';
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

function SettingsIcon() {
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M9.7 3.4h4.6l.5 2.4c.5.2 1 .4 1.4.8l2.3-.8 2.3 4-1.8 1.6v1.2l1.8 1.6-2.3 4-2.3-.8c-.4.3-.9.6-1.4.8l-.5 2.4H9.7l-.5-2.4c-.5-.2-1-.5-1.4-.8l-2.3.8-2.3-4L5 12.6v-1.2L3.2 9.8l2.3-4 2.3.8c.4-.3.9-.6 1.4-.8z" />
      <circle cx="12" cy="12" r="3" />
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

function defaultPathForActor(actor: ActorContext | null): string {
  if (!actor) {
    return '/exposure';
  }
  if (actor.roles.some((role) => role.replace(/^ROLE_/, '') === 'PLATFORM_OWNER') && actor.platformScope) {
    return '/platform/tenants';
  }
  if (canManageRiskPolicy(actor)) {
    return '/configurations';
  }
  return '/exposure';
}

function HomeRoute() {
  const actor = useActor();
  return <Navigate to={defaultPathForActor(actor)} replace />;
}

function ExposureDashboardRoute() {
  return <ExposureDashboardPage />;
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
  const actor = useActor();
  const isPlatformScope = actor?.platformScope ?? false;
  const platformScopeOwner = canAccessPlatformConsole(actor) && isPlatformScope;

  if (platformScopeOwner) {
    return (
      <Navigate
        to={pathForPlatformView('eol')}
        replace
        state={{ platformMessage: 'Operations is no longer part of the platform view. Use EOL from the platform console.' }}
      />
    );
  }

  return <OperationalDashboardPage selectedView={normalizeOperationsRouteView(params.operationsView)} redirectSearch={location.search} />;
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

function SoftwareIdentityDetailRoute() {
  const params = useParams<{ softwareIdentityId?: string }>();
  const softwareIdentityId = params.softwareIdentityId ? decodeURIComponent(params.softwareIdentityId) : null;

  if (!softwareIdentityId) {
    return <Navigate to={pathForInventoryView('software-identities')} replace />;
  }

  return <SoftwareIdentityDetailPage softwareIdentityId={softwareIdentityId} />;
}

function InventoryRoute() {
  const params = useParams<{ inventoryView?: string }>();
  const selectedView = normalizeInventoryRouteView(params.inventoryView);
  if (selectedView === 'overview') {
    return <InventoryOverviewPage />;
  }
  if (selectedView === 'software-identities') {
    return <SoftwareIdentitiesPage />;
  }
  if (selectedView === 'hosts') {
    return <InventoryPage selectedView={selectedView} />;
  }
  if (selectedView === 'sbom') {
    return <ApplicationsDashboard />;
  }
  if (selectedView === 'bom-components') {
    return <BomComponents />;
  }
  if (selectedView === 'bom-inventory') {
    return <BomInventoryPage />;
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

function EndOfLifeRoute() {
  const actor = useActor();
  const isPlatformScope = actor?.platformScope ?? false;
  const platformScopeOwner = canAccessPlatformConsole(actor) && isPlatformScope;

  if (platformScopeOwner) {
    return <Navigate to={pathForPlatformView('eol')} replace />;
  }

  return <Navigate to={pathForTab('exposure')} replace />;
}

function PlatformRoute() {
  const actor = useActor();
  const params = useParams<{ platformView?: string }>();
  if (!canAccessPlatformConsole(actor)) {
    return (
      <section className="panel">
        <div className="notice error" role="alert">
          Platform console access requires the Platform Owner role.
        </div>
      </section>
    );
  }
  return <PlatformConsolePage selectedView={normalizePlatformRouteView(params.platformView)} />;
}

function AuthorizedWorkspacesRoute() {
  const actor = useActor();
  if (!actor?.roles.includes('PLATFORM_OWNER')) {
    return <Navigate to="/exposure" replace />;
  }
  return <AuthorizedWorkspacesPage />;
}

function AdminRoute() {
  const actor = useActor();
  if (!canManageTenant(actor)) {
    return <Navigate to="/exposure" replace />;
  }
  return <UserManagementPage />;
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

function actorFromPersona(persona: TestPersona): ActorContext {
  const platformOwner = persona.roles.some((role) => role.replace(/^ROLE_/, '') === 'PLATFORM_OWNER');
  return {
    creator: platformOwner,
    principal: persona.subject,
    userId: persona.subject,
    tenantId: platformOwner ? null : persona.tenantSlug ? `preview:${persona.tenantSlug}` : null,
    tenantName: platformOwner ? null : persona.tenantName,
    roles: persona.roles,
    allowedTenants: !platformOwner && persona.tenantSlug && persona.tenantName ? [{
      id: `preview:${persona.tenantSlug}`,
      name: persona.tenantName,
      slug: persona.tenantSlug,
      role: persona.roles[0] ?? 'SECURITY_ANALYST'
    }] : [],
    platformScope: platformOwner,
    actingAsPlatformOwner: false,
    sensitiveActionConfirmationRequired: false,
    planCode: null,
    demo: false,
    demoExpiresAt: null,
    demoDaysRemaining: null,
    demoCapabilities: null,
    demoUsage: null
  };
}

function savePreviousAuthTokenForPersona(): void {
  if (typeof window === 'undefined' || window.localStorage.getItem(TEST_PERSONA_PREVIOUS_TOKEN_KEY) != null) {
    return;
  }
  window.localStorage.setItem(TEST_PERSONA_PREVIOUS_TOKEN_KEY, getStoredAuthToken());
}

function restorePreviousAuthTokenForPersona(): void {
  if (typeof window === 'undefined') {
    clearStoredAuthToken();
    return;
  }
  const previous = window.localStorage.getItem(TEST_PERSONA_PREVIOUS_TOKEN_KEY);
  window.localStorage.removeItem(TEST_PERSONA_PREVIOUS_TOKEN_KEY);
  if (previous && previous.trim().length > 0) {
    setStoredAuthToken(previous);
  } else {
    clearStoredAuthToken();
  }
}

function AuthSessionBoundary({ children }: { children: React.ReactNode }) {
  const location = useLocation();
  const actorQuery = useActorQuery();
  const [personas, setPersonas] = React.useState<TestPersona[]>([]);
  const [personaLoading, setPersonaLoading] = React.useState(false);
  const [personaError, setPersonaError] = React.useState<string | null>(null);
  const [activePersona, setActivePersona] = React.useState<ActiveTestPersona | null>(null);
  const [previewActor, setPreviewActor] = React.useState<ActorContext | null>(null);

  const loadPersonas = React.useCallback(() => {
    if (!TEST_PERSONAS_ENABLED || personaLoading || personas.length > 0) {
      return;
    }
    setPersonaLoading(true);
    setPersonaError(null);
    api.listTestPersonas()
      .then(setPersonas)
      .catch((error) => setPersonaError(error instanceof Error ? error.message : 'Failed to load test personas'))
      .finally(() => setPersonaLoading(false));
  }, [personaLoading, personas.length]);

  const impersonateBackend = React.useCallback((persona: TestPersona) => {
    savePreviousAuthTokenForPersona();
    setPersonaLoading(true);
    setPersonaError(null);
    api.issueTestPersonaToken(persona.key)
      .then((response) => {
        setStoredAuthToken(response.token);
        setPreviewActor(null);
        setActivePersona({ mode: 'backend', persona: response.persona });
        return actorQuery.refetch();
      })
      .catch((error) => setPersonaError(error instanceof Error ? error.message : 'Failed to issue test persona token'))
      .finally(() => setPersonaLoading(false));
  }, [actorQuery]);

  const previewPersona = React.useCallback((persona: TestPersona) => {
    setPreviewActor(actorFromPersona(persona));
    setActivePersona({ mode: 'preview', persona });
    setPersonaError(null);
  }, []);

  const resetPersona = React.useCallback(() => {
    restorePreviousAuthTokenForPersona();
    setPreviewActor(null);
    setActivePersona(null);
    setPersonaError(null);
    void actorQuery.refetch();
  }, [actorQuery]);

  const personaControls = React.useMemo<TestPersonaControls>(() => ({
    enabled: TEST_PERSONAS_ENABLED,
    personas,
    activePersona,
    loading: personaLoading,
    error: personaError,
    loadPersonas,
    impersonateBackend,
    previewPersona,
    resetPersona
  }), [activePersona, impersonateBackend, loadPersonas, personaError, personaLoading, personas, previewPersona, resetPersona]);

  if (actorQuery.isLoading || actorQuery.isFetching && !actorQuery.data) {
    return routeLoadingFallback();
  }

  if (actorQuery.isError || !actorQuery.data) {
    if (location.pathname === '/') {
      return <DemoLandingPage />;
    }
    return <Navigate to="/login" replace />;
  }

  return (
    <TestPersonaControlsState.Provider value={personaControls}>
      <ActorContextState.Provider value={previewActor ?? actorQuery.data}>
        {children}
      </ActorContextState.Provider>
    </TestPersonaControlsState.Provider>
  );
}

function AppShell() {
  const actor = useActor();
  const testPersonas = React.useContext(TestPersonaControlsState);
  const queryClient = useQueryClient();
  const location = useLocation();
  const navigate = useNavigate();
  const [theme, setTheme] = React.useState<Theme>(() => getInitialTheme());
  const [navOpen, setNavOpen] = React.useState(false);
  const [settingsMenuOpen, setSettingsMenuOpen] = React.useState(false);
  const [personaDialogOpen, setPersonaDialogOpen] = React.useState(false);
  const [inventoryNavExpanded, setInventoryNavExpanded] = React.useState(true);
  const [adminNavExpanded, setAdminNavExpanded] = React.useState(true);
  const [configurationsNavExpanded, setConfigurationsNavExpanded] = React.useState(true);

  const activeTab = activeTabForPath(location.pathname);
  const pathSegments = location.pathname.split('/').filter(Boolean);
  const activeInventoryView = normalizeInventoryRouteView(pathSegments[1]);
  const activeAdminView = normalizeAdminRouteView(pathSegments[1]);
  const activeConfigurationsView = normalizeConfigurationsRouteView(pathSegments[1]);
  const vulnRepoSegment = location.pathname.startsWith('/vuln-repo')
    ? pathSegments[1]
    : null;
  const activeVulnRepoView = vulnRepoSegment === 'vulnerabilities'
    ? 'vulnerabilities'
    : vulnRepoSegment === 'campaigns'
      ? 'campaigns'
    : vulnRepoSegment === 'org-cves'
      ? 'org-cves'
      : 'dashboard';
  const isPlatformScope = actor?.platformScope ?? false;
  const platformScopeOwner = canAccessPlatformConsole(actor) && isPlatformScope;
  const visibleVulnRepoNavItems = React.useMemo(
    () => VULN_REPO_NAV_ITEMS,
    []
  );
  const visiblePrimaryNavTabs = React.useMemo(() => {
    if (platformScopeOwner) {
      return ['vuln-repo', 'connect', 'platform', 'end-of-life'] satisfies AppTab[];
    }
    if (canManageTenant(actor)) {
      return ['exposure', 'findings', 'vuln-repo', 'campaigns', 'inventory', 'connect', 'admin', 'configurations'] satisfies AppTab[];
    }
    const tabs: AppTab[] = ['exposure'];
    if (canRunSecurityWorkflow(actor) || canViewReadOnly(actor)) {
      tabs.push('findings', 'vuln-repo', 'campaigns', 'inventory');
    }
    if (canAccessPlatformConsole(actor)) {
      tabs.push('operations');
    }
    if (canManageInventorySources(actor)) {
      tabs.push('connect');
    }
    if (canManageTenant(actor) || canManageUsers(actor)) {
      tabs.push('admin');
    }
    if (canManageRiskPolicy(actor)) {
      tabs.push('configurations');
    }
    return tabs;
  }, [actor, platformScopeOwner]);
  const inventoryAssetsQuery = useQuery({
    queryKey: ['inventory-nav-assets'],
    queryFn: api.listAssets,
    enabled: activeTab === 'inventory' && !platformScopeOwner
  });
  const inventorySoftwareQuery = useQuery({
    queryKey: ['inventory-nav-software-identities'],
    queryFn: () => api.listSoftwareIdentities({ page: 0, size: 1 }),
    enabled: activeTab === 'inventory' && !platformScopeOwner
  });
  const inventoryBomQuery = useQuery({
    queryKey: ['inventory-nav-bom-inventory'],
    queryFn: () => api.listBomInventory(0, 1),
    enabled: activeTab === 'inventory' && !platformScopeOwner
  });
  const inventoryPillCounts = React.useMemo(() => {
    const assets = inventoryAssetsQuery.data ?? [];
    return {
      hosts: assets.filter((asset) => asset.type.toUpperCase() === 'HOST').length,
      applications: assets.filter((asset) => asset.type.toUpperCase() === 'APPLICATION').length,
      containerImages: assets.filter((asset) => asset.type.toUpperCase() === 'CONTAINER_IMAGE').length,
      software: inventorySoftwareQuery.data?.totalElements ?? 0,
      bomInventory: inventoryBomQuery.data?.length ?? 0
    };
  }, [inventoryAssetsQuery.data, inventoryBomQuery.data?.length, inventorySoftwareQuery.data?.totalElements]);
  const visibleInventoryPills = React.useMemo(
    () => INVENTORY_PILL_ORDER.filter((item) => !item.countKey || inventoryPillCounts[item.countKey] > 0),
    [inventoryPillCounts]
  );

  React.useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  React.useEffect(() => {
    setNavOpen(false);
    setSettingsMenuOpen(false);
    setPersonaDialogOpen(false);
  }, [location.pathname]);

  React.useEffect(() => {
    if (personaDialogOpen && testPersonas.enabled && testPersonas.personas.length === 0 && !testPersonas.loading) {
      testPersonas.loadPersonas();
    }
  }, [personaDialogOpen, testPersonas]);

  const navigateToTab = (tab: AppTab): void => {
    navigate(pathForTab(tab));
  };

  const displayRole = actor?.roles?.[0]?.replace(/^ROLE_/, '').replace(/_/g, ' ') ?? 'No role';
  const tenantLabel = actor?.tenantName ?? (canAccessPlatformConsole(actor) ? 'Platform' : 'No tenant');
  const actorLabel = actor?.principal ?? actor?.userId ?? 'Unknown user';
  const isDemoTenant = actor?.demo === true;
  const activePersonaLabel = testPersonas.activePersona
    ? `Impersonating: ${testPersonas.activePersona.persona.label}`
    : null;

  const handleLogout = React.useCallback(() => {
    clearStoredAuthToken();
    queryClient.clear();
    navigate('/login', { replace: true });
  }, [navigate, queryClient]);

  const openPersonaDialog = (): void => {
    setSettingsMenuOpen(false);
    setPersonaDialogOpen(true);
  };

  const selectBackendPersona = (persona: TestPersona): void => {
    testPersonas.impersonateBackend(persona);
    setPersonaDialogOpen(false);
  };

  const selectPreviewPersona = (persona: TestPersona): void => {
    testPersonas.previewPersona(persona);
    setPersonaDialogOpen(false);
  };

  const resetPersona = (): void => {
    testPersonas.resetPersona();
    setPersonaDialogOpen(false);
  };

  const pageTitle = React.useMemo(() => {
    if (activeTab === 'exposure') return 'Exposure Dashboard';
    if (activeTab === 'admin') return 'Tenant Administration';
    if (activeTab === 'connect') return 'Connectors';
    if (activeTab === 'configurations') return 'Configurations';
    if (activeTab === 'platform') return 'Tenant Management';
    return titleForTab(activeTab);
  }, [activeTab]);

  const tenantScopedTabs = new Set<AppTab>(['exposure', 'findings', 'inventory', 'admin', 'configurations']);
  if (actor && isPlatformScope && tenantScopedTabs.has(activeTab)) {
    return <Navigate to={pathForPlatformView('tenants')} replace state={{ platformMessage: 'Select a tenant to continue.' }} />;
  }
  if (actor && isPlatformScope && location.pathname.startsWith('/vuln-repo/campaigns')) {
    return <Navigate to={pathForPlatformView('tenants')} replace state={{ platformMessage: 'Select a tenant to continue.' }} />;
  }
  if (
    actor
    && platformScopeOwner
    && (location.pathname.startsWith('/vuln-repo/org-cves')
      || location.pathname.startsWith('/vuln-repo/software-assets')
      || location.pathname.startsWith('/vuln-repo/host-assets'))
  ) {
    return <Navigate to={pathForVulnRepoView('dashboard')} replace />;
  }

  const renderNavButton = (tab: AppTab): React.ReactNode => (
    <button
      key={tab}
      className={activeTab === tab ? 'nav-btn active' : 'nav-btn'}
      onClick={() => navigateToTab(tab)}
    >
      <span className="nav-label">{titleForTab(tab)}</span>
    </button>
  );

  const renderExpandableNavButton = (
    tab: AppTab,
    expanded: boolean,
    onToggleExpanded: () => void,
    subItems: Array<{ key: string; label: string }>,
    isSubItemActive: (key: string) => boolean,
    onSubItemClick: (key: string) => void
  ): React.ReactNode => (
    <React.Fragment key={tab}>
      <button
        className={activeTab === tab ? 'nav-btn active' : 'nav-btn'}
        onClick={() => navigateToTab(tab)}
      >
        <span className="nav-label">{titleForTab(tab)}</span>
        <span
          className="nav-expand-toggle"
          role="button"
          tabIndex={0}
          aria-label={expanded ? `Collapse ${titleForTab(tab)} sections` : `Expand ${titleForTab(tab)} sections`}
          onClick={(event) => {
            event.stopPropagation();
            onToggleExpanded();
          }}
          onKeyDown={(event) => {
            if (event.key === 'Enter' || event.key === ' ') {
              event.preventDefault();
              event.stopPropagation();
              onToggleExpanded();
            }
          }}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            {expanded ? <path d="M6 15l6-6 6 6" /> : <path d="M6 9l6 6 6-6" />}
          </svg>
        </span>
      </button>
      {expanded && (
        <div className="nav-sub-list">
          {subItems.map((item) => (
            <button
              key={item.key}
              type="button"
              className={isSubItemActive(item.key) ? 'nav-sub-btn active' : 'nav-sub-btn'}
              onClick={() => onSubItemClick(item.key)}
            >
              {item.label}
            </button>
          ))}
        </div>
      )}
    </React.Fragment>
  );

  return (
    <>
      <LegacyQueryRedirect />
      <div className="app-shell">
        <aside className={navOpen ? 'sidebar open' : 'sidebar'}>
          <div className="brand-block compact">
            <div className="brand-mark">S</div>
            <div className="brand">Scout</div>
          </div>

          <div className="nav-main-section">
            {visiblePrimaryNavTabs.map((tab) => {
              if (tab === 'inventory') {
                return renderExpandableNavButton(
                  tab,
                  inventoryNavExpanded,
                  () => setInventoryNavExpanded((current) => !current),
                  visibleInventoryPills,
                  (key) => activeTab === 'inventory' && activeInventoryView === key,
                  (key) => navigate(pathForInventoryView(key as InventoryViewKey))
                );
              }
              if (tab === 'admin') {
                return renderExpandableNavButton(
                  tab,
                  adminNavExpanded,
                  () => setAdminNavExpanded((current) => !current),
                  ADMIN_PILL_ORDER,
                  (key) => activeTab === 'admin' && activeAdminView === key,
                  (key) => navigate(pathForAdminView(key as AdminRouteView))
                );
              }
              if (tab === 'configurations') {
                return renderExpandableNavButton(
                  tab,
                  configurationsNavExpanded,
                  () => setConfigurationsNavExpanded((current) => !current),
                  CONFIGURATIONS_PILL_ORDER,
                  (key) => activeTab === 'configurations' && activeConfigurationsView === key,
                  (key) => navigate(pathForConfigurationsView(key as ConfigurationsRouteView))
                );
              }
              return renderNavButton(tab);
            })}
          </div>

          {platformScopeOwner && (
            <div className="nav-ops-section">
              <button
                className={location.pathname.startsWith('/platform/operations') ? 'nav-btn active' : 'nav-btn'}
                onClick={() => navigate(pathForPlatformView('operations'))}
              >
                <span className="nav-label">Operations</span>
              </button>
            </div>
          )}

          <div className="nav-bottom-section">
            {BOTTOM_NAV_TABS.map((tab) => renderNavButton(tab))}
          </div>
        </aside>

        <main className="content">
          <header className="topbar">
            <div className="topbar-copy">
              <div className="eyebrow">Enterprise Vulnerability Operations</div>
              <h1>{pageTitle}</h1>
            </div>
            <div className="topbar-actions">
              <div className="tenant-context-pill" title={`${actorLabel} · ${displayRole}`}>
                <span>{tenantLabel}</span>
                <small>{displayRole}</small>
              </div>
              {isDemoTenant && (
                <div className="tenant-context-pill demo-status-pill" title={actor.demoExpiresAt ? `Expires ${actor.demoExpiresAt}` : 'Demo workspace'}>
                  <span>Demo</span>
                  <small>{actor.demoDaysRemaining == null ? 'Limited access' : `${actor.demoDaysRemaining} days left`}</small>
                </div>
              )}
              {activePersonaLabel && (
                <div className={`tenant-context-pill test-persona-pill ${testPersonas.activePersona?.mode === 'preview' ? 'preview' : ''}`}>
                  <span>{activePersonaLabel}</span>
                  <small>{testPersonas.activePersona?.mode === 'preview' ? 'UI preview only' : 'Backend-backed'}</small>
                </div>
              )}
              {testPersonas.activePersona?.mode === 'preview' && (
                <div className="test-persona-inline-warning" role="status">
                  UI preview only - backend authorization still uses the current real session.
                </div>
              )}
              <button
                className="btn btn-secondary nav-toggle"
                onClick={() => setNavOpen((current) => !current)}
              >
                {navOpen ? 'Close Menu' : 'Menu'}
              </button>
              <div className="settings-menu-wrap">
                <button
                  className={settingsMenuOpen || ['admin', 'platform'].includes(activeTab) ? 'btn btn-secondary theme-icon-btn active' : 'btn btn-secondary theme-icon-btn'}
                  onClick={() => setSettingsMenuOpen((open) => !open)}
                  aria-label="Open settings menu"
                  aria-expanded={settingsMenuOpen}
                  title="Settings"
                >
                  <SettingsIcon />
                </button>
                {settingsMenuOpen && (
                  <div className="settings-menu" role="menu">
                    <div className="settings-menu-header">
                      <div className="brand-mark settings-menu-mark">S</div>
                      <strong>Settings</strong>
                    </div>
                    {testPersonas.enabled && (
                      <button
                        type="button"
                        className="settings-menu-item"
                        role="menuitem"
                        onClick={openPersonaDialog}
                      >
                        <span>Impersonate User</span>
                        <small>Open non-production test personas</small>
                      </button>
                    )}
                    {actor?.roles.includes('PLATFORM_OWNER') && (
                      <button
                        type="button"
                        className="settings-menu-item"
                        role="menuitem"
                        onClick={() => {
                          setSettingsMenuOpen(false);
                          navigate('/authorized-workspaces');
                        }}
                      >
                        <span>Authorized Workspaces</span>
                        <small>Open only tenant-approved access</small>
                      </button>
                    )}
                    <button
                      type="button"
                      className="settings-menu-item settings-menu-item-logout"
                      role="menuitem"
                      onClick={handleLogout}
                    >
                      <span>Log out</span>
                    </button>
                  </div>
                )}
              </div>
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
              {visibleVulnRepoNavItems.map((item) => (
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
              <Route path="/exposure" element={<ExposureDashboardRoute />} />
              <Route path="/" element={<HomeRoute />} />
              <Route path="/findings/:displayId" element={<FindingDetailRoute />} />
              <Route path="/findings" element={<FindingsRoute />} />
              <Route path="/operations/:operationsView?" element={<OperationsRoute />} />
              <Route path="/vulnerability-intelligence" element={<LegacyVulnerabilityIntelVulnerabilitiesRoute />} />
              <Route path="/vulnerability-intelligence/vulnerabilities" element={<LegacyVulnerabilityIntelVulnerabilitiesRoute />} />
              <Route path="/vulnerability-intelligence/org-cves/:cveId?" element={<LegacyVulnerabilityIntelWorkbenchRoute />} />
              <Route path="/vuln-repo" element={<VulnRepoDashboardRoute />} />
              <Route path="/vuln-repo/intel/:externalId" element={<PlatformVulnIntelDetailPage />} />
              <Route path="/vuln-repo/vulnerabilities" element={<VulnRepoVulnerabilitiesPage />} />
              <Route path="/vuln-repo/campaigns" element={<CampaignsPage />} />
              <Route path="/vuln-repo/campaigns/:id" element={<CampaignDetailPage />} />
              <Route path="/vuln-repo/software-assets" element={<VulnRepoSoftwareAssetsPage />} />
              <Route path="/vuln-repo/host-assets/:assetId" element={<VulnRepoHostAssetRoute />} />
              <Route path="/vuln-repo/org-cves/:cveId/assets" element={<VulnRepoCveAssetsPage />} />
              <Route path="/vuln-repo/org-cves/:cveId/software" element={<VulnRepoCveSoftwarePage />} />
              <Route path="/vuln-repo/org-cves/:cveId?" element={<VulnRepoWorkbenchRoute />} />
              <Route path="/inventory/hosts/:assetId" element={<InventoryHostAssetRoute />} />
              <Route path="/inventory/software-identities/:softwareIdentityId" element={<SoftwareIdentityDetailRoute />} />
              <Route path="/inventory/:inventoryView?" element={<InventoryRoute />} />
              <Route path="/end-of-life" element={<EndOfLifeRoute />} />
              <Route path="/connect/:connectView?" element={<ConnectRoute />} />
              <Route path="/admin/:adminView?" element={<AdminRoute />} />
              <Route path="/platform/:platformView?" element={<PlatformRoute />} />
              <Route path="/authorized-workspaces" element={<AuthorizedWorkspacesRoute />} />
              <Route path="/configurations/:configView?" element={<ConfigurationsPage />} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </React.Suspense>
        </main>

        {navOpen && <button type="button" className="mobile-nav-backdrop" onClick={() => setNavOpen(false)} aria-label="Close navigation" />}
      </div>
      {personaDialogOpen && (
        <div className="modal-backdrop" role="presentation" onClick={() => setPersonaDialogOpen(false)}>
          <section
            className="test-persona-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="test-persona-dialog-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="test-persona-dialog-header">
              <div>
                <h2 id="test-persona-dialog-title">Non-production test personas</h2>
                <p>Choose a persona for backend-backed authorization, or preview role-gated UI only.</p>
              </div>
              <button
                type="button"
                className="btn btn-secondary theme-icon-btn"
                onClick={() => setPersonaDialogOpen(false)}
                aria-label="Close persona dialog"
                title="Close"
              >
                X
              </button>
            </div>
            {testPersonas.loading && testPersonas.personas.length === 0 && (
              <div className="test-persona-empty">Loading personas...</div>
            )}
            {testPersonas.error && (
              <div className="test-persona-warning" role="alert">{testPersonas.error}</div>
            )}
            <div className="test-persona-list">
              {testPersonas.personas.map((persona) => (
                <div className="test-persona-row" key={persona.key}>
                  <div>
                    <strong>{persona.label}</strong>
                    <small>{persona.tenantName ?? 'Platform'} · {persona.roles.map((role) => role.replace(/^ROLE_/, '').replace(/_/g, ' ')).join(', ')}</small>
                  </div>
                  <div className="test-persona-actions">
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => selectBackendPersona(persona)}
                      disabled={testPersonas.loading}
                    >
                      Use
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => selectPreviewPersona(persona)}
                      disabled={testPersonas.loading}
                    >
                      Preview
                    </button>
                  </div>
                </div>
              ))}
            </div>
            {testPersonas.activePersona?.mode === 'preview' && (
              <div className="test-persona-warning">
                UI preview only - backend authorization still uses the current real session.
              </div>
            )}
            {testPersonas.activePersona && (
              <div className="test-persona-dialog-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={resetPersona}
                >
                  Reset to real user
                </button>
              </div>
            )}
          </section>
        </div>
      )}
    </>
  );
}

export default function App() {
  return (
    <React.Suspense fallback={routeLoadingFallback()}>
      <PerformanceInstrumentation />
      <Routes>
        <Route path="/demo" element={<DemoLandingPage />} />
        <Route path="/demo/request" element={<DemoRequestPage />} />
        <Route path="/demo/request/success" element={<DemoRequestSuccessPage />} />
        <Route path="/demo/expired" element={<DemoExpiredPage />} />
        <Route path="/invite/:token" element={<DemoInvitePage />} />
        <Route path="/tenant-invite/:token" element={<TenantInvitePage />} />
        <Route path="/login" element={<LoginPage />} />
        <Route path="/*" element={
          <AuthSessionBoundary>
            <AppShell />
          </AuthSessionBoundary>
        } />
      </Routes>
    </React.Suspense>
  );
}
