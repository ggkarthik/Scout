import React from 'react';
import { DashboardPage } from './pages/DashboardPage';
import { ConnectPage } from './pages/ConnectPage';
import { ConfigurationsPage } from './pages/ConfigurationsPage';
import { FindingsPage } from './pages/FindingsPage';
import { InventoryPage, InventoryViewKey } from './pages/InventoryPage';
import {
  OperationalDashboardPage,
  OPERATIONS_NAV_ITEMS,
  OperationsViewKey,
  normalizeOperationsView
} from './pages/OperationalDashboardPage';
import {
  VulnerabilityIntelDashboardPage,
  VulnerabilityIntelViewKey
} from './pages/VulnerabilityIntelDashboardPage';
import { VulnerabilityIntelOrgCvePage } from './pages/VulnerabilityIntelOrgCvePage';
import { EolPage } from './pages/EolPage';
import './styles.css';

type Tab =
  | 'dashboard'
  | 'findings'
  | 'operations'
  | 'vulnerability-intelligence'
  | 'inventory'
  | 'end-of-life'
  | 'connect'
  | 'configurations';
type Theme = 'light' | 'dark';
const THEME_STORAGE_KEY = 'scoutai-theme';

const tabs: { key: Tab; label: string; navLabel: string }[] = [
  { key: 'dashboard', label: 'Overview', navLabel: 'Overview' },
  { key: 'findings', label: 'Findings', navLabel: 'Findings' },
  { key: 'operations', label: 'Operational Dashboard', navLabel: 'Operations' },
  { key: 'vulnerability-intelligence', label: 'Vulnerability Intelligence', navLabel: 'Vuln Intel' },
  { key: 'inventory', label: 'Inventory', navLabel: 'Inventory' },
  { key: 'end-of-life', label: 'End-of-Life', navLabel: 'EOL' },
  { key: 'connect', label: 'Connect', navLabel: 'Connect' },
  { key: 'configurations', label: 'Configurations', navLabel: 'Config' }
];

const primaryNavTabs: Tab[] = ['dashboard', 'findings', 'operations', 'vulnerability-intelligence', 'inventory', 'end-of-life'];
const bottomNavTabs: Tab[] = ['connect', 'configurations'];

const INVENTORY_VIEW_QUERY_KEY = 'inventoryView';
const OPERATIONS_VIEW_QUERY_KEY = 'operationsView';
const VULN_INTEL_VIEW_QUERY_KEY = 'vulnIntelView';

const vulnerabilityIntelNavItems: Array<{ key: VulnerabilityIntelViewKey; label: string }> = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'vulnerabilities', label: 'Vulnerabilities' },
  { key: 'org-cves', label: 'CVE Assessment Workbench' }
];

type InventoryFlyoutGroup = {
  title: string;
  items: Array<{ key: InventoryViewKey; label: string }>;
};

const inventoryFlyoutGroups: InventoryFlyoutGroup[] = [
  {
    title: 'Imported Assets',
    items: [
      { key: 'imported-assets', label: 'Imported Assets' }
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
  },
  {
    title: 'Repositories',
    items: [
      { key: 'sbom', label: 'Repositories' }
    ]
  }
];

function TabIcon({ tab }: { tab: Tab }) {
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
  if (tab === 'vulnerability-intelligence') {
    return (
      <svg viewBox="0 0 24 24" aria-hidden="true">
        <circle cx="12" cy="12" r="8.5" />
        <path d="M12 7v5l3 2" />
        <path d="M7.2 16.4c1.3-1.3 3-2.1 4.8-2.1 1.9 0 3.6.8 4.8 2.1" />
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

function isTab(value: string | null): value is Tab {
  return tabs.some((tab) => tab.key === value);
}

function isInventoryView(value: string | null): value is InventoryViewKey {
  return inventoryFlyoutGroups.some((group) => group.items.some((item) => item.key === value));
}

function isOperationsView(value: string | null): value is OperationsViewKey {
  return OPERATIONS_NAV_ITEMS.some((item) => item.key === value);
}

function isVulnerabilityIntelView(value: string | null): value is VulnerabilityIntelViewKey {
  return vulnerabilityIntelNavItems.some((item) => item.key === value);
}

function getInitialTheme(): Theme {
  const saved = localStorage.getItem(THEME_STORAGE_KEY);
  if (saved === 'light' || saved === 'dark') {
    return saved;
  }
  return 'dark';
}

function readInitialRoute(): { tab: Tab } {
  const params = new URLSearchParams(window.location.search);
  const rawTab = params.get('tab');
  const rawInventoryView = params.get(INVENTORY_VIEW_QUERY_KEY);
  if (rawTab === 'ingestion' || rawTab === 'sources') {
    return { tab: 'connect' };
  }
  if (rawTab === 'configurations') {
    return { tab: 'configurations' };
  }
  if (rawTab === 'assets') {
    return { tab: 'inventory' };
  }
  return {
    tab: isTab(rawTab) ? rawTab : 'dashboard'
  };
}

function readInitialInventoryView(): InventoryViewKey {
  const fromQuery = new URLSearchParams(window.location.search).get(INVENTORY_VIEW_QUERY_KEY);
  if (fromQuery === 'host-review-queue' || fromQuery === 'host-details') {
    return 'hosts';
  }
  return isInventoryView(fromQuery) ? fromQuery : 'sbom';
}

function readInitialOperationsView(): OperationsViewKey {
  const fromQuery = new URLSearchParams(window.location.search).get(OPERATIONS_VIEW_QUERY_KEY);
  return normalizeOperationsView(fromQuery);
}

function readInitialVulnerabilityIntelView(): VulnerabilityIntelViewKey {
  const fromQuery = new URLSearchParams(window.location.search).get(VULN_INTEL_VIEW_QUERY_KEY);
  return isVulnerabilityIntelView(fromQuery) ? fromQuery : 'dashboard';
}

function updateTabInUrl(tab: Tab): void {
  const url = new URL(window.location.href);
  url.searchParams.set('tab', tab);
  window.history.replaceState({}, '', `${url.pathname}?${url.searchParams.toString()}`);
}

function updateInventoryViewInUrl(view: InventoryViewKey): void {
  const url = new URL(window.location.href);
  url.searchParams.set(INVENTORY_VIEW_QUERY_KEY, view);
  window.history.replaceState({}, '', `${url.pathname}?${url.searchParams.toString()}`);
}

function updateOperationsViewInUrl(view: OperationsViewKey): void {
  const url = new URL(window.location.href);
  url.searchParams.set(OPERATIONS_VIEW_QUERY_KEY, view);
  window.history.replaceState({}, '', `${url.pathname}?${url.searchParams.toString()}`);
}

function updateVulnerabilityIntelViewInUrl(view: VulnerabilityIntelViewKey): void {
  const url = new URL(window.location.href);
  url.searchParams.set(VULN_INTEL_VIEW_QUERY_KEY, view);
  window.history.replaceState({}, '', `${url.pathname}?${url.searchParams.toString()}`);
}

function buildAppHref(
  tab: Tab,
  options?: {
    inventoryView?: InventoryViewKey;
    operationsView?: OperationsViewKey;
    vulnerabilityIntelView?: VulnerabilityIntelViewKey;
  }
): string {
  const url = new URL(window.location.href);
  url.searchParams.set('tab', tab);
  if (options?.inventoryView) {
    url.searchParams.set(INVENTORY_VIEW_QUERY_KEY, options.inventoryView);
  }
  if (options?.operationsView) {
    url.searchParams.set(OPERATIONS_VIEW_QUERY_KEY, options.operationsView);
  }
  if (options?.vulnerabilityIntelView) {
    url.searchParams.set(VULN_INTEL_VIEW_QUERY_KEY, options.vulnerabilityIntelView);
  }
  return `${url.pathname}?${url.searchParams.toString()}`;
}

function matchTabFromInput(value: string, allowedTabs: Tab[]): Tab | null {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return null;
  const allowed = tabs.filter((tab) => allowedTabs.includes(tab.key));
  const exact = allowed.find((tab) => tab.label.toLowerCase() === normalized || tab.key.toLowerCase() === normalized);
  if (exact) return exact.key;
  const partial = allowed.find((tab) => tab.label.toLowerCase().includes(normalized));
  return partial ? partial.key : null;
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

export default function App() {
  const initialRoute = React.useMemo(() => readInitialRoute(), []);
  const [activeTab, setActiveTab] = React.useState<Tab>(initialRoute.tab);
  const [theme, setTheme] = React.useState<Theme>(() => getInitialTheme());
  const [navOpen, setNavOpen] = React.useState(false);
  const [tabSearch, setTabSearch] = React.useState('');
  const quickJumpRef = React.useRef<HTMLInputElement>(null);
  const [inventoryView, setInventoryView] = React.useState<InventoryViewKey>(() => readInitialInventoryView());
  const [operationsView, setOperationsView] = React.useState<OperationsViewKey>(() => readInitialOperationsView());
  const [vulnerabilityIntelView, setVulnerabilityIntelView] = React.useState<VulnerabilityIntelViewKey>(() => (
    readInitialVulnerabilityIntelView()
  ));
  const [inventoryFlyoutOpen, setInventoryFlyoutOpen] = React.useState(false);
  const [operationsFlyoutOpen, setOperationsFlyoutOpen] = React.useState(false);
  const [vulnerabilityIntelFlyoutOpen, setVulnerabilityIntelFlyoutOpen] = React.useState(false);
  const [initialCveId, setInitialCveId] = React.useState<string | undefined>(undefined);
  const inventoryFlyoutTimer = React.useRef<number | null>(null);
  const operationsFlyoutTimer = React.useRef<number | null>(null);
  const vulnerabilityIntelFlyoutTimer = React.useRef<number | null>(null);

  React.useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  }, [theme]);

  React.useEffect(() => {
    updateTabInUrl(activeTab);
    setNavOpen(false);
  }, [activeTab]);

  React.useEffect(() => {
    updateInventoryViewInUrl(inventoryView);
  }, [inventoryView]);

  React.useEffect(() => {
    updateOperationsViewInUrl(operationsView);
  }, [operationsView]);

  React.useEffect(() => {
    updateVulnerabilityIntelViewInUrl(vulnerabilityIntelView);
  }, [vulnerabilityIntelView]);

  React.useEffect(() => {
    const handlePopState = (): void => {
      const route = readInitialRoute();
      setActiveTab(route.tab);
      setInventoryView(readInitialInventoryView());
      setOperationsView(readInitialOperationsView());
      setVulnerabilityIntelView(readInitialVulnerabilityIntelView());
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, []);

  React.useEffect(() => {
    const handleGlobalKeyDown = (event: KeyboardEvent): void => {
      if ((event.metaKey || event.ctrlKey) && event.key === 'k') {
        event.preventDefault();
        quickJumpRef.current?.focus();
        quickJumpRef.current?.select();
      }
    };
    window.addEventListener('keydown', handleGlobalKeyDown);
    return () => window.removeEventListener('keydown', handleGlobalKeyDown);
  }, []);

  React.useEffect(() => () => {
    if (inventoryFlyoutTimer.current != null) {
      window.clearTimeout(inventoryFlyoutTimer.current);
    }
    if (operationsFlyoutTimer.current != null) {
      window.clearTimeout(operationsFlyoutTimer.current);
    }
    if (vulnerabilityIntelFlyoutTimer.current != null) {
      window.clearTimeout(vulnerabilityIntelFlyoutTimer.current);
    }
  }, []);

  const activeTabMeta = tabs.find((tab) => tab.key === activeTab) ?? tabs[0];
  const visiblePrimaryTabs = primaryNavTabs;
  const tabSearchSuggestions = tabs
    .filter((tab) => visiblePrimaryTabs.includes(tab.key) || bottomNavTabs.includes(tab.key))
    .filter((tab) => tab.label.toLowerCase().includes(tabSearch.trim().toLowerCase()));

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

  const applyTabSearch = (): void => {
    const next = matchTabFromInput(tabSearch, [...visiblePrimaryTabs, ...bottomNavTabs]);
    if (!next) return;
    setActiveTab(next);
    setTabSearch('');
  };

  const renderNavButton = (tab: Tab): React.ReactNode => (
    <button
      key={tab}
      className={activeTab === tab ? 'nav-btn active' : 'nav-btn'}
      onClick={() => {
        setActiveTab(tab);
        setNavOpen(false);
        if (tab !== 'inventory') {
          setInventoryFlyoutOpen(false);
        }
        if (tab !== 'operations') {
          setOperationsFlyoutOpen(false);
        }
        if (tab !== 'vulnerability-intelligence') {
          setVulnerabilityIntelFlyoutOpen(false);
        }
      }}
    >
      <span className="nav-icon">
        <TabIcon tab={tab} />
      </span>
      <span className="nav-label">{tabs.find((entry) => entry.key === tab)?.navLabel ?? tab}</span>
    </button>
  );

  const openVulnerabilityIntelFlyout = (): void => {
    if (vulnerabilityIntelFlyoutTimer.current != null) {
      window.clearTimeout(vulnerabilityIntelFlyoutTimer.current);
      vulnerabilityIntelFlyoutTimer.current = null;
    }
    setVulnerabilityIntelFlyoutOpen(true);
  };

  const closeVulnerabilityIntelFlyoutWithDelay = (): void => {
    if (vulnerabilityIntelFlyoutTimer.current != null) {
      window.clearTimeout(vulnerabilityIntelFlyoutTimer.current);
    }
    vulnerabilityIntelFlyoutTimer.current = window.setTimeout(() => {
      setVulnerabilityIntelFlyoutOpen(false);
      vulnerabilityIntelFlyoutTimer.current = null;
    }, 180);
  };

  return (
    <div className="app-shell">
      <aside className={navOpen ? 'sidebar open' : 'sidebar'}>
        <div className="brand-block compact">
          <div className="brand-mark">SA</div>
          <div className="brand">Scout.ai</div>
        </div>

        <div className="nav-main-section">
          {visiblePrimaryTabs.map((tab) => {
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
                      setActiveTab('operations');
                      setNavOpen(false);
                      setInventoryFlyoutOpen(false);
                      setVulnerabilityIntelFlyoutOpen(false);
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
                          <a
                            key={item.key}
                            href={buildAppHref('operations', { operationsView: item.key })}
                            className={operationsView === item.key ? 'operations-flyout-item active' : 'operations-flyout-item'}
                            onClick={(event) => {
                              event.preventDefault();
                              setActiveTab('operations');
                              setOperationsView(item.key);
                              setOperationsFlyoutOpen(false);
                            }}
                          >
                            <span>{item.label}</span>
                          </a>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );
            }
            if (tab === 'vulnerability-intelligence') {
              return (
                <div
                  key={tab}
                  className="vuln-intel-nav-wrap"
                  onMouseEnter={openVulnerabilityIntelFlyout}
                  onMouseLeave={closeVulnerabilityIntelFlyoutWithDelay}
                >
                  <button
                    className={activeTab === tab ? 'nav-btn active' : 'nav-btn'}
                    onClick={() => {
                      setActiveTab('vulnerability-intelligence');
                      setNavOpen(false);
                      setInventoryFlyoutOpen(false);
                      setOperationsFlyoutOpen(false);
                      setVulnerabilityIntelFlyoutOpen((open) => !open);
                    }}
                  >
                    <span className="nav-icon">
                      <TabIcon tab="vulnerability-intelligence" />
                    </span>
                    <span className="nav-label">Vuln Intel</span>
                  </button>

                  {vulnerabilityIntelFlyoutOpen && (
                    <div
                      className="vuln-intel-flyout"
                      onMouseEnter={openVulnerabilityIntelFlyout}
                      onMouseLeave={closeVulnerabilityIntelFlyoutWithDelay}
                    >
                      <div className="vuln-intel-flyout-header">
                        <span>Vulnerability Intel</span>
                        <span aria-hidden="true">→</span>
                      </div>
                      <div className="vuln-intel-flyout-items">
                        {vulnerabilityIntelNavItems.map((item) => (
                          <button
                            key={item.key}
                            type="button"
                            className={vulnerabilityIntelView === item.key ? 'vuln-intel-flyout-item active' : 'vuln-intel-flyout-item'}
                            onClick={() => {
                              setActiveTab('vulnerability-intelligence');
                              setVulnerabilityIntelView(item.key);
                              setVulnerabilityIntelFlyoutOpen(false);
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
                      {inventoryFlyoutGroups.map((group) => (
                        <div key={group.title} className="inventory-flyout-group">
                          <div className="inventory-flyout-group-title">{group.title}</div>
                          <div className="inventory-flyout-items">
                            {group.items.map((item) => (
                              <button
                                key={item.key}
                                type="button"
                                className={inventoryView === item.key ? 'inventory-flyout-item active' : 'inventory-flyout-item'}
                                onClick={() => {
                                  setInventoryView(item.key);
                                  setActiveTab('inventory');
                                  setInventoryFlyoutOpen(false);
                                  setOperationsFlyoutOpen(false);
                                  setVulnerabilityIntelFlyoutOpen(false);
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
          {bottomNavTabs.map((tab) => renderNavButton(tab))}
        </div>
      </aside>

      <main className="content">
        <header className="topbar">
          <div className="topbar-copy">
            <div className="eyebrow">Enterprise Vulnerability Operations</div>
            <h1>{activeTabMeta.label}</h1>
          </div>
          <div className="topbar-actions">
            <div className="quick-jump">
              <input
                ref={quickJumpRef}
                value={tabSearch}
                onChange={(event) => setTabSearch(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') {
                    event.preventDefault();
                    applyTabSearch();
                  }
                }}
                placeholder="Jump to page..."
                aria-label="Jump to page"
              />
              {!tabSearch && <span className="quick-jump-kbd">⌘K</span>}
              {tabSearch.trim() && tabSearchSuggestions.length > 0 && (
                <div className="quick-jump-menu">
                  {tabSearchSuggestions.map((tab) => (
                    <button
                      key={tab.key}
                      type="button"
                      className="quick-jump-item"
                      onClick={() => {
                        setActiveTab(tab.key);
                        setTabSearch('');
                      }}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
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

        {activeTab === 'dashboard' && <DashboardPage onViewEol={() => setActiveTab('end-of-life')} />}
        {activeTab === 'findings' && (
          <FindingsPage
            onOpenCveWorkbench={(vulnerabilityId) => {
              setInitialCveId(vulnerabilityId);
              setActiveTab('vulnerability-intelligence');
              setVulnerabilityIntelView('org-cves');
            }}
          />
        )}
        {activeTab === 'operations' && <OperationalDashboardPage selectedView={operationsView} />}
        {activeTab === 'vulnerability-intelligence' && vulnerabilityIntelView === 'dashboard' && (
          <VulnerabilityIntelDashboardPage onOpenVulnerabilities={() => setVulnerabilityIntelView('vulnerabilities')} />
        )}
        {activeTab === 'vulnerability-intelligence' && vulnerabilityIntelView === 'vulnerabilities' && (
          <InventoryPage selectedView="vulnerability-intelligence" />
        )}
        {activeTab === 'vulnerability-intelligence' && vulnerabilityIntelView === 'org-cves' && (
          <VulnerabilityIntelOrgCvePage initialCveId={initialCveId} />
        )}
        {activeTab === 'inventory' && (
          <InventoryPage selectedView={inventoryView} />
        )}
        {activeTab === 'end-of-life' && <EolPage />}
        {activeTab === 'connect' && <ConnectPage />}
        {activeTab === 'configurations' && <ConfigurationsPage />}
      </main>

      {navOpen && <button type="button" className="mobile-nav-backdrop" onClick={() => setNavOpen(false)} aria-label="Close navigation" />}
    </div>
  );
}
