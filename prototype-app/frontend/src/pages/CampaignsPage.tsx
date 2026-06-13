import React from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useActor } from '../features/auth/context';
import type { TenantMember } from '../features/admin/types';
import type { OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { cveWorkbenchApi } from '../features/cve-workbench/api';
import type {
  CampaignCreateRequest,
  CampaignStatus,
  CampaignSummary,
} from '../features/campaigns/types';

type StatusTab = {
  label: string;
  value: CampaignStatus | 'ALL';
};

type WizardForm = {
  name: string;
  summary: string;
  dueDate: string;
  launchNote: string;
  watchlistTriggerPolicy: 'ALL_EVENTS' | 'STATUS_CHANGES' | 'NOTES_ONLY' | 'CLOSURE_RISK';
  selectedCves: string[];
  selectedGroups: string[];
  selectedWatchlistIds: string[];
};


const STATUS_TABS: StatusTab[] = [
  { label: 'All Campaigns', value: 'ALL' },
  { label: 'Active', value: 'ACTIVE' },
  { label: 'Paused', value: 'PAUSED' },
  { label: 'Blocked', value: 'BLOCKED' },
  { label: 'Closed', value: 'CLOSED' },
  { label: 'Draft', value: 'DRAFT' },
];

const WIZARD_STEPS = ['Basics', 'Scope', 'Watchlist', 'Launch'] as const;

function statusBadgeClass(status: CampaignStatus): string {
  if (status === 'ACTIVE') return 'campaign-status-badge active';
  if (status === 'PAUSED') return 'campaign-status-badge paused';
  if (status === 'BLOCKED') return 'campaign-status-badge blocked';
  if (status === 'CLOSED' || status === 'CANCELLED') return 'campaign-status-badge closed';
  if (status === 'IN_REVIEW') return 'campaign-status-badge review';
  return 'campaign-status-badge draft';
}

function formatStatus(status: CampaignStatus): string {
  return status.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, (char) => char.toUpperCase());
}

function formatDate(value?: string | null): string {
  if (!value) return 'TBD';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' });
}

function createDefaultForm(): WizardForm {
  const dueDate = new Date();
  dueDate.setDate(dueDate.getDate() + 14);
  return {
    name: '',
    summary: '',
    dueDate: dueDate.toISOString().slice(0, 10),
    launchNote: '',
    watchlistTriggerPolicy: 'ALL_EVENTS',
    selectedCves: [],
    selectedGroups: [],
    selectedWatchlistIds: [],
  };
}

export function CampaignsPage() {
  const actor = useActor();
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = React.useState<CampaignSummary[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [activeTab, setActiveTab] = React.useState<StatusTab['value']>('ALL');
  const [search, setSearch] = React.useState('');

  const [wizardOpen, setWizardOpen] = React.useState(false);
  const [wizardStep, setWizardStep] = React.useState(0);
  const [wizardForm, setWizardForm] = React.useState<WizardForm>(() => createDefaultForm());
  const [wizardBusy, setWizardBusy] = React.useState(false);
  const [wizardError, setWizardError] = React.useState<string | null>(null);
  const [orgCves, setOrgCves] = React.useState<OrgSpecificCveExposureRecord[]>([]);
  const [groupOptions, setGroupOptions] = React.useState<string[]>([]);
  const [members, setMembers] = React.useState<TenantMember[]>([]);

  const loadCampaigns = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.listCampaigns(activeTab === 'ALL' ? undefined : activeTab);
      setCampaigns(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setCampaigns([]);
    } finally {
      setLoading(false);
    }
  }, [activeTab]);

  React.useEffect(() => {
    void loadCampaigns();
  }, [loadCampaigns]);


  React.useEffect(() => {
    if (!wizardOpen) return;
    let cancelled = false;
    Promise.all([
      cveWorkbenchApi.listOrgSpecificCves({ page: 0, size: 100, includeAll: true }),
      api.listAssignmentGroups(),
      actor?.tenantId ? api.listTenantMembers(actor.tenantId) : Promise.resolve([] as TenantMember[]),
    ])
      .then(([cvePage, groups, tenantMembers]) => {
        if (cancelled) return;
        setOrgCves(cvePage.items);
        setGroupOptions(Array.from(new Set(groups)).sort((a, b) => a.localeCompare(b)));
        setMembers(tenantMembers);
      })
      .catch((err) => {
        if (cancelled) return;
        setWizardError(err instanceof Error ? err.message : String(err));
      });
    return () => {
      cancelled = true;
    };
  }, [wizardOpen, actor?.tenantId]);

  const filteredCampaigns = React.useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return campaigns;
    return campaigns.filter((campaign) =>
      campaign.name.toLowerCase().includes(query)
      || campaign.cveIds.some((cveId) => cveId.toLowerCase().includes(query))
      || (campaign.summary ?? '').toLowerCase().includes(query)
    );
  }, [campaigns, search]);

  const countsByTab = React.useMemo(() => {
    const counts = new Map<StatusTab['value'], number>();
    counts.set('ALL', campaigns.length);
    STATUS_TABS.forEach((tab) => {
      if (tab.value === 'ALL') return;
      counts.set(tab.value, campaigns.filter((campaign) => campaign.status === tab.value).length);
    });
    return counts;
  }, [campaigns]);

  const kpis = React.useMemo(() => {
    const total = campaigns.length;
    const active = campaigns.filter((campaign) => campaign.status === 'ACTIVE').length;
    const behind = campaigns.filter((campaign) => campaign.exceptionCount > 0).length;
    const assets = campaigns.reduce((sum, campaign) => sum + campaign.assetCount, 0);
    const findings = campaigns.reduce((sum, campaign) => sum + campaign.totalFindings, 0);
    return { total, active, behind, assets, findings };
  }, [campaigns]);

  function toggleSelection(list: string[], value: string): string[] {
    return list.includes(value) ? list.filter((item) => item !== value) : [...list, value];
  }

  function resetWizard(): void {
    setWizardStep(0);
    setWizardForm(createDefaultForm());
    setWizardBusy(false);
    setWizardError(null);
  }

  function openWizard(): void {
    resetWizard();
    setWizardOpen(true);
  }

  function closeWizard(): void {
    setWizardOpen(false);
    resetWizard();
  }

  async function submitWizard(): Promise<void> {
    if (!wizardForm.name.trim()) {
      setWizardError('Campaign name is required.');
      return;
    }
    if (wizardForm.selectedCves.length === 0) {
      setWizardError('Select at least one CVE.');
      return;
    }
    setWizardBusy(true);
    setWizardError(null);
    const watchlist = members
      .filter((member) => wizardForm.selectedWatchlistIds.includes(member.id))
      .map((member) => ({
        entryType: 'USER' as const,
        label: member.displayName || member.email || member.subject,
        email: member.email,
        triggerPolicy: wizardForm.watchlistTriggerPolicy,
        active: true,
      }));
    const payload: CampaignCreateRequest = {
      name: wizardForm.name.trim(),
      summary: wizardForm.summary.trim() || null,
      cveIds: wizardForm.selectedCves,
      dueAt: wizardForm.dueDate ? new Date(`${wizardForm.dueDate}T00:00:00Z`).toISOString() : null,
      launchNote: wizardForm.launchNote.trim() || null,
      notifyGroups: wizardForm.selectedGroups.map((groupName, index) => ({
        groupName,
        roleLabel: index === 0 ? 'Owner group' : 'Resolver group',
        triggerSummary: 'Status changes, notes, closure risk',
        notificationsPaused: false,
      })),
      watchlist,
    };
    try {
      const created = await api.createCampaign(payload);
      closeWizard();
      await loadCampaigns();
      navigate(`/vuln-repo/campaigns/${created.summary.id}`);
    } catch (err) {
      setWizardError(err instanceof Error ? err.message : String(err));
    } finally {
      setWizardBusy(false);
    }
  }


  return (
    <div className="campaigns-page">
      <div className="campaigns-topbar">
        <div>
          <h2>Remediation Campaigns</h2>
          <p>Coordinate multi-CVE patch rollouts, watchlist notifications, and closure tracking from one workspace.</p>
        </div>
        <div className="campaigns-topbar-actions">
          <button type="button" className="btn btn-secondary" onClick={() => void loadCampaigns()}>
            Refresh
          </button>
          <button type="button" className="btn btn-primary" onClick={openWizard}>
            New Campaign
          </button>
        </div>
      </div>

      <div className="campaigns-tab-row">
        {STATUS_TABS.map((tab) => (
          <button
            key={tab.value}
            type="button"
            className={activeTab === tab.value ? 'campaign-tab active' : 'campaign-tab'}
            onClick={() => setActiveTab(tab.value)}
          >
            <span>{tab.label}</span>
            <span className="campaign-tab-count">{countsByTab.get(tab.value) ?? 0}</span>
          </button>
        ))}
      </div>

      <div className="campaign-kpi-grid">
        <div className="campaign-kpi-card">
          <span className="campaign-kpi-label">Total Campaigns</span>
          <strong>{kpis.total}</strong>
        </div>
        <div className="campaign-kpi-card">
          <span className="campaign-kpi-label">Active</span>
          <strong>{kpis.active}</strong>
        </div>
        <div className="campaign-kpi-card">
          <span className="campaign-kpi-label">Behind SLA</span>
          <strong>{kpis.behind}</strong>
        </div>
        <div className="campaign-kpi-card">
          <span className="campaign-kpi-label">Scoped Assets</span>
          <strong>{kpis.assets}</strong>
        </div>
        <div className="campaign-kpi-card">
          <span className="campaign-kpi-label">Tracked Findings</span>
          <strong>{kpis.findings}</strong>
        </div>
      </div>

      <div className="campaigns-filter-row">
        <input
          className="input"
          type="search"
          placeholder="Search campaigns, CVEs, or summary"
          value={search}
          onChange={(event) => setSearch(event.target.value)}
        />
      </div>

      {error && <div className="notice error">{error}</div>}

      <div className="campaigns-body campaigns-body--full">
        <section className="panel campaigns-list-panel campaigns-list-panel--full">
          {loading ? (
            <div className="notice">Loading campaigns...</div>
          ) : filteredCampaigns.length === 0 ? (
            <div className="campaign-empty">
              <h3>No campaigns yet</h3>
              <p>Create the first remediation campaign to turn CVE scope into an operational rollout.</p>
            </div>
          ) : (
            <table className="campaigns-table">
              <thead>
                <tr>
                  <th>Campaign</th>
                  <th>Status</th>
                  <th>Progress</th>
                  <th>Assets</th>
                  <th>Due</th>
                </tr>
              </thead>
              <tbody>
                {filteredCampaigns.map((campaign) => (
                  <tr
                    key={campaign.id}
                    style={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/vuln-repo/campaigns/${campaign.id}`)}
                  >
                    <td>
                      <div className="campaign-name-cell">
                        <strong>{campaign.name}</strong>
                        <span>{campaign.cveIds.join(', ')}</span>
                      </div>
                    </td>
                    <td>
                      <span className={statusBadgeClass(campaign.status)}>{formatStatus(campaign.status)}</span>
                    </td>
                    <td>
                      <div className="campaign-progress-cell">
                        <div className="campaign-progress-bar">
                          <div style={{ width: `${campaign.completionPercent}%` }} />
                        </div>
                        <span>{campaign.completionPercent}%</span>
                      </div>
                    </td>
                    <td>{campaign.assetCount}</td>
                    <td>{formatDate(campaign.dueAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </section>

      </div>

      {wizardOpen && (
        <div className="campaign-modal-backdrop" role="presentation" onClick={closeWizard}>
          <section className="campaign-modal" role="dialog" aria-modal="true" onClick={(event) => event.stopPropagation()}>
            <div className="campaign-modal-header">
              <div>
                <h3>New Campaign</h3>
                <p>Follow the campaign launch flow from the mock, backed by real CVE and tenant data.</p>
              </div>
              <button type="button" className="btn btn-secondary" onClick={closeWizard}>Close</button>
            </div>

            <div className="campaign-wizard-steps">
              {WIZARD_STEPS.map((step, index) => (
                <button
                  key={step}
                  type="button"
                  className={wizardStep === index ? 'campaign-wizard-step active' : 'campaign-wizard-step'}
                  onClick={() => setWizardStep(index)}
                >
                  <span>{index + 1}</span>
                  {step}
                </button>
              ))}
            </div>

            <div className="campaign-modal-body">
              {wizardError && <div className="notice error">{wizardError}</div>}

              {wizardStep === 0 && (
                <div className="campaign-form-grid">
                  <label>
                    <span>Campaign Name</span>
                    <input value={wizardForm.name} onChange={(event) => setWizardForm((current) => ({ ...current, name: event.target.value }))} />
                  </label>
                  <label>
                    <span>Target Due Date</span>
                    <input type="date" value={wizardForm.dueDate} onChange={(event) => setWizardForm((current) => ({ ...current, dueDate: event.target.value }))} />
                  </label>
                  <label className="full">
                    <span>Summary</span>
                    <textarea value={wizardForm.summary} onChange={(event) => setWizardForm((current) => ({ ...current, summary: event.target.value }))} />
                  </label>
                </div>
              )}

              {wizardStep === 1 && (
                <div className="campaign-picker-grid">
                  {orgCves.map((item) => {
                    const selected = wizardForm.selectedCves.includes(item.externalId);
                    return (
                      <button
                        key={item.externalId}
                        type="button"
                        className={selected ? 'campaign-choice-card active' : 'campaign-choice-card'}
                        onClick={() => setWizardForm((current) => ({ ...current, selectedCves: toggleSelection(current.selectedCves, item.externalId) }))}
                      >
                        <strong>{item.externalId}</strong>
                        <span>{item.title}</span>
                        <small>{item.matchedAssetCount} assets · {item.openFindings} open findings</small>
                      </button>
                    );
                  })}
                </div>
              )}

              {wizardStep === 2 && (
                <div className="campaign-form-columns">
                  <div>
                    <h4>Notify Groups</h4>
                    <div className="campaign-chip-grid">
                      {groupOptions.map((group) => (
                        <button
                          key={group}
                          type="button"
                          className={wizardForm.selectedGroups.includes(group) ? 'campaign-chip active' : 'campaign-chip'}
                          onClick={() => setWizardForm((current) => ({ ...current, selectedGroups: toggleSelection(current.selectedGroups, group) }))}
                        >
                          {group}
                        </button>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h4>Watchlist Members</h4>
                    <label className="campaign-watchlist-policy">
                      <span>Trigger Policy</span>
                      <select value={wizardForm.watchlistTriggerPolicy} onChange={(event) => setWizardForm((current) => ({ ...current, watchlistTriggerPolicy: event.target.value as WizardForm['watchlistTriggerPolicy'] }))}>
                        <option value="ALL_EVENTS">All events</option>
                        <option value="STATUS_CHANGES">Status changes only</option>
                        <option value="NOTES_ONLY">Notes only</option>
                        <option value="CLOSURE_RISK">Closure risk only</option>
                      </select>
                    </label>
                    <div className="campaign-picker-grid compact">
                      {members.map((member) => {
                        const selected = wizardForm.selectedWatchlistIds.includes(member.id);
                        return (
                          <button
                            key={member.id}
                            type="button"
                            className={selected ? 'campaign-choice-card active' : 'campaign-choice-card'}
                            onClick={() => setWizardForm((current) => ({ ...current, selectedWatchlistIds: toggleSelection(current.selectedWatchlistIds, member.id) }))}
                          >
                            <strong>{member.displayName || member.email || member.subject}</strong>
                            <span>{member.role}</span>
                            <small>{member.email || 'No email on record'} · {wizardForm.watchlistTriggerPolicy}</small>
                          </button>
                        );
                      })}
                    </div>
                  </div>
                </div>
              )}

              {wizardStep === 3 && (
                <div className="campaign-form-grid">
                  <div className="campaign-launch-summary full">
                    <h4>Launch Summary</h4>
                    <p>{wizardForm.selectedCves.length} CVEs selected, {wizardForm.selectedGroups.length} notify groups, {wizardForm.selectedWatchlistIds.length} watchlist members.</p>
                  </div>
                  <label className="full">
                    <span>Launch Note</span>
                    <textarea value={wizardForm.launchNote} onChange={(event) => setWizardForm((current) => ({ ...current, launchNote: event.target.value }))} />
                  </label>
                </div>
              )}
            </div>

            <div className="campaign-modal-footer">
              <button type="button" className="btn btn-secondary" disabled={wizardStep === 0} onClick={() => setWizardStep((step) => Math.max(0, step - 1))}>
                Back
              </button>
              {wizardStep < WIZARD_STEPS.length - 1 ? (
                <button type="button" className="btn btn-primary" onClick={() => setWizardStep((step) => Math.min(WIZARD_STEPS.length - 1, step + 1))}>
                  Next
                </button>
              ) : (
                <button type="button" className="btn btn-primary" disabled={wizardBusy} onClick={() => void submitWizard()}>
                  {wizardBusy ? 'Launching…' : 'Launch Campaign'}
                </button>
              )}
            </div>
          </section>
        </div>
      )}
    </div>
  );
}
