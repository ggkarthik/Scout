import React from 'react';
import { InfoTooltip } from '../components/InfoTooltip';
import { useServiceNowCmdbConfigQuery, useTicketingProviderStatusQuery } from '../features/connect/queries';
import { formatTimestamp } from '../lib/time';

/**
 * ServiceNow's incident-ticketing face.
 *
 * <p>Read-only on purpose: ServiceNow incident creation authenticates with the same instance
 * credentials as the ServiceNow inventory connector, so there is one place to edit them and
 * this page reports how they are being used rather than offering a second, divergent copy.
 */
export function ServiceNowTicketingConnectorPage() {
  const serviceNowConfigQuery = useServiceNowCmdbConfigQuery();
  const ticketingStatusQuery = useTicketingProviderStatusQuery();
  const config = serviceNowConfigQuery.data ?? null;
  const ticketingStatus = ticketingStatusQuery.data ?? null;

  if (serviceNowConfigQuery.isLoading) {
    return <section className="panel">Loading ServiceNow ticketing...</section>;
  }

  const isActive = ticketingStatus?.activeProvider === 'servicenow';
  const isOverridden = (ticketingStatus?.overridden ?? []).includes('servicenow');
  const overriddenBy = ticketingStatus?.activeProviderName ?? 'another connector';

  return (
    <section className="panel">
      {config?.configured && config.lastTestedAt && (
        <div className="sn-status-row">
          <span className="sn-status-meta">Last connection test: {formatTimestamp(config.lastTestedAt)}</span>
        </div>
      )}

      {!config?.configured && (
        <div className="notice">
          ServiceNow is not configured yet. Set up the ServiceNow connector under{' '}
          <strong>Inventory</strong> — incident ticketing reuses the same instance URL and
          credentials.
        </div>
      )}

      {isActive && (
        <div className="notice">
          <strong>ServiceNow is the active ticketing system.</strong> New finding tickets are
          raised as ServiceNow incidents.
        </div>
      )}

      {isOverridden && (
        <div className="notice">
          <strong>{overriddenBy} is overriding ServiceNow ticketing.</strong> New finding tickets
          go to {overriddenBy}. Incidents already raised here keep their numbers and continue to
          sync from ServiceNow, so nothing in flight is lost.
        </div>
      )}

      <div className="form-section">
        <h4 className="form-section-title">Ticketing Configuration</h4>
        <div className="form-grid">
          <label>
            <span>
              Instance URL{' '}
              <InfoTooltip text="Shared with the ServiceNow inventory connector. Change it there." />
            </span>
            <input type="text" value={config?.baseUrl ?? ''} readOnly disabled />
          </label>

          <label>
            <span>
              Integration User{' '}
              <InfoTooltip text="The account incidents are created as. It needs write access to the incident table." />
            </span>
            <input type="text" value={config?.username ?? ''} readOnly disabled />
          </label>

          <label>
            <span>
              Credentials{' '}
              <InfoTooltip text="Stored encrypted with the ServiceNow inventory connector." />
            </span>
            <input
              type="text"
              value={config?.hasCredentialSecret ? 'Saved' : 'Not saved'}
              readOnly
              disabled
            />
          </label>

          <label>
            <span>
              Incident Table{' '}
              <InfoTooltip text="Incidents are created in the standard incident table via the Table API." />
            </span>
            <input type="text" value="incident" readOnly disabled />
          </label>
        </div>
      </div>

      <div className="form-section">
        <h4 className="form-section-title">What This Connector Does</h4>
        <div className="panel-caption" style={{ lineHeight: 1.7 }}>
          Raises a ServiceNow incident for a finding, with severity mapped to incident priority
          and the remediation due date written as a Task SLA. A daily job reads each incident's
          state back and updates the finding, so remediation progress stays visible in Scout
          without anyone re-entering it.
        </div>
      </div>
    </section>
  );
}
