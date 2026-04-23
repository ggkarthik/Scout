import React from 'react';
import { api } from '../api/client';
import type { VulnIntelSourceStatus } from '../api/client';
import { VulnIntelConnectorPage } from './VulnIntelConnectorPage';

function Tooltip({ text }: { text: string }) {
  return <span className="sn-tooltip" title={text} aria-label={text}>ⓘ</span>;
}

type Props = { lastRun?: VulnIntelSourceStatus };

export function NvdConnectorPage({ lastRun }: Props) {
  const [apiKey, setApiKey] = React.useState('');
  const [showKey, setShowKey] = React.useState(false);

  const configFields = (
    <div className="form-grid">
      <label>
        <span>
          NVD API Key (optional){' '}
          <Tooltip text="Requests without a key are rate-limited to 5 req/30s. A free key raises the limit to 50 req/30s." />
        </span>
        <div className="secure-input-row">
          <input
            type={showKey ? 'text' : 'password'}
            value={apiKey}
            onChange={(e) => setApiKey(e.target.value)}
            placeholder="Leave blank to use anonymous rate limits"
            autoComplete="off"
          />
          <button
            type="button"
            className="btn btn-secondary btn-inline"
            onClick={() => setShowKey((v) => !v)}
          >
            {showKey ? 'Hide' : 'Show'}
          </button>
        </div>
      </label>
    </div>
  );

  return (
    <VulnIntelConnectorPage
      config={{
        title: 'NVD Vulnerability Feed',
        sourceKey: 'NVD',
        triggerSync: () => api.syncNvd(),
        configFields
      }}
      lastRun={lastRun}
    />
  );
}
