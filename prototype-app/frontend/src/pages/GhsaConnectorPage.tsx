import React from 'react';
import { api } from '../api/client';
import type { VulnIntelSourceStatus } from '../api/client';
import { VulnIntelConnectorPage } from './VulnIntelConnectorPage';

function Tooltip({ text }: { text: string }) {
  return <span className="sn-tooltip" title={text} aria-label={text}>ⓘ</span>;
}

type Props = { lastRun?: VulnIntelSourceStatus };

export function GhsaConnectorPage({ lastRun }: Props) {
  const configFields = (
    <div className="form-grid">
      <div className="inline-note">
        GitHub Advisory Database (GHSA) is fetched using the GitHub GraphQL API.
        The GitHub token is configured server-side in{' '}
        <code>backend/secrets/github-api-token</code> or via the{' '}
        <code>GITHUB_API_TOKEN</code> environment variable.{' '}
        <Tooltip text="The token requires no special scopes — public advisory data is accessible with any valid token." />
      </div>
    </div>
  );

  return (
    <VulnIntelConnectorPage
      config={{
        title: 'GitHub Advisory Database (GHSA)',
        sourceKey: 'GHSA',
        triggerSync: () => api.syncGhsa(),
        configFields
      }}
      lastRun={lastRun}
    />
  );
}
