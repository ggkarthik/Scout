import React, { useState } from 'react';

export function BigFixPatchConnectorPage() {
  const [baseUrl, setBaseUrl] = useState('');
  const [apiToken, setApiToken] = useState('');
  const [autoSync, setAutoSync] = useState(true);

  const handleTestConnection = () => {
    console.log('Testing connection:', { baseUrl, apiToken });
    // API call will go here
  };

  const handleSaveConfiguration = () => {
    console.log('Saving configuration:', { baseUrl, apiToken, autoSync });
    // API call will go here
  };

  return (
    <div style={{ display: 'grid', gap: 24 }}>
      {/* Header */}
      <div>
        <h2>BigFix Patch Connector</h2>
        <p style={{ color: 'var(--fg-muted)', marginTop: 8 }}>
          IBM BigFix patch and endpoint management integration. Configure your BigFix server to automatically ingest patch deployment status.
        </p>
      </div>

      {/* Connector Info Card */}
      <div className="panel" style={{ padding: 20 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 20 }}>
          <div>
            <div style={{ fontSize: '3rem', marginBottom: 12 }}>🔧</div>
            <div style={{ display: 'grid', gap: 8 }}>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                  Authentication Type
                </div>
                <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>REST API Token</div>
              </div>
              <div>
                <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                  Status
                </div>
                <div style={{ fontSize: '0.875rem', fontWeight: 500, color: '#4CAF50' }}>● Configurable</div>
              </div>
            </div>
          </div>
          <div>
            <h3 style={{ margin: '0 0 12px 0' }}>Configuration Details</h3>
            <div style={{ display: 'grid', gap: 12, fontSize: '0.875rem', color: 'var(--fg-muted)', lineHeight: 1.6 }}>
              <p style={{ margin: 0 }}>
                <strong>Base URL:</strong> Your BigFix server URL with port (typically 52311)
              </p>
              <p style={{ margin: 0 }}>
                <strong>API Token:</strong> REST API token with Fixlet query permissions
              </p>
              <p style={{ margin: 0 }}>
                <strong>Auto-Sync:</strong> Enable automatic ingestion of patch deployment status every 6 hours
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Configuration Form */}
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ marginTop: 0 }}>Configure BigFix</h3>

        <div style={{ display: 'grid', gap: 16, marginTop: 16 }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
              Base URL
            </label>
            <input
              type="text"
              placeholder="https://bigfix-server.example.com:52311"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px',
                border: '1px solid var(--border)',
                borderRadius: 4,
                fontSize: '0.875rem',
                fontFamily: 'monospace'
              }}
            />
            <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
              BigFix server URL with port (typically 52311)
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
              API Token
            </label>
            <input
              type="password"
              placeholder="••••••••••••••••"
              value={apiToken}
              onChange={(e) => setApiToken(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px',
                border: '1px solid var(--border)',
                borderRadius: 4,
                fontSize: '0.875rem'
              }}
            />
            <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
              REST API token with Fixlet query permissions
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
              <input
                type="checkbox"
                checked={autoSync}
                onChange={(e) => setAutoSync(e.target.checked)}
                style={{ marginRight: 6 }}
              />
              Enable Automatic Sync (every 6 hours)
            </label>
          </div>

          <div style={{ display: 'flex', gap: 12, marginTop: 12 }}>
            <button
              className="btn btn-secondary"
              onClick={handleTestConnection}
              style={{ cursor: 'pointer' }}
            >
              Test Connection
            </button>
            <button
              className="btn btn-primary"
              onClick={handleSaveConfiguration}
              style={{ cursor: 'pointer' }}
            >
              Save Configuration
            </button>
          </div>
        </div>
      </div>

      {/* Info Box */}
      <div className="panel" style={{ padding: 16, background: 'var(--info-bg)', border: '1px solid var(--info-border)' }}>
        <h4 style={{ margin: '0 0 8px 0', color: 'var(--info)' }}>ℹ How It Works</h4>
        <div style={{ margin: 0, fontSize: '0.875rem', color: 'var(--info)', lineHeight: '1.6' }}>
          1. <strong>Configure Credentials</strong> — Provide BigFix server URL and API token<br />
          2. <strong>Test Connection</strong> — Verify connectivity to your BigFix server<br />
          3. <strong>Auto-Sync</strong> — Connector automatically ingests patch deployment status every 6 hours<br />
          4. <strong>Auto-Resolve</strong> — When a patch is deployed to an asset, related findings are automatically resolved
        </div>
      </div>
    </div>
  );
}
