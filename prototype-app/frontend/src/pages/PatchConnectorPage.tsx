import React, { useState } from 'react';

export function PatchConnectorPage() {
  const [selectedConnector, setSelectedConnector] = useState<string | null>(null);

  const connectors = [
    {
      id: 'sccm',
      name: 'SCCM/MECM',
      icon: '🖥️',
      description: 'Microsoft Configuration Manager patch deployment tracking',
      auth: 'SQL Server Connection String',
      status: 'Configurable'
    },
    {
      id: 'bigfix',
      name: 'BigFix',
      icon: '🔧',
      description: 'IBM BigFix patch and endpoint management',
      auth: 'REST API Token',
      status: 'Configurable'
    },
    {
      id: 'tanium',
      name: 'Tanium',
      icon: '⚙️',
      description: 'Tanium endpoint platform patch management',
      auth: 'GraphQL API Key',
      status: 'Configurable'
    }
  ];

  return (
    <div style={{ display: 'grid', gap: 24 }}>
      {/* Header */}
      <div>
        <h2>Patch Management Connectors</h2>
        <p style={{ color: 'var(--fg-muted)', marginTop: 8 }}>
          Configure patch sources to automatically ingest patch deployment status and auto-resolve findings when patches are deployed.
        </p>
      </div>

      {/* Connectors Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
        {connectors.map((connector) => (
          <div
            key={connector.id}
            className="panel"
            style={{
              display: 'flex',
              flexDirection: 'column',
              cursor: 'pointer',
              transition: 'all 0.2s ease',
              border: selectedConnector === connector.id ? '2px solid #0052CC' : '1px solid var(--border)',
            }}
            onMouseEnter={(e) => {
              if (selectedConnector !== connector.id) {
                e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)';
              }
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.boxShadow = '';
            }}
            onClick={() => setSelectedConnector(connector.id)}
          >
            <div style={{ padding: '20px', flex: 1 }}>
              <div style={{ fontSize: '2rem', marginBottom: 12 }}>{connector.icon}</div>
              <h3 style={{ margin: '0 0 8px 0', fontSize: '1.1rem' }}>{connector.name}</h3>
              <p style={{ margin: '0 0 12px 0', fontSize: '0.875rem', color: 'var(--fg-muted)' }}>
                {connector.description}
              </p>
              <div style={{ display: 'grid', gap: 6, marginTop: 12 }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase' }}>
                  Authentication Type
                </div>
                <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>{connector.auth}</div>
              </div>
            </div>
            <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', background: 'var(--panel-muted)' }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                Status
              </div>
              <div style={{ fontSize: '0.875rem', fontWeight: 500, color: '#4CAF50' }}>● {connector.status}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Configuration Form */}
      {selectedConnector && (
        <div className="panel" style={{ padding: 24 }}>
          <h3 style={{ marginTop: 0 }}>Configure {connectors.find(c => c.id === selectedConnector)?.name}</h3>

          <div style={{ display: 'grid', gap: 16, marginTop: 16 }}>
            {selectedConnector === 'sccm' && (
              <>
                <div>
                  <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                    Connection String
                  </label>
                  <input
                    type="text"
                    placeholder="Server=myserver;Database=CM_ABC;User Id=sa;Password=***"
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontFamily: 'monospace',
                      fontSize: '0.875rem'
                    }}
                  />
                  <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
                    SQL Server connection string to SCCM site database
                  </div>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                    Site Code
                  </label>
                  <input
                    type="text"
                    placeholder="ABC"
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontSize: '0.875rem'
                    }}
                  />
                  <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
                    Your SCCM/MECM site code (e.g., ABC)
                  </div>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                    <input type="checkbox" style={{ marginRight: 6 }} />
                    Enable Automatic Sync (every 6 hours)
                  </label>
                </div>
              </>
            )}

            {selectedConnector === 'bigfix' && (
              <>
                <div>
                  <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                    Base URL
                  </label>
                  <input
                    type="text"
                    placeholder="https://bigfix-server.example.com:52311"
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontSize: '0.875rem'
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
                    <input type="checkbox" style={{ marginRight: 6 }} defaultChecked />
                    Enable Automatic Sync (every 6 hours)
                  </label>
                </div>
              </>
            )}

            {selectedConnector === 'tanium' && (
              <>
                <div>
                  <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                    Base URL
                  </label>
                  <input
                    type="text"
                    placeholder="https://tanium-server.example.com"
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontSize: '0.875rem'
                    }}
                  />
                  <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
                    Tanium server URL
                  </div>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                    API Key
                  </label>
                  <input
                    type="password"
                    placeholder="••••••••••••••••"
                    style={{
                      width: '100%',
                      padding: '8px 12px',
                      border: '1px solid var(--border)',
                      borderRadius: 4,
                      fontSize: '0.875rem'
                    }}
                  />
                  <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
                    API key with Patch module access
                  </div>
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                    <input type="checkbox" style={{ marginRight: 6 }} defaultChecked />
                    Enable Automatic Sync (every 6 hours)
                  </label>
                </div>
              </>
            )}

            <div style={{ display: 'flex', gap: 12, marginTop: 12 }}>
              <button className="btn btn-secondary">Test Connection</button>
              <button className="btn btn-primary">Save Configuration</button>
            </div>
          </div>
        </div>
      )}

      {/* Info Box */}
      <div className="panel" style={{ padding: 16, background: 'var(--info-bg)', border: '1px solid var(--info-border)' }}>
        <h4 style={{ margin: '0 0 8px 0', color: 'var(--info)' }}>ℹ How It Works</h4>
        <div style={{ margin: 0, fontSize: '0.875rem', color: 'var(--info)', lineHeight: '1.6' }}>
          1. <strong>Configure Credentials</strong> — Provide authentication details for your patch management system<br />
          2. <strong>Auto-Sync</strong> — Connectors automatically ingest patch deployment status every 6 hours<br />
          3. <strong>Auto-Resolve</strong> — When a patch is deployed to an asset, related findings are automatically resolved<br />
          4. <strong>View Dashboard</strong> — Monitor patch coverage and deployment status on the Patch Dashboard
        </div>
      </div>
    </div>
  );
}
