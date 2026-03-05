import React from 'react';
import { api } from '../api/client';
import { RiskPolicy } from '../types';

export function PolicyPage() {
  const [policy, setPolicy] = React.useState<RiskPolicy | null>(null);
  const [message, setMessage] = React.useState('');

  React.useEffect(() => {
    api.getRiskPolicy()
      .then(setPolicy)
      .catch((e) => setMessage(e instanceof Error ? e.message : String(e)));
  }, []);

  const updateField = (key: keyof RiskPolicy, value: number) => {
    if (!policy) return;
    setPolicy({ ...policy, [key]: value });
  };

  const save = async () => {
    if (!policy) return;
    try {
      const updated = await api.updateRiskPolicy(policy);
      setPolicy(updated);
      setMessage('Policy saved');
    } catch (e) {
      setMessage(e instanceof Error ? e.message : String(e));
    }
  };

  if (!policy) {
    return <div className="panel">Loading policy...</div>;
  }

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>Risk Policy</h3>
        <span className="panel-caption">Adjust severity weighting and escalation thresholds</span>
      </div>

      <div className="form-grid">
        <label>CVSS Weight
          <input type="number" step="0.1" value={policy.cvssWeight} onChange={(e) => updateField('cvssWeight', Number(e.target.value))} />
        </label>

        <label>KEV Boost
          <input type="number" step="0.1" value={policy.kevBoost} onChange={(e) => updateField('kevBoost', Number(e.target.value))} />
        </label>

        <label>EPSS Weight
          <input type="number" step="0.1" value={policy.epssWeight} onChange={(e) => updateField('epssWeight', Number(e.target.value))} />
        </label>

        <label>Critical Threshold
          <input type="number" step="0.1" value={policy.criticalThreshold} onChange={(e) => updateField('criticalThreshold', Number(e.target.value))} />
        </label>

        <label>High Threshold
          <input type="number" step="0.1" value={policy.highThreshold} onChange={(e) => updateField('highThreshold', Number(e.target.value))} />
        </label>
      </div>

      <button type="button" className="btn btn-primary" onClick={save}>Save Policy</button>
      {message && <div className="notice">{message}</div>}
    </div>
  );
}
