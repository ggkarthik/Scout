import React from 'react';
import { api } from '../api/client';

type Props = {
  title?: string;
  caption?: string;
};

type JobDef = {
  key: string;
  label: string;
  description: string;
  trigger: () => Promise<unknown>;
};

const JOBS: JobDef[] = [
  {
    key: 'full',
    label: 'Run Full EOL Refresh',
    description: 'Fetch product catalog → release cycles → resolve mappings → denormalize status. Runs all 4 steps in sequence.',
    trigger: () => api.triggerEolFullRefresh()
  },
  {
    key: 'catalog',
    label: 'Refresh Product Catalog',
    description: 'Pull all product slugs and CPE/PURL identifiers from endoflife.date. Step 1 of 4.',
    trigger: () => api.triggerEolCatalogRefresh()
  },
  {
    key: 'releases',
    label: 'Refresh Release Cycles',
    description: 'Fetch EOL dates and lifecycle data for products matched in your inventory. Step 2 of 4.',
    trigger: () => api.triggerEolReleaseRefresh()
  },
  {
    key: 'mappings',
    label: 'Resolve Inventory Mappings',
    description: 'Match software identities from inventory to EOL product slugs using CPE, PURL, and name heuristics. Step 3 of 4.',
    trigger: () => api.triggerEolMappingResolve()
  },
  {
    key: 'denormalize',
    label: 'Denormalize EOL Status',
    description: 'Update is_eol, eol_days_remaining, and eol_cycle on inventory components for fast dashboard queries. Step 4 of 4.',
    trigger: () => api.triggerEolDenormalize()
  }
];

export function EolSourcePanel({
  title = 'endoflife.date Feed',
  caption = 'Run endoflife.date catalog, release, mapping, and denormalization jobs. Browse ingested products in the EOL tab.'
}: Props) {
  const [busy, setBusy] = React.useState<string | null>(null);
  const [message, setMessage] = React.useState('');
  const eolCatalogHref = React.useMemo(() => {
    const url = new URL(window.location.href);
    url.searchParams.set('tab', 'end-of-life');
    return `${url.pathname}?${url.searchParams.toString()}`;
  }, []);

  const runJob = async (job: JobDef): Promise<void> => {
    setBusy(job.key);
    setMessage(`${job.label} starting...`);
    try {
      const response = await job.trigger();
      if (response && typeof response === 'object' && 'runId' in response) {
        const typed = response as { runId?: string; status?: string; message?: string };
        setMessage(`Queued: run ${typed.runId ?? 'n/a'} — ${typed.message ?? typed.status ?? 'running'}`);
      } else {
        setMessage(`${job.label} completed`);
      }
    } catch (e) {
      setMessage(`${job.label} failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>{title}</h3>
        <span className="panel-caption">{caption}</span>
      </div>

      <div className="section-block">
        <h4 className="section-title">How EOL data flows</h4>
        <div className="panel-caption">
          The EOL pipeline has 4 ordered stages. Run <strong>Full EOL Refresh</strong> to execute all stages at once,
          or trigger individual stages to update only what is needed. Scheduled stages run automatically on Sunday from 2 AM through 4 AM.
          <strong> Connect → Processing Jobs</strong> currently shows the manual runs launched from this panel.
        </div>

        <div className="eol-pipeline-steps">
          {['1. Catalog', '2. Releases', '3. Mappings', '4. Denormalize'].map((step) => (
            <div key={step} className="eol-pipeline-step">{step}</div>
          ))}
        </div>
      </div>

      {message && (
        <div className={`notice${message.includes('failed') ? ' error' : ''}`} style={{ margin: '0 0 12px' }}>
          {message}
        </div>
      )}

      <div className="button-row section-actions">
        {JOBS.map((job) => (
          <button
            key={job.key}
            type="button"
            className={job.key === 'full' ? 'btn btn-primary' : 'btn btn-secondary'}
            disabled={busy !== null}
            title={job.description}
            onClick={() => runJob(job)}
          >
            {busy === job.key ? 'Running...' : job.label}
          </button>
        ))}
        <a
          href={eolCatalogHref}
          className="btn btn-secondary"
        >
          Open EOL Catalog
        </a>
      </div>

      <div className="eol-job-descriptions">
        {JOBS.filter((j) => j.key !== 'full').map((job) => (
          <div key={job.key} className="eol-job-row">
            <span className="eol-job-label">{job.label}</span>
            <span className="panel-caption">{job.description}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
