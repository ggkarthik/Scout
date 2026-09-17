import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';
import { formatTimestamp } from '../lib/time';

export function AiAgentExecutionsPage() {
  const [searchParams] = useSearchParams();
  const [selected, setSelected] = React.useState<string | null>(null);
  const [agentId, setAgentId] = React.useState(searchParams.get('agentId') ?? '');
  const [agentVersionId, setAgentVersionId] = React.useState(searchParams.get('agentVersionId') ?? '');
  const [status, setStatus] = React.useState('');
  const [source, setSource] = React.useState(searchParams.get('source') ?? '');
  const [from, setFrom] = React.useState(toLocalDateTime(searchParams.get('from')));
  const [to, setTo] = React.useState(toLocalDateTime(searchParams.get('to')));
  const [page, setPage] = React.useState(0);
  const pageSize = 50;
  const executions = useQuery({
    queryKey: ['ai-agent-executions', agentId, agentVersionId, status, source, from, to, page],
    queryFn: () => api.listAiAgentExecutions({
      agentId: agentId || undefined, agentVersionId: agentVersionId || undefined,
      status: status || undefined, source: source || undefined,
      from: from ? new Date(from).toISOString() : undefined,
      to: to ? new Date(to).toISOString() : undefined,
      page, size: pageSize,
    }),
  });
  const timeline = useQuery({ queryKey: ['ai-agent-execution-timeline', selected], queryFn: () => api.getAiAgentExecutionTimeline(selected!), enabled: selected !== null });
  if (executions.isPending) return <main className="page"><p>Loading execution metadata…</p></main>;
  if (executions.isError) return <main className="page"><p>Unable to load execution metadata.</p></main>;
  return <main className="page ai-security-page">
    <header><h1>Agent execution metadata</h1><p>Metadata only — prompts, messages, arguments, results, and provider IDs are never shown.</p></header>
    <section className="panel inventory-fpl-toolbar">
      <label>Agent ID<input value={agentId} onChange={event => { setAgentId(event.target.value); setPage(0); }} placeholder="Internal artifact UUID" /></label>
      <label>Agent version ID<input value={agentVersionId} onChange={event => { setAgentVersionId(event.target.value); setPage(0); }} placeholder="Internal version UUID" /></label>
      <label>Status<input value={status} onChange={event => { setStatus(event.target.value); setPage(0); }} placeholder="completed" /></label>
      <label>Source<input value={source} onChange={event => { setSource(event.target.value); setPage(0); }} placeholder="COPILOT_STUDIO_RUNTIME" /></label>
      <label>From<input type="datetime-local" value={from} onChange={event => { setFrom(event.target.value); setPage(0); }} /></label>
      <label>To<input type="datetime-local" value={to} onChange={event => { setTo(event.target.value); setPage(0); }} /></label>
    </section>
    {executions.data.items.length === 0 ? <p>No runtime metadata has been collected.</p> : <table><thead><tr><th>Evidence time</th><th>Provider</th><th>Source</th><th>Agent version</th><th>Correlation</th><th>Status</th><th>Latency</th><th /></tr></thead>
      <tbody>{executions.data.items.map(item => <tr key={item.id}><td>{formatTimestamp(item.evidenceTime)}</td><td>{item.provider}</td><td>{item.source}</td><td className="mono">{item.agentVersionArtifactId ?? '—'}</td><td>{item.correlationStatus}{item.correlationDiagnostic ? <small>{item.correlationDiagnostic.replace(/_/g, ' ')}</small> : null}</td><td>{item.status}</td><td>{item.latencyMs == null ? '—' : `${item.latencyMs} ms`}</td><td><button type="button" onClick={() => setSelected(item.id)}>Timeline</button></td></tr>)}</tbody></table>}
    <div className="pagination-row"><button type="button" disabled={page === 0} onClick={() => setPage(value => value - 1)}>Previous</button><span>Page {page + 1}</span><button type="button" disabled={(page + 1) * pageSize >= executions.data.total} onClick={() => setPage(value => value + 1)}>Next</button></div>
    {selected && <section><h2>Timeline</h2><button type="button" onClick={() => setSelected(null)}>Close</button>{timeline.isPending ? <p>Loading…</p> : timeline.isError ? <p>Unable to load this timeline.</p> : <ol>{timeline.data?.map(event => <li key={event.id}>{formatTimestamp(event.eventTime)} — {event.eventType}{event.status ? ` (${event.status})` : ''}</li>)}</ol>}</section>}
  </main>;
}

function toLocalDateTime(value: string | null): string {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const offset = date.getTimezoneOffset() * 60_000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}
