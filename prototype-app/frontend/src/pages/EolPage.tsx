import { useQueryClient } from '@tanstack/react-query';
import React from 'react';
import { api } from '../api/client';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { EolDetailDrawer } from '../components/EolDetailDrawer';
import {
  useEolProductsQuery,
  useEolUnresolvedMappingsQuery
} from '../features/eol/queries';
import type {
  EolProductCatalog,
  UnresolvedEolMapping
} from '../features/eol/types';

const PAGE_SIZE = 25;

function matchesProduct(product: EolProductCatalog, query: string): boolean {
  const needle = query.trim().toLowerCase();
  if (!needle) {
    return true;
  }

  const haystacks = [
    product.slug,
    product.displayName,
    product.cpeVendor,
    product.cpeProduct,
    product.purlType,
    product.purlNamespace,
    ...(product.aliases ?? [])
  ];

  return haystacks.some(value => value?.toLowerCase().includes(needle));
}

function formatAliases(aliases?: string[]): string {
  if (!aliases || aliases.length === 0) {
    return '-';
  }
  if (aliases.length <= 3) {
    return aliases.join(', ');
  }
  return `${aliases.slice(0, 3).join(', ')} +${aliases.length - 3} more`;
}

function formatInstant(value?: string): string {
  if (!value) {
    return '-';
  }

  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return value;
  }

  return parsed.toLocaleString();
}

function formatIdentifier(primary?: string, secondary?: string): string {
  if (!primary && !secondary) {
    return '-';
  }
  if (primary && secondary) {
    return `${primary}/${secondary}`;
  }
  return primary ?? secondary ?? '-';
}

export function EolPage() {
  const queryClient = useQueryClient();
  const productsQuery = useEolProductsQuery();
  const unresolvedMappingsQuery = useEolUnresolvedMappingsQuery();
  const products = React.useMemo(() => productsQuery.data ?? [], [productsQuery.data]);
  const unresolvedList = React.useMemo(
    () => unresolvedMappingsQuery.data ?? [],
    [unresolvedMappingsQuery.data]
  );
  const loading = productsQuery.isPending;
  const error = productsQuery.error instanceof Error ? productsQuery.error.message : null;
  const [query, setQuery] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [drawer, setDrawer] = React.useState<EolProductCatalog | null>(null);
  const [confirmSlug, setConfirmSlug] = React.useState<Record<string, string>>({});
  const [unresolvedOpen, setUnresolvedOpen] = React.useState(false);

  React.useEffect(() => {
    setPage(0);
  }, [query]);

  const filteredProducts = React.useMemo(
    () => products.filter(product => matchesProduct(product, query)),
    [products, query]
  );

  const totalPages = Math.max(1, Math.ceil(filteredProducts.length / PAGE_SIZE));
  const activePage = Math.min(page, totalPages - 1);
  const pageItems = React.useMemo(
    () => filteredProducts.slice(activePage * PAGE_SIZE, activePage * PAGE_SIZE + PAGE_SIZE),
    [activePage, filteredProducts]
  );

  React.useEffect(() => {
    if (page !== activePage) {
      setPage(activePage);
    }
  }, [activePage, page]);

  const catalogStats = React.useMemo(() => ({
    products: products.length,
    cpeMapped: products.filter(product => Boolean(product.cpeVendor || product.cpeProduct)).length,
    purlMapped: products.filter(product => Boolean(product.purlType || product.purlNamespace)).length,
    aliases: products.filter(product => (product.aliases?.length ?? 0) > 0).length,
    fetched: products.filter(product => Boolean(product.lastFetchedAt)).length
  }), [products]);
  const productColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'product', label: 'Product', header: 'Product', initialSize: 220 },
    { id: 'slug', label: 'Slug', header: 'Slug', initialSize: 150 },
    { id: 'identifiers', label: 'Identifiers', header: 'Identifiers', initialSize: 260 },
    { id: 'aliases', label: 'Aliases', header: 'Aliases', initialSize: 240 },
    { id: 'syncMetadata', label: 'Sync Metadata', header: 'Sync Metadata', initialSize: 240 },
    { id: 'actions', label: 'Actions', header: '', initialSize: 140 }
  ], []);
  const productRows = React.useMemo<DataTableRow[]>(() => (
    pageItems.map((product) => ({
      id: product.slug,
      cells: {
        product: {
          content: (
            <>
              <div>{product.displayName || product.slug}</div>
              {product.displayName && product.displayName !== product.slug && (
                <span className="panel-caption mono">{product.slug}</span>
              )}
            </>
          )
        },
        slug: { content: <span className="mono">{product.slug}</span> },
        identifiers: {
          content: (
            <>
              <div className="eol-catalog-meta">
                <span className="panel-caption">CPE</span>
                <span className="mono">{formatIdentifier(product.cpeVendor, product.cpeProduct)}</span>
              </div>
              <div className="eol-catalog-meta">
                <span className="panel-caption">PURL</span>
                <span className="mono">{formatIdentifier(product.purlType, product.purlNamespace)}</span>
              </div>
            </>
          )
        },
        aliases: { content: <span className="eol-catalog-aliases">{formatAliases(product.aliases)}</span> },
        syncMetadata: {
          content: (
            <>
              <div className="eol-catalog-meta">
                <span className="panel-caption">Last fetched</span>
                <span>{formatInstant(product.lastFetchedAt)}</span>
              </div>
              <div className="eol-catalog-meta">
                <span className="panel-caption">Last modified</span>
                <span className="mono">{product.lastModified || '-'}</span>
              </div>
            </>
          )
        },
        actions: {
          content: (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setDrawer(product)}
            >
              View Cycles
            </button>
          )
        }
      }
    }))
  ), [pageItems]);
  const unresolvedColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'software', label: 'Software', header: 'Software', initialSize: 220 },
    { id: 'vendor', label: 'Vendor', header: 'Vendor', initialSize: 140 },
    { id: 'normalizedKey', label: 'Normalized Key', header: 'Normalized Key', initialSize: 240 },
    { id: 'eolSlug', label: 'EOL Slug', header: 'EOL Slug', initialSize: 220 },
    { id: 'actions', label: 'Actions', header: '', initialSize: 120 }
  ], []);
  function exportCsv() {
    const header = 'Display Name,Slug,CPE Vendor,CPE Product,PURL Type,PURL Namespace,Aliases,Last Modified,Last Fetched At';
    const rows = filteredProducts.map(product =>
      [
        product.displayName ?? '',
        product.slug,
        product.cpeVendor ?? '',
        product.cpeProduct ?? '',
        product.purlType ?? '',
        product.purlNamespace ?? '',
        (product.aliases ?? []).join('|'),
        product.lastModified ?? '',
        product.lastFetchedAt ?? ''
      ].map(value => `"${String(value).replace(/"/g, '""')}"`).join(',')
    );

    const csv = [header, ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'eol-product-catalog.csv';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(() => URL.revokeObjectURL(url), 100);
  }

  const handleConfirmMapping = React.useCallback(async (normalizedKey: string) => {
    const slug = confirmSlug[normalizedKey];
    if (!slug?.trim()) {
      return;
    }

    try {
      await api.confirmEolMapping(normalizedKey, slug.trim());
      setConfirmSlug(prev => {
        const next = { ...prev };
        delete next[normalizedKey];
        return next;
      });
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: ['eol-unresolved-mappings'] }),
        queryClient.invalidateQueries({ queryKey: ['software-identities'] }),
        queryClient.invalidateQueries({ queryKey: ['software-identity-detail'] })
      ]);
    } catch (e) {
      alert(`Failed to confirm mapping: ${e instanceof Error ? e.message : String(e)}`);
    }
  }, [confirmSlug, queryClient]);

  const unresolvedRows = React.useMemo<DataTableRow[]>(() => (
    unresolvedList.slice(0, 50).map((item: UnresolvedEolMapping) => ({
      id: item.normalizedKey,
      cells: {
        software: { content: item.displayName },
        vendor: { content: <span className="mono">{item.vendor || '-'}</span> },
        normalizedKey: { content: <span className="mono">{item.normalizedKey}</span> },
        eolSlug: {
          content: (
            <input
              type="text"
              className="filter-input"
              placeholder="e.g. ubuntu, python, java"
              value={confirmSlug[item.normalizedKey] ?? ''}
              onChange={event => setConfirmSlug(prev => ({
                ...prev,
                [item.normalizedKey]: event.target.value
              }))}
              style={{ width: '180px' }}
            />
          )
        },
        actions: {
          content: (
            <button
              type="button"
              className="btn btn-secondary"
              disabled={!confirmSlug[item.normalizedKey]?.trim()}
              onClick={() => void handleConfirmMapping(item.normalizedKey)}
            >
              Confirm
            </button>
          )
        }
      }
    }))
  ), [confirmSlug, handleConfirmMapping, unresolvedList]);

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>End-of-Life Catalog</h3>
          </div>
          <button
            type="button"
            className="btn btn-secondary"
            onClick={exportCsv}
            disabled={filteredProducts.length === 0}
          >
            Export CSV
          </button>
        </div>

        <div className="ingestion-summary-grid">
          <div className="summary-card">
            <strong>Products</strong>
            <span>{catalogStats.products.toLocaleString()}</span>
          </div>
          <div className="summary-card">
            <strong>CPE Tagged</strong>
            <span>{catalogStats.cpeMapped.toLocaleString()}</span>
          </div>
          <div className="summary-card">
            <strong>PURL Tagged</strong>
            <span>{catalogStats.purlMapped.toLocaleString()}</span>
          </div>
          <div className="summary-card">
            <strong>Aliases</strong>
            <span>{catalogStats.aliases.toLocaleString()}</span>
          </div>
          <div className="summary-card">
            <strong>Fetched</strong>
            <span>{catalogStats.fetched.toLocaleString()}</span>
          </div>
        </div>

        <div className="toolbar eol-catalog-toolbar">
          <label className="eol-catalog-search">
            <span className="panel-caption">Search catalog</span>
            <input
              type="text"
              className="filter-input"
              placeholder="slug, display name, alias, CPE, or PURL"
              value={query}
              onChange={event => setQuery(event.target.value)}
            />
          </label>
          <span className="panel-caption">
            {filteredProducts.length.toLocaleString()} matching products
          </span>
        </div>

        {error && (
          <div className="notice error" style={{ margin: '0 0 12px' }}>
            Error: {error}
          </div>
        )}

        {loading ? (
          <div className="panel-caption" style={{ padding: '24px 0' }}>Loading...</div>
        ) : (
          <>
            {error && products.length === 0 ? null : pageItems.length === 0 ? (
              <div className="panel-caption" style={{ padding: '32px 0' }}>
                {query.trim().length > 0 ? 'No products matched your search.' : 'No EOL products have been ingested yet.'}
              </div>
            ) : (
              <div className="table-scroll">
                <DataTable
                  storageKey="eol-product-catalog"
                  columns={productColumns}
                  rows={productRows}
                />
              </div>
            )}

            {filteredProducts.length > PAGE_SIZE && (
              <div className="pagination-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={activePage === 0}
                  onClick={() => setPage(current => current - 1)}
                >
                  Previous
                </button>
                <span className="panel-caption">
                  Page {activePage + 1} of {totalPages}
                  {' · '}{filteredProducts.length.toLocaleString()} products
                </span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  disabled={activePage >= totalPages - 1}
                  onClick={() => setPage(current => current + 1)}
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </section>

      {unresolvedList.length > 0 && (
        <section className="panel">
          <button
            type="button"
            className="eol-unresolved-toggle"
            onClick={() => setUnresolvedOpen(open => !open)}
          >
            <span>
              Mapping Review
              <span className="eol-unresolved-badge">{unresolvedList.length}</span>
            </span>
            <span className="panel-caption">
              {unresolvedOpen ? 'Collapse ▲' : 'Expand ▼'}
            </span>
          </button>

          {unresolvedOpen && (
            <div className="table-scroll">
              <DataTable
                storageKey="eol-unresolved-mappings"
                columns={unresolvedColumns}
                rows={unresolvedRows}
              />
            </div>
          )}
        </section>
      )}

      {drawer && (
        <EolDetailDrawer
          slug={drawer.slug}
          packageName={drawer.displayName && drawer.displayName !== drawer.slug
            ? `${drawer.displayName} (${drawer.slug})`
            : drawer.slug}
          onClose={() => setDrawer(null)}
        />
      )}
    </div>
  );
}
