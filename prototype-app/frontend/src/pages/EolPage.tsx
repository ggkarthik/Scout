import React from 'react';
import { pathForOperationsView } from '../app/routes';
import {
  DataTable,
  type DataTableColumn,
  type DataTableRow
} from '../components/DataTable';
import { EolDetailDrawer } from '../components/EolDetailDrawer';
import { useEolProductsQuery } from '../features/eol/queries';
import type { EolProductCatalog } from '../features/eol/types';

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

function formatCount(value?: number): string {
  return (value ?? 0).toLocaleString();
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
  const productsQuery = useEolProductsQuery();
  const products = React.useMemo(() => productsQuery.data ?? [], [productsQuery.data]);
  const loading = productsQuery.isPending;
  const error = productsQuery.error instanceof Error ? productsQuery.error.message : null;
  const [query, setQuery] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [drawer, setDrawer] = React.useState<EolProductCatalog | null>(null);
  const eolMappingReviewHref = `${pathForOperationsView('quality')}?domain=EOL&focus=eol-mapping-review`;

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
    lifecycleReady: products.filter(product => (product.releaseCount ?? 0) > 0).length,
    cpeMapped: products.filter(product => Boolean(product.cpeVendor || product.cpeProduct)).length,
    purlMapped: products.filter(product => Boolean(product.purlType || product.purlNamespace)).length,
    aliases: products.filter(product => (product.aliases?.length ?? 0) > 0).length
  }), [products]);
  const productColumns = React.useMemo<DataTableColumn[]>(() => [
    { id: 'product', label: 'Product', header: 'Product', initialSize: 220 },
    { id: 'slug', label: 'Slug', header: 'Slug', initialSize: 150 },
    { id: 'coverage', label: 'Coverage', header: 'Coverage', initialSize: 190 },
    { id: 'referenceHints', label: 'Reference Hints', header: 'Reference Hints', initialSize: 260 },
    { id: 'aliases', label: 'Aliases', header: 'Aliases', initialSize: 240 },
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
        coverage: {
          content: (
            <div className="eol-catalog-coverage">
              <strong
                className={
                  (product.releaseCount ?? 0) > 0
                    ? 'eol-catalog-coverage-title'
                    : 'eol-catalog-coverage-title eol-catalog-coverage-title--empty'
                }
              >
                {(product.releaseCount ?? 0) > 0
                  ? `${formatCount(product.releaseCount)} ${(product.releaseCount ?? 0) === 1 ? 'cycle' : 'cycles'} loaded`
                  : 'No release cycles'}
              </strong>
              <span className="panel-caption">
                {(product.releaseCount ?? 0) > 0 ? 'Lifecycle data ready' : 'Reference-only entry'}
              </span>
            </div>
          )
        },
        referenceHints: {
          content: (
            <div className="eol-catalog-reference-list">
              {(product.cpeVendor || product.cpeProduct) && (
                <div className="eol-catalog-reference-row">
                  <span className="eol-catalog-reference-label">CPE</span>
                  <span className="eol-catalog-reference-value mono">
                    {formatIdentifier(product.cpeVendor, product.cpeProduct)}
                  </span>
                </div>
              )}
              {(product.purlType || product.purlNamespace) && (
                <div className="eol-catalog-reference-row">
                  <span className="eol-catalog-reference-label">PURL</span>
                  <span className="eol-catalog-reference-value mono">
                    {formatIdentifier(product.purlType, product.purlNamespace)}
                  </span>
                </div>
              )}
              {!product.cpeVendor && !product.cpeProduct && !product.purlType && !product.purlNamespace && (
                <span className="panel-caption">No catalog identifiers</span>
              )}
            </div>
          )
        },
        aliases: {
          content: (
            <span className="eol-catalog-aliases">{formatAliases(product.aliases)}</span>
          )
        },
        actions: {
          content: (
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setDrawer(product)}
            >
              View Details
            </button>
          )
        }
      }
    }))
  ), [pageItems]);
  function exportCsv() {
    const header = 'Display Name,Slug,Release Count,CPE Vendor,CPE Product,PURL Type,PURL Namespace,Aliases,Last Modified,Last Fetched At';
    const rows = filteredProducts.map(product =>
      [
        product.displayName ?? '',
        product.slug,
        product.releaseCount ?? 0,
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

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>End-of-Life Catalog</h3>
          </div>
          <div className="button-row">
            <a href={eolMappingReviewHref} className="btn btn-secondary">
              Review Unmatched Mappings
            </a>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={exportCsv}
              disabled={filteredProducts.length === 0}
            >
              Export CSV
            </button>
          </div>
        </div>

        <div className="ingestion-summary-grid">
          <div className="summary-card">
            <strong>Products</strong>
            <span>{catalogStats.products.toLocaleString()}</span>
          </div>
          <div className="summary-card">
            <strong>Lifecycle Ready</strong>
            <span>{catalogStats.lifecycleReady.toLocaleString()}</span>
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
                  storageKey="eol-product-catalog-v2"
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

      {drawer && (
        <EolDetailDrawer
          slug={drawer.slug}
          catalogProduct={drawer}
          packageName={drawer.displayName && drawer.displayName !== drawer.slug
            ? `${drawer.displayName} (${drawer.slug})`
            : drawer.slug}
          onClose={() => setDrawer(null)}
        />
      )}
    </div>
  );
}
