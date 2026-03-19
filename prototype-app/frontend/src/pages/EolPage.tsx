import React from 'react';
import { api } from '../api/client';
import { EolProductCatalog } from '../types';
import { EolDetailDrawer } from '../components/EolDetailDrawer';

type UnresolvedMapping = {
  vendor: string;
  product: string;
  displayName: string;
  normalizedKey: string;
};

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
  const [products, setProducts] = React.useState<EolProductCatalog[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [query, setQuery] = React.useState('');
  const [page, setPage] = React.useState(0);
  const [drawer, setDrawer] = React.useState<EolProductCatalog | null>(null);

  const [unresolvedList, setUnresolvedList] = React.useState<UnresolvedMapping[] | null>(null);
  const [confirmSlug, setConfirmSlug] = React.useState<Record<string, string>>({});
  const [unresolvedOpen, setUnresolvedOpen] = React.useState(false);

  const loadProducts = React.useCallback(() => {
    setLoading(true);
    setError(null);
    api.listEolProducts()
      .then(items => {
        setProducts(items);
        setLoading(false);
      })
      .catch(e => {
        setError(e instanceof Error ? e.message : String(e));
        setLoading(false);
      });
  }, []);

  const loadUnresolvedMappings = React.useCallback(() => {
    api.listEolUnresolvedMappings()
      .then(list => setUnresolvedList(list))
      .catch(() => {});
  }, []);

  React.useEffect(() => {
    loadProducts();
  }, [loadProducts]);

  React.useEffect(() => {
    loadUnresolvedMappings();
  }, [loadUnresolvedMappings]);

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

  async function handleConfirmMapping(normalizedKey: string) {
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
      loadUnresolvedMappings();
    } catch (e) {
      alert(`Failed to confirm mapping: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return (
    <div className="page-grid">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>End-of-Life Catalog</h3>
            <span className="panel-caption">
              Raw endoflife.date products ingested into VulnWatch. Open a product to inspect its release cycles and source metadata.
            </span>
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
            <span className="panel-caption">Catalog slugs stored from the feed.</span>
          </div>
          <div className="summary-card">
            <strong>CPE Tagged</strong>
            <span>{catalogStats.cpeMapped.toLocaleString()}</span>
            <span className="panel-caption">Entries with vendor or product CPE metadata.</span>
          </div>
          <div className="summary-card">
            <strong>PURL Tagged</strong>
            <span>{catalogStats.purlMapped.toLocaleString()}</span>
            <span className="panel-caption">Entries with package-url identifiers.</span>
          </div>
          <div className="summary-card">
            <strong>Aliases</strong>
            <span>{catalogStats.aliases.toLocaleString()}</span>
            <span className="panel-caption">Products carrying ingested alias hints.</span>
          </div>
          <div className="summary-card">
            <strong>Fetched</strong>
            <span>{catalogStats.fetched.toLocaleString()}</span>
            <span className="panel-caption">Entries with recorded fetch timestamps.</span>
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
            <div className="table-scroll">
              <table>
                <thead>
                  <tr>
                    <th>Product</th>
                    <th>Slug</th>
                    <th>Identifiers</th>
                    <th>Aliases</th>
                    <th>Sync Metadata</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {pageItems.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '32px 0' }}>
                        <span className="panel-caption">
                          {query.trim().length > 0 ? 'No products matched your search.' : 'No EOL products have been ingested yet.'}
                        </span>
                      </td>
                    </tr>
                  ) : pageItems.map(product => (
                    <tr key={product.slug}>
                      <td>
                        <div>{product.displayName || product.slug}</div>
                        {product.displayName && product.displayName !== product.slug && (
                          <span className="panel-caption mono">{product.slug}</span>
                        )}
                      </td>
                      <td className="mono">{product.slug}</td>
                      <td>
                        <div className="eol-catalog-meta">
                          <span className="panel-caption">CPE</span>
                          <span className="mono">{formatIdentifier(product.cpeVendor, product.cpeProduct)}</span>
                        </div>
                        <div className="eol-catalog-meta">
                          <span className="panel-caption">PURL</span>
                          <span className="mono">{formatIdentifier(product.purlType, product.purlNamespace)}</span>
                        </div>
                      </td>
                      <td>
                        <span className="eol-catalog-aliases">{formatAliases(product.aliases)}</span>
                      </td>
                      <td>
                        <div className="eol-catalog-meta">
                          <span className="panel-caption">Last fetched</span>
                          <span>{formatInstant(product.lastFetchedAt)}</span>
                        </div>
                        <div className="eol-catalog-meta">
                          <span className="panel-caption">Last modified</span>
                          <span className="mono">{product.lastModified || '-'}</span>
                        </div>
                      </td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() => setDrawer(product)}
                        >
                          View Cycles
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

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

      {unresolvedList && unresolvedList.length > 0 && (
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
            <>
              <p className="panel-caption" style={{ margin: '0 0 12px' }}>
                These normalized software identities still need an endoflife.date slug. Confirming them keeps Org-CVE and matched software EOL signals accurate.
              </p>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Software</th>
                      <th>Vendor</th>
                      <th>Normalized Key</th>
                      <th>EOL Slug</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {unresolvedList.slice(0, 50).map(item => (
                      <tr key={item.normalizedKey}>
                        <td>{item.displayName}</td>
                        <td className="mono">{item.vendor || '-'}</td>
                        <td className="mono">{item.normalizedKey}</td>
                        <td>
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
                        </td>
                        <td>
                          <button
                            type="button"
                            className="btn btn-secondary"
                            disabled={!confirmSlug[item.normalizedKey]?.trim()}
                            onClick={() => handleConfirmMapping(item.normalizedKey)}
                          >
                            Confirm
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
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
