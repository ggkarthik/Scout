export type QueryParamValue = string | string[] | null | undefined;
export type QueryParamUpdates = Record<string, QueryParamValue>;

function resolveUrl(href: string): URL {
  try {
    return new URL(href);
  } catch {
    return new URL(href, 'http://localhost');
  }
}

function applyQueryParamUpdates(url: URL, updates: QueryParamUpdates): URL {
  Object.entries(updates).forEach(([key, value]) => {
    url.searchParams.delete(key);
    if (value == null) {
      return;
    }
    if (Array.isArray(value)) {
      value.forEach((item) => url.searchParams.append(key, item));
      return;
    }
    url.searchParams.set(key, value);
  });
  return url;
}

export function readQueryParam(key: string, search: string = window.location.search): string | null {
  return new URLSearchParams(search).get(key);
}

export function readQueryParams(key: string, search: string = window.location.search): string[] {
  return new URLSearchParams(search).getAll(key);
}

export function buildPathWithQueryParams(
  updates: QueryParamUpdates,
  href: string = window.location.href
): string {
  const url = applyQueryParamUpdates(resolveUrl(href), updates);
  return `${url.pathname}${url.search}${url.hash}`;
}

export function replaceBrowserQueryParams(updates: QueryParamUpdates): void {
  window.history.replaceState({}, '', buildPathWithQueryParams(updates));
}
