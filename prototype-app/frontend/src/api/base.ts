export function resolveApiBase(apiBase = import.meta.env.VITE_API_BASE): string {
  const configured = apiBase?.trim();
  if (configured) {
    return configured.replace(/\/+$/, '');
  }
  return '/api';
}
