import React from 'react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, type RenderOptions } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

function createTestQueryClient(): QueryClient {
  return new QueryClient({
    defaultOptions: {
      queries: {
        retry: false
      }
    }
  });
}

type ProviderProps = {
  children: React.ReactNode;
  route?: string;
  queryClient?: QueryClient;
};

type ExtendedRenderOptions = Omit<RenderOptions, 'wrapper'> & {
  route?: string;
  queryClient?: QueryClient;
};

export function renderWithProviders(
  ui: React.ReactElement,
  { route, queryClient, ...options }: ExtendedRenderOptions = {}
) {
  const Wrapper = ({ children }: ProviderProps) => (
    <QueryClientProvider client={queryClient ?? createTestQueryClient()}>
      <MemoryRouter initialEntries={[route ?? '/']}>
        {children}
      </MemoryRouter>
    </QueryClientProvider>
  );

  return render(ui, {
    wrapper: Wrapper,
    ...options
  });
}

export { createTestQueryClient };
