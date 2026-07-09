import { act, screen } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { renderWithProviders } from '../test/test-utils';
import { PageFreshnessStatus } from './PageFreshnessStatus';

describe('PageFreshnessStatus', () => {
  const RETURN_PULSE_MS = 4000;
  const visibilityDescriptor = Object.getOwnPropertyDescriptor(document, 'visibilityState')
    ?? Object.getOwnPropertyDescriptor(Document.prototype, 'visibilityState');

  beforeEach(() => {
    vi.useFakeTimers();
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'visible',
    });
  });

  afterEach(() => {
    vi.useRealTimers();
    if (visibilityDescriptor) {
      Object.defineProperty(document, 'visibilityState', visibilityDescriptor);
    }
  });

  it('shows a return-to-tab pulse when data updates while the tab is hidden', () => {
    const view = renderWithProviders(
      <PageFreshnessStatus updatedAt="2026-07-09T10:00:00Z" />
    );

    expect(screen.queryByText(/Updated just now while you were away/i)).not.toBeInTheDocument();

    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'hidden',
    });
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    view.rerender(<PageFreshnessStatus updatedAt="2026-07-09T10:05:00Z" />);

    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'visible',
    });
    act(() => {
      document.dispatchEvent(new Event('visibilitychange'));
    });

    expect(screen.getByText(/Updated just now while you were away/i)).toBeInTheDocument();

    act(() => {
      vi.advanceTimersByTime(RETURN_PULSE_MS);
    });

    expect(screen.queryByText(/Updated just now while you were away/i)).not.toBeInTheDocument();
  });
});
