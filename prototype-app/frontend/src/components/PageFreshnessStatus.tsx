import React from 'react';

type FreshnessValue = number | string | null | undefined;
const RETURN_TO_TAB_NOTICE_MS = 4000;

function resolveTimestamp(value: FreshnessValue): number | null {
  if (value == null) {
    return null;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) && value > 0 ? value : null;
  }
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function formatTimestamp(value: FreshnessValue): string | null {
  const timestamp = resolveTimestamp(value);
  if (timestamp == null) {
    return null;
  }
  return new Date(timestamp).toLocaleString();
}

export function latestFreshnessValue(values: FreshnessValue[]): number | null {
  return values.reduce<number | null>((latest, value) => {
    const resolved = resolveTimestamp(value);
    if (resolved == null) {
      return latest;
    }
    return latest == null ? resolved : Math.max(latest, resolved);
  }, null);
}

export function PageFreshnessStatus({
  updatedAt,
  isRefreshing = false,
  delayedMessage,
  refreshLabel = 'Refreshing current view…',
  returnLabel = 'Updated just now while you were away.',
}: {
  updatedAt?: FreshnessValue;
  isRefreshing?: boolean;
  delayedMessage?: string | null;
  refreshLabel?: string;
  returnLabel?: string;
}) {
  const resolvedUpdatedAt = React.useMemo(() => resolveTimestamp(updatedAt), [updatedAt]);
  const formatted = formatTimestamp(updatedAt);
  const [showReturnPulse, setShowReturnPulse] = React.useState(false);
  const hiddenUpdatedAtRef = React.useRef<number | null>(null);
  const lastVisibleUpdatedAtRef = React.useRef<number | null>(null);
  const pulseTimeoutRef = React.useRef<number | null>(null);

  React.useEffect(() => {
    if (typeof document === 'undefined') {
      return;
    }

    const clearPulseTimeout = () => {
      if (pulseTimeoutRef.current != null) {
        window.clearTimeout(pulseTimeoutRef.current);
        pulseTimeoutRef.current = null;
      }
    };

    const showPulse = () => {
      setShowReturnPulse(true);
      clearPulseTimeout();
      pulseTimeoutRef.current = window.setTimeout(() => {
        setShowReturnPulse(false);
      }, RETURN_TO_TAB_NOTICE_MS);
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'hidden') {
        hiddenUpdatedAtRef.current = resolvedUpdatedAt;
        return;
      }

      if (
        resolvedUpdatedAt != null
        && hiddenUpdatedAtRef.current != null
        && resolvedUpdatedAt > hiddenUpdatedAtRef.current
      ) {
        showPulse();
      }
      hiddenUpdatedAtRef.current = null;
      lastVisibleUpdatedAtRef.current = resolvedUpdatedAt;
    };

    if (document.visibilityState !== 'hidden' && resolvedUpdatedAt != null) {
      if (
        lastVisibleUpdatedAtRef.current != null
        && resolvedUpdatedAt > lastVisibleUpdatedAtRef.current
      ) {
        showPulse();
      }
      lastVisibleUpdatedAtRef.current = resolvedUpdatedAt;
    }

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      clearPulseTimeout();
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [resolvedUpdatedAt]);

  const statusText = isRefreshing
    ? formatted
      ? `${refreshLabel} Last updated ${formatted}.`
      : refreshLabel
    : formatted
      ? `Last updated ${formatted}`
      : null;

  if (!statusText && !delayedMessage) {
    return null;
  }

  return (
    <div style={{ marginBottom: 12 }}>
      {statusText ? (
        <div className="panel-caption" role="status" aria-live="polite" style={{ marginBottom: delayedMessage ? 8 : 0 }}>
          {statusText}
        </div>
      ) : null}
      {showReturnPulse ? (
        <div className="notice success" role="status" aria-live="polite" style={{ marginBottom: delayedMessage ? 8 : 0 }}>
          {returnLabel}
        </div>
      ) : null}
      {delayedMessage ? (
        <div className="notice warning" role="status" aria-live="polite">
          {delayedMessage}
        </div>
      ) : null}
    </div>
  );
}
