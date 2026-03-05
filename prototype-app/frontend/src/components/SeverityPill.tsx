import React from 'react';

type Props = {
  severity: string;
  inKev?: boolean;
};

export function SeverityPill({ severity, inKev }: Props) {
  const normalized = severity.toLowerCase();
  const className = `severity-pill severity-${normalized}`;

  return (
    <span className={className}>
      {severity}
      {inKev ? ' + KEV' : ''}
    </span>
  );
}
