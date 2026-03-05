import React from 'react';

type Props = {
  title: string;
  value: number;
  tone?: 'neutral' | 'warn' | 'critical';
  caption?: string;
};

export function StatCard({ title, value, tone = 'neutral', caption = 'Current tenant' }: Props) {
  return (
    <div className={`stat-card stat-${tone}`}>
      <div className="stat-title">{title}</div>
      <div className="stat-value">{value.toLocaleString()}</div>
      <div className="stat-caption">{caption}</div>
    </div>
  );
}
