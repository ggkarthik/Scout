import React from 'react';
import { StatCard } from '../../components/StatCard';
import type { InventoryViewKey } from './types';

type Props = {
  selectedView: InventoryViewKey;
  componentTotalItems: number;
  activeCount: number;
  retiredCount: number;
  assetCount: number;
  needsReviewCount: number;
};

export function InventorySummaryStats({
  selectedView,
  componentTotalItems,
  activeCount,
  retiredCount,
  assetCount,
  needsReviewCount
}: Props) {
  if (selectedView === 'vulnerability-intelligence') {
    return null;
  }

  return (
    <div className="stats-grid">
      <StatCard title="Inventory Records" value={componentTotalItems} />
      <StatCard title="Active Components" value={activeCount} />
      <StatCard title="Retired Components" value={retiredCount} />
      <StatCard title="Assets Represented" value={assetCount} />
      {selectedView === 'hosts' && (
        <StatCard title="Rows Needing Review" value={needsReviewCount} />
      )}
    </div>
  );
}
