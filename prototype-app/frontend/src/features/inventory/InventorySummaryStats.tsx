import React from 'react';
import type { InventoryViewKey } from './types';

type Props = {
  selectedView: InventoryViewKey;
  componentTotalItems: number;
  activeCount: number;
  retiredCount: number;
  assetCount: number;
  needsReviewCount: number;
};

function StatWidget({ title, value, caption = 'Current tenant' }: { title: string; value: number; caption?: string }) {
  return (
    <div className="fpl-widget">
      <div className="fpl-widget-title">{title}</div>
      <div className="fpl-widget-body">
        <div className="fpl-stat-num">{value.toLocaleString()}</div>
        <div className="fpl-stat-caption">{caption}</div>
      </div>
    </div>
  );
}

export function InventorySummaryStats({
  selectedView,
  componentTotalItems,
  activeCount,
  retiredCount,
  assetCount,
  needsReviewCount
}: Props) {
  return (
    <div className="fpl-widgets">
      <StatWidget title="Inventory Records" value={componentTotalItems} />
      <StatWidget title="Active Components" value={activeCount} />
      <StatWidget title="Retired Components" value={retiredCount} />
      <StatWidget title="Assets Represented" value={assetCount} />
      {selectedView === 'hosts' && (
        <StatWidget title="Rows Needing Review" value={needsReviewCount} />
      )}
    </div>
  );
}
