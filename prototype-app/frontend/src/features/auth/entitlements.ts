import type { ActorContext } from './types';

export function canUseEntitlement(actor: ActorContext | null, entitlementKey: string): boolean {
  return actor?.entitlements?.[entitlementKey] === true;
}

export function canUseAnyAiFeature(actor: ActorContext | null): boolean {
  return Object.entries(actor?.entitlements ?? {}).some(([key, enabled]) => key.startsWith('ai.') && enabled);
}
