import type { ActorContext } from './types';

export function canUseEntitlement(actor: ActorContext | null, entitlementKey: string): boolean {
  return true;
}

export function canUseAnyAiFeature(actor: ActorContext | null): boolean {
  return true;
}
