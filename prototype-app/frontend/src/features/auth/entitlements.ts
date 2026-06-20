import type { ActorContext } from './types';

export function canUseEntitlement(_actor: ActorContext | null, _entitlementKey: string): boolean {
  return true;
}

export function canUseAnyAiFeature(_actor: ActorContext | null): boolean {
  return true;
}
