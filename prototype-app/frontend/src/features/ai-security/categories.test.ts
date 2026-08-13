import { describe, expect, it } from 'vitest';
import { categoryForNativeKind, combinedNativeKindFilterValue, stripProviderPrefix } from './categories';

describe('categoryForNativeKind', () => {
  it('maps AWS and Azure agent kinds to the same Agents category', () => {
    expect(categoryForNativeKind('AWS_BEDROCK_AGENT')?.key).toBe('AGENTS');
    expect(categoryForNativeKind('AZURE_BOT_SERVICES')?.key).toBe('AGENTS');
  });

  it('maps AWS and Azure guardrail kinds to the same Guardrails category', () => {
    expect(categoryForNativeKind('AWS_BEDROCK_GUARDRAIL')?.key).toBe('GUARDRAILS');
    expect(categoryForNativeKind('AZURE_RAI_POLICIES')?.key).toBe('GUARDRAILS');
  });

  it('groups Azure RBAC and Identity under Identity', () => {
    expect(categoryForNativeKind('AZURE_RBAC_GLOBAL')?.key).toBe('IDENTITY');
    expect(categoryForNativeKind('AZURE_IDENTITY')?.key).toBe('IDENTITY');
  });

  it('returns undefined for kinds with no cross-provider grouping', () => {
    expect(categoryForNativeKind('AWS_BEDROCK_INFERENCE_PROFILE')).toBeUndefined();
    expect(categoryForNativeKind('AZURE_BOT_CHANNELS')).toBeUndefined();
  });
});

describe('stripProviderPrefix', () => {
  it('drops the leading provider token and humanizes the rest', () => {
    expect(stripProviderPrefix('AWS_BEDROCK_INFERENCE_PROFILE')).toBe('BEDROCK INFERENCE PROFILE');
    expect(stripProviderPrefix('AZURE_IDENTITY')).toBe('IDENTITY');
    expect(stripProviderPrefix('AZURE_AI_ACCOUNTS')).toBe('AI ACCOUNTS');
  });
});

describe('combinedNativeKindFilterValue', () => {
  it('joins native kinds into a single comma-separated filter value', () => {
    expect(combinedNativeKindFilterValue(['AWS_BEDROCK_AGENT', 'AZURE_BOT_SERVICES'])).toBe('AWS_BEDROCK_AGENT,AZURE_BOT_SERVICES');
  });
});
