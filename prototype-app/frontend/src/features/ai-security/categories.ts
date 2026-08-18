export type AiArtifactCategoryKey = 'AGENTS' | 'MODELS' | 'GUARDRAILS' | 'IDENTITY';

export type AiArtifactCategory = {
  key: AiArtifactCategoryKey;
  label: string;
  nativeKinds: string[];
};

/** Cross-provider groupings for native artifact kinds that play the same role on AWS and
 * Azure. Deliberately small and explicit — only kinds with a genuine functional equivalent
 * on the other provider are combined here. Everything else stays as its own native-kind row. */
export const AI_ARTIFACT_CATEGORIES: AiArtifactCategory[] = [
  { key: 'AGENTS', label: 'Agents', nativeKinds: ['AWS_BEDROCK_AGENT', 'AZURE_BOT_SERVICES', 'AZURE_FOUNDRY_AGENTS'] },
  { key: 'MODELS', label: 'Models', nativeKinds: ['AWS_BEDROCK_MODEL', 'AZURE_FOUNDRY_DEPLOYMENTS', 'AZURE_ML_MODELS'] },
  { key: 'GUARDRAILS', label: 'Guardrails', nativeKinds: ['AWS_BEDROCK_GUARDRAIL', 'AZURE_RAI_POLICIES'] },
  { key: 'IDENTITY', label: 'Identity', nativeKinds: ['AZURE_RBAC_GLOBAL', 'AZURE_IDENTITY'] },
];

const NATIVE_KIND_TO_CATEGORY = new Map<string, AiArtifactCategory>(
  AI_ARTIFACT_CATEGORIES.flatMap((category) => category.nativeKinds.map((kind) => [kind, category] as const)),
);

export function categoryForNativeKind(nativeKind: string): AiArtifactCategory | undefined {
  return NATIVE_KIND_TO_CATEGORY.get(nativeKind);
}

/** Drops the leading AWS_/AZURE_ provider token from a native-kind label so cross-provider
 * views read as entity types ("Identity") rather than provider-specific names ("Azure Identity"). */
export function stripProviderPrefix(nativeKind: string): string {
  return nativeKind.replace(/^(AWS|AZURE)_/, '').replace(/_/g, ' ');
}

export function combinedNativeKindFilterValue(nativeKinds: string[]): string {
  return nativeKinds.join(',');
}
