import { screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import type { AiBomDeclaredResource, AiBomDeclaredResourceDetail } from '../api/client';
import { ActorContextState } from '../features/auth/context';
import type { ActorContext } from '../features/auth/types';
import { buildFinding } from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { AiBomDeclaredResourceDetailPage } from './AiBomDeclaredResourceDetailPage';

const navigateMock = vi.fn();

vi.mock('react-router-dom', async () => {
  const actual = await vi.importActual<typeof import('react-router-dom')>('react-router-dom');
  return {
    ...actual,
    useNavigate: () => navigateMock,
  };
});

const ANALYST_ACTOR: ActorContext = {
  creator: false,
  principal: 'analyst@example.com',
  userId: 'user-analyst',
  tenantId: 'tenant-1',
  tenantName: 'Acme Security',
  roles: ['ROLE_SECURITY_ANALYST'],
};

const TENANT_ADMIN_ACTOR: ActorContext = {
  ...ANALYST_ACTOR,
  principal: 'admin@example.com',
  userId: 'user-admin',
  roles: ['ROLE_TENANT_ADMIN'],
};

function renderAs(actor: ActorContext, ui: React.ReactElement) {
  return renderWithProviders(<ActorContextState.Provider value={actor}>{ui}</ActorContextState.Provider>);
}

function buildResource(overrides: Partial<AiBomDeclaredResource> = {}): AiBomDeclaredResource {
  return {
    id: 'resource-1',
    sourceId: 'source-1',
    bomId: 'bom-1',
    bomComponentId: 'component-1',
    resourceKind: 'MODEL',
    name: 'llama-3',
    version: '3.1',
    identityKind: 'VERSIONED_IDENTIFIER',
    identityValue: 'llama-3@3.1',
    deploymentState: 'UNVERIFIED',
    linkedArtifactId: null,
    linkMethod: null,
    linkReviewedBy: null,
    linkReviewedAt: null,
    proposedArtifactId: null,
    proposedBy: null,
    proposedAt: null,
    firstDeclaredAt: '2026-08-01T00:00:00Z',
    lastDeclaredAt: '2026-08-01T00:00:00Z',
    ...overrides,
  };
}

function buildDetail(overrides: Partial<AiBomDeclaredResourceDetail> = {}): AiBomDeclaredResourceDetail {
  return {
    resource: buildResource(),
    sourceBomType: 'AI_BOM',
    sourceState: 'ACTIVE',
    sourceRevision: 1,
    currentInLatestRevision: true,
    component: {
      componentId: 'component-1',
      name: 'llama-3',
      version: '3.1',
      purl: 'pkg:huggingface/llama-3@3.1',
      license: null,
      scope: null,
      componentType: 'machine-learning-model',
    },
    completeness: { completeness: 'PARTIAL', assertedBy: 'uploader@example.com', assertedAt: '2026-08-01T00:00:00Z' },
    projection: {
      provenanceProjected: true,
      provenanceProjectedAt: '2026-08-01T00:05:00Z',
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      latestReceiptOperation: 'PROVENANCE_PROJECTION',
      latestReceiptCompletedAt: '2026-08-01T00:05:00Z',
    },
    ...overrides,
  };
}

describe('AiBomDeclaredResourceDetailPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    navigateMock.mockReset();
  });

  it('renders declaration, source, component, and projection details', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail());
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);

    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    expect(await screen.findByText('UNVERIFIED')).toBeInTheDocument();
    expect(screen.getByText('CycloneDX')).toBeInTheDocument();
    expect(screen.getByText('pkg:huggingface/llama-3@3.1')).toBeInTheDocument();
  });

  it('lets an analyst propose a mapping', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail());
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    const propose = vi.spyOn(api, 'proposeAiBomMapping').mockResolvedValue(
      buildResource({ proposedArtifactId: 'artifact-9', proposedBy: 'user-analyst' }));

    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    const input = await screen.findByLabelText('Artifact ID to propose');
    fireEvent.change(input, { target: { value: 'artifact-9' } });
    fireEvent.click(screen.getByText('Propose mapping'));

    await waitFor(() => expect(propose).toHaveBeenCalledWith('resource-1', 'artifact-9'));
  });

  it('does not show approve controls to a plain analyst when a proposal is pending', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({
      resource: buildResource({ proposedArtifactId: 'artifact-9', proposedBy: 'user-analyst', proposedAt: '2026-08-02T00:00:00Z' }),
    }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);

    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    await screen.findByText('artifact-9');
    expect(screen.queryByText('Approve mapping')).not.toBeInTheDocument();
    expect(screen.getByText('Awaiting approval from an inventory admin or tenant admin.')).toBeInTheDocument();
  });

  it('lets a tenant admin approve a pending proposal', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail({
      resource: buildResource({ proposedArtifactId: 'artifact-9', proposedBy: 'user-analyst', proposedAt: '2026-08-02T00:00:00Z' }),
    }));
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([]);
    const approve = vi.spyOn(api, 'approveAiBomMapping').mockResolvedValue(
      buildResource({ deploymentState: 'LINKED', linkedArtifactId: 'artifact-9', linkMethod: 'REVIEWED', linkReviewedBy: 'user-admin' }));

    renderAs(TENANT_ADMIN_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    fireEvent.click(await screen.findByText('Approve mapping'));

    await waitFor(() => expect(approve).toHaveBeenCalledWith('resource-1'));
  });

  it('renders findings affecting this resource', async () => {
    vi.spyOn(api, 'getAiBomDeclaredResource').mockResolvedValue(buildDetail());
    vi.spyOn(api, 'getAiBomDeclaredResourceFindings').mockResolvedValue([buildFinding({ id: 'finding-7', displayId: 'F-000007' })]);

    renderAs(ANALYST_ACTOR, <AiBomDeclaredResourceDetailPage resourceId="resource-1" />);

    expect(await screen.findByText('F-000007')).toBeInTheDocument();
  });
});
