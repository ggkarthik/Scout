import React from 'react';
import { EolDetailDrawer } from './EolDetailDrawer';
import { ConfirmDialog } from './ConfirmDialog';
import {
  type CveMatchedSoftware,
  type CveDetail,
  type OrgSpecificCveExposureRecord,
} from '../features/cve-workbench/types';
import {
  formatDate,
  formatLabel,
  severityClassName,
} from '../features/cve-workbench/formatting';
import { CveSummarySidebar } from '../features/cve-workbench/components/CveSummarySidebar';
import { InvestigationContent } from '../features/cve-workbench/components/InvestigationContent';
import {
  ApplicabilityTable,
  DecisionSummary
} from '../features/cve-workbench/components/ApplicabilityPanel';
import {
  FindingConfigSidebar,
  FindingsContent
} from '../features/cve-workbench/components/FindingsPanel';
import {
  useCveWorkbenchAssessment
} from '../features/cve-workbench/hooks/useCveWorkbenchAssessment';
import {
  useCveWorkbenchFindings
} from '../features/cve-workbench/hooks/useCveWorkbenchFindings';
import {
  usePendingNavigationGuard
} from '../features/cve-workbench/hooks/usePendingNavigationGuard';
import type { RiskPolicy } from '../features/configurations/types';

type WorkflowStep = 1 | 2 | 3;

type Props = {
  item: OrgSpecificCveExposureRecord;
  detail: CveDetail | null;
  loading: boolean;
  error: string | null;
  findingGenerationMode: RiskPolicy['findingGenerationMode'];
  analystId?: string;
  onBack: () => void;
  onRefreshDetail: (options?: { includeList?: boolean }) => Promise<void>;
};

// --- Main Component ---

export function CveAssessmentWorkbench({ item, detail, loading, error, findingGenerationMode, analystId, onBack, onRefreshDetail }: Props) {
  const [activeStep, setActiveStep] = React.useState<WorkflowStep>(1);
  const [actionNotice, setActionNotice] = React.useState<string | null>(null);
  const [actionError, setActionError] = React.useState<string | null>(null);

  // EOL detail drawer
  const [eolDrawer, setEolDrawer] = React.useState<CveMatchedSoftware | null>(null);

  // Finding creation confirmation
  const [pendingFindingAction, setPendingFindingAction] = React.useState<(() => Promise<void>) | null>(null);
  const assessment = useCveWorkbenchAssessment({
    item,
    detail,
    onRefreshDetail,
    setActionNotice,
    setActionError,
  });
  const findings = useCveWorkbenchFindings({
    item,
    detail,
    currentApplicableSoftware: assessment.currentApplicableSoftware,
    applicabilityDecisions: assessment.applicabilityDecisions,
    impactDecisions: assessment.impactDecisions,
    onRefreshDetail,
    setActionNotice,
    setActionError,
  });
  const navigationGuard = usePendingNavigationGuard(assessment.isDirty);

  const currentBreadcrumbStep = activeStep === 1 ? null : activeStep === 2 ? 'Applicability' : 'Create Findings';

  const stepLabels: Array<{ step: WorkflowStep; label: string }> = [
    { step: 1, label: 'Investigation' },
    { step: 2, label: 'Applicability' },
    { step: 3, label: 'Create Findings' },
  ];

  return (
    <div className="cve-assessment-page">
      {/* Breadcrumb */}
      <div className="cve-assessment-breadcrumb">
        <button type="button" onClick={() => navigationGuard.guardedNav(onBack)}>CVE Assessment</button>
        <span aria-hidden="true">›</span>
        <button type="button" onClick={() => navigationGuard.guardedNav(() => setActiveStep(1))}>{item.externalId}</button>
        {currentBreadcrumbStep && (
          <>
            <span aria-hidden="true">›</span>
            <span>{currentBreadcrumbStep}</span>
          </>
        )}
      </div>

      {/* Header */}
      <div className="cve-assessment-header">
        <div className="cve-assessment-header-left">
          <span className="cve-assessment-id">{item.externalId}</span>
          <span className={severityClassName(item.severity)}>{formatLabel(item.severity)}</span>
          {item.cvssScore != null && <span className="cve-score-pill">{item.cvssScore.toFixed(1)}</span>}
          {item.inKev ? (
            <span className="severity-pill severity-critical" title="CISA Known Exploited Vulnerabilities catalog">
              Actively Exploited (KEV)
            </span>
          ) : detail?.signals.exploitAvailable ? (
            <span className="status-pill status-in-progress">
              {detail.signals.exploitReason || 'Exploit Signal Present'}
            </span>
          ) : null}
        </div>
        <span className="cve-assessment-last-reviewed">
          Last evaluated {item.lastEvaluatedAt ? formatDate(item.lastEvaluatedAt) : '-'}
        </span>
      </div>

      {/* Stepper */}
      <div className="cve-stepper">
        {stepLabels.map(({ step, label }, index) => (
          <React.Fragment key={step}>
            {index > 0 && <span className="cve-stepper-connector" aria-hidden="true">›</span>}
            <div
              className={`cve-stepper-item ${activeStep === step ? 'active' : ''} ${activeStep > step ? 'completed' : ''}`}
            >
              <span className="cve-stepper-number">
                {activeStep > step ? (
                  <svg viewBox="0 0 14 14" fill="none" aria-hidden="true">
                    <path d="M2.5 7L5.5 10L11.5 4" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                ) : step}
              </span>
              <span className="cve-stepper-label">{label}</span>
            </div>
          </React.Fragment>
        ))}
      </div>

      {loading ? (
        <div className="notice">Loading CVE details...</div>
      ) : error ? (
        <div className="notice error">{error}</div>
      ) : !detail ? (
        <div className="notice error">No detail available for this CVE.</div>
      ) : (
        <>
          {actionNotice && <div className="notice">{actionNotice}</div>}
          {actionError && <div className="notice error">{actionError}</div>}

          {/* Step 1 — Investigation */}
          {activeStep === 1 && (
            <div className="cve-assessment-layout">
              <CveSummarySidebar detail={detail} cvssFields={assessment.cvssFields} softwareGroups={assessment.softwareGroups} />
              <div className="cve-investigation-main">
                <InvestigationContent
                  item={item}
                  detail={detail}
                  softwareGroups={assessment.softwareGroups}
                  vendorRows={assessment.vendorRows}
                  overallConfidence={assessment.overallConfidence}
                  investigationNotes={assessment.investigationNotes}
                  autoNote={assessment.autoNote}
                  onNotesChange={assessment.setInvestigationNotes}
                  onEolClick={setEolDrawer}
                />
              </div>
            </div>
          )}

          {/* Step 2 — Applicability */}
          {activeStep === 2 && (
            <div className="cve-applicability-layout">
              <div className="cve-applicability-main">
                <ApplicabilityTable
                  matchedSoftware={detail.matchedSoftware}
                  applicabilityDecisions={assessment.applicabilityDecisions}
                  impactDecisions={assessment.impactDecisions}
                  expandedEvidenceComponentId={assessment.expandedEvidenceComponentId}
                  vexEvidenceByComponent={assessment.vexEvidenceByComponent}
                  vexEvidenceErrors={assessment.vexEvidenceErrors}
                  vexEvidenceLoadingComponentId={assessment.vexEvidenceLoadingComponentId}
                  onApplicabilityDecision={assessment.setApplicabilityDecision}
                  onBulkApplicabilityDecision={assessment.applyBulkApplicabilityDecision}
                  onImpactDecision={assessment.setImpactDecision}
                  onToggleVexEvidence={assessment.toggleVexEvidence}
                  onEolClick={setEolDrawer}
                />
              </div>
              <DecisionSummary
                matchedSoftware={detail.matchedSoftware}
                applicabilityDecisions={assessment.applicabilityDecisions}
                impactDecisions={assessment.impactDecisions}
                analystRationale={assessment.analystRationale}
                onAnalystRationaleChange={assessment.setAnalystRationale}
                latestAssessment={assessment.latestAssessment}
                saveBusy={assessment.assessmentBusy}
                analystId={analystId}
                onSave={() => { void assessment.saveAssessment(); }}
                onProceed={() => {
                  void assessment.saveAssessment({ showSuccessNotice: false }).then((saved) => {
                    if (saved) setActiveStep(3);
                  });
                }}
                onBack={() => navigationGuard.guardedNav(() => setActiveStep(1))}
              />
            </div>
          )}

          {/* Step 3 — Create Findings */}
          {activeStep === 3 && (
            <div className="cve-applicability-layout">
              <FindingsContent
                filteredSoftware={findings.filteredFindingSoftware}
                selectedIds={findings.selectedFindingIds}
                groupBy={findings.findingGroupBy}
                showFilter={findings.findingShowFilter}
                severity={item.severity}
                onToggleRow={findings.toggleFindingRow}
                onSelectAll={findings.selectAllFindings}
                onClearAll={findings.clearAllFindings}
                onGroupByChange={findings.setFindingGroupBy}
                onShowFilterChange={findings.setFindingShowFilter}
                onEolClick={setEolDrawer}
              />
              <FindingConfigSidebar
                filteredSoftware={findings.filteredFindingSoftware}
                selectedIds={findings.selectedFindingIds}
                findingGenerationMode={findingGenerationMode}
                findingTitle={findings.findingTitle}
                findingPriority={findings.findingPriority}
                assignmentGroup={findings.assignmentGroup}
                ticketTarget={findings.ticketTarget}
                dueDate={findings.dueDate}
                findingNotes={findings.findingNotes}
                findingBusy={findings.findingBusy}
                onFindingTitleChange={findings.setFindingTitle}
                onFindingPriorityChange={findings.setFindingPriority}
                onAssignmentGroupChange={findings.setAssignmentGroup}
                onTicketTargetChange={findings.setTicketTarget}
                onDueDateChange={findings.setDueDate}
                onFindingNotesChange={findings.setFindingNotes}
                onRequestCreateFindings={() => setPendingFindingAction(() => findings.createFindings)}
                onRequestCreateGrouped={() => setPendingFindingAction(() => findings.createFindings)}
                onSaveAssessment={() => { void assessment.saveAssessment(); }}
                onBack={() => setActiveStep(2)}
              />
            </div>
          )}

          {/* Footer — only for step 1 */}
          {activeStep === 1 && (
            <div className="cve-assessment-footer">
              <div className="cve-assessment-footer-left">
                <button type="button" className="btn btn-secondary" onClick={() => navigationGuard.guardedNav(onBack)}>← Workbench</button>
                <button type="button" className="btn btn-secondary">Mark Deferred</button>
                <button type="button" className="btn btn-secondary">Export Evidence</button>
              </div>
              <div className="cve-assessment-footer-right">
                <button
                  type="button"
                  className="btn btn-primary"
                  onClick={() => {
                    void assessment.saveInvestigation().then((saved) => {
                      if (saved) setActiveStep(2);
                    });
                  }}
                  disabled={assessment.investigationBusy}
                >
                  {assessment.investigationBusy ? 'Saving...' : 'Continue to Applicability'}
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Unsaved-changes navigation guard */}
      <ConfirmDialog
        isOpen={navigationGuard.pendingNavAction !== null}
        title="Unsaved Changes"
        message="You have unsaved notes or rationale. Navigating away will discard them. Continue?"
        confirmLabel="Discard & Leave"
        cancelLabel="Stay"
        onConfirm={navigationGuard.confirmPendingNavigation}
        onCancel={navigationGuard.cancelPendingNavigation}
      />

      {/* Finding creation confirmation */}
      <ConfirmDialog
        isOpen={pendingFindingAction !== null}
        title={`Create ${findings.selectedFindingIds.size} Finding${findings.selectedFindingIds.size === 1 ? '' : 's'}?`}
        message="This will immediately create findings for the selected assets. Existing open findings for the same components will be reopened rather than duplicated."
        confirmLabel="Create Findings"
        cancelLabel="Cancel"
        onConfirm={() => {
          const action = pendingFindingAction;
          setPendingFindingAction(null);
          if (action) void action();
        }}
        onCancel={() => setPendingFindingAction(null)}
      />

      {/* EOL detail drawer */}
      {eolDrawer?.eolSlug && (
        <EolDetailDrawer
          slug={eolDrawer.eolSlug}
          cycle={eolDrawer.eolCycle ?? undefined}
          packageName={eolDrawer.packageName}
          version={eolDrawer.version ?? undefined}
          isEol={eolDrawer.isEol ?? undefined}
          eolDate={eolDrawer.eolDate ?? undefined}
          daysRemaining={eolDrawer.eolDaysRemaining ?? undefined}
          onClose={() => setEolDrawer(null)}
        />
      )}
    </div>
  );
}
