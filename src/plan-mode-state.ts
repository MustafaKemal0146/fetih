/**
 * @fileoverview Plan modu global state — REPL ile araçlar arasında sinyal taşır.
 */

export interface PlanModeState {
  /** Kullanıcı tarafından aktif edilen plan modu bayrağı. */
  enabled: boolean;
  active: boolean;
  reason: string;
  planText: string;
  waitingForApproval: boolean;
  approved?: boolean;
}

let planState: PlanModeState = {
  enabled: false,
  active: false,
  reason: '',
  planText: '',
  waitingForApproval: false,
};

export function getPlanModeState(): PlanModeState {
  return planState;
}

export function setPlanModeState(patch: Partial<PlanModeState>): void {
  planState = { ...planState, ...patch };
}

export function resetPlanModeState(): void {
  planState = {
    enabled: planState.enabled, // enabled flag'i koru
    active: false,
    reason: '',
    planText: '',
    waitingForApproval: false,
  };
}

export function isPlanModeActive(): boolean {
  return planState.active;
}

export function isPlanModeEnabled(): boolean {
  return planState.enabled;
}

export function setPlanModeEnabled(value: boolean): void {
  planState = { ...planState, enabled: value };
}

export function isPlanWaitingApproval(): boolean {
  return planState.waitingForApproval;
}

export function approvePlan(): void {
  planState = { ...planState, waitingForApproval: false, approved: true };
}

export function rejectPlan(): void {
  planState = { ...planState, waitingForApproval: false, approved: false, active: false };
}
