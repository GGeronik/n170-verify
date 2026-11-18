/**
 * N170 Verify - Read-Only Connector Status, Capabilities & Scope Validation.
 *
 * Exposes live connector capabilities parsed from connectorCapabilities.json,
 * enforces read-only scope boundaries (hard abort on trading / withdrawal scopes),
 * and maps provider approval states to anti-slop compliant UI status pills.
 */

import {
  AccountScope,
  OriginAssurance,
  ProviderApprovalState,
} from "./contracts.ts";
import rawCapabilities from "./connectorCapabilities.json" with { type: "json" };

export interface ConnectorCapabilityDescriptor {
  broker_id: string;
  display_name: string;
  approval_state: ProviderApprovalState | string;
  default_origin_assurance: OriginAssurance | string;
  supports_subaccount_enumeration: boolean;
  allowed_capabilities: readonly string[];
}

export type StatusPillVariant = "emerald" | "champagne" | "ochre" | "neutral";

export interface StatusPillConfig {
  label: string;
  variant: StatusPillVariant;
  approvalState: ProviderApprovalState | string;
  defaultOrigin: OriginAssurance;
  accountScope: AccountScope;
  securityNote: string;
  scopeNote: string;
}

const FORBIDDEN_SCOPE_PATTERNS: readonly RegExp[] = [
  /\btrad(?:e|ing)\b/i,
  /\bwithdraw(?:al)?\b/i,
  /\btransfer\b/i,
  /\border\b/i,
  /\bwrite\b/i,
  /\bexecute\b/i,
];

export const CONNECTOR_DESCRIPTORS: readonly ConnectorCapabilityDescriptor[] =
  rawCapabilities as readonly ConnectorCapabilityDescriptor[];

export function getAllConnectorDescriptors(): readonly ConnectorCapabilityDescriptor[] {
  return CONNECTOR_DESCRIPTORS;
}

export function getConnectorDescriptor(
  brokerId: string,
): ConnectorCapabilityDescriptor | undefined {
  const norm = brokerId.trim().toLowerCase();
  const aliasMap: Record<string, string> = {
    ibkr: "ibkr_oauth",
    ibkr_flex: "ibkr_flex_web",
    schwab: "schwab",
    schwab_csv: "schwab_csv",
    degiro: "degiro_csv",
    robinhood: "robinhood_csv",
    mt4: "mt4_statement",
    mt5: "mt5_statement",
    tradovate: "tradovate_csv",
    ctrader: "ctrader_oauth",
    tradersync: "journal_migration",
    tradezella: "journal_migration",
  };
  const target = aliasMap[norm] ?? norm;
  return CONNECTOR_DESCRIPTORS.find((d) => d.broker_id === target);
}

export function listSupportedBrokerIds(): string[] {
  return CONNECTOR_DESCRIPTORS.map((d) => d.broker_id);
}

export function isCapabilityAllowed(
  brokerId: string,
  capability: string,
): boolean {
  const desc = getConnectorDescriptor(brokerId);
  if (!desc) return false;
  return desc.allowed_capabilities.includes(capability);
}

export function resolveStatusPill(approvalState: string | ProviderApprovalState): {
  label: string;
  variant: StatusPillVariant;
} {
  switch (approvalState) {
    case ProviderApprovalState.APPROVED_LIVE:
    case "approved_live":
      return { label: "Verified Direct", variant: "emerald" };
    case ProviderApprovalState.USER_KEY_SELF_ATTESTED:
    case "user_key_self_attested":
      return { label: "Active Read-Only Key", variant: "champagne" };
    case ProviderApprovalState.PENDING_PROVIDER_APPROVAL:
    case "pending_provider_approval":
      return { label: "Pending Provider Approval", variant: "ochre" };
    case ProviderApprovalState.OFFLINE_EXPORT_ONLY:
    case "offline_export_only":
      return { label: "Offline Export", variant: "neutral" };
    case ProviderApprovalState.AGGREGATOR_RELAYED:
    case "aggregator_relayed":
      return { label: "Aggregator Relayed (5-Slot)", variant: "ochre" };
    case ProviderApprovalState.PUBLIC_API_PERMISSIONLESS:
    case "public_api_permissionless":
      return { label: "Public Permissionless", variant: "emerald" };
    default:
      return { label: "Self-Reported", variant: "neutral" };
  }
}

export function validateReadOnlyScopeString(scopeString: string): {
  allowed: boolean;
  rejectedTokens: string[];
} {
  const tokens = scopeString
    .split(/[\s,;:|]+/)
    .map((t) => t.trim())
    .filter(Boolean);
  const rejected: string[] = [];

  for (const token of tokens) {
    for (const pattern of FORBIDDEN_SCOPE_PATTERNS) {
      if (pattern.test(token)) {
        rejected.push(token);
        break;
      }
    }
  }

  return {
    allowed: rejected.length === 0,
    rejectedTokens: rejected,
  };
}

export function validateScopePermissions(
  brokerId: string,
  scopes: readonly string[],
): {
  allowed: boolean;
  violations: string[];
} {
  const violations: string[] = [];
  for (const s of scopes) {
    const res = validateReadOnlyScopeString(s);
    if (!res.allowed) {
      violations.push(...res.rejectedTokens);
    }
  }
  return {
    allowed: violations.length === 0,
    violations,
  };
}
