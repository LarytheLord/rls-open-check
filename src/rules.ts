import type { RuleId, Severity } from "./types.js";

export interface RuleInfo {
  id: RuleId;
  name: string;
  description: string;
  severity: Severity;
}

export const RULES: RuleInfo[] = [
  { id: "R1", name: "TableWithoutRls", severity: "critical", description: "Table in the public schema never has Row Level Security enabled." },
  { id: "R2", name: "OpenPolicyForAnon", severity: "high", description: "Policy lets anon or public use rows with a condition that is always true." },
  { id: "R3", name: "AuthenticatedChangesAnyRow", severity: "high", description: "Policy lets any logged-in user update or delete any row." },
  { id: "R4", name: "AnonGrantWithoutRls", severity: "high", description: "anon is granted privileges on a table that has no Row Level Security." },
  { id: "R5", name: "SecurityDefinerWithoutSearchPath", severity: "medium", description: "SECURITY DEFINER function has no SET search_path." },
  { id: "R6", name: "RlsDisabled", severity: "critical", description: "Row Level Security was disabled on a table in the public schema." },
  { id: "R7", name: "GrantWithoutPolicy", severity: "high", description: "anon or authenticated has SELECT, INSERT, UPDATE or DELETE on a public table, and RLS is off or no policy covers that command." },
  { id: "R8", name: "PolicyReadsUserMetadata", severity: "high", description: "Policy reads user_metadata or raw_user_meta_data, which users can edit themselves." },
  { id: "R9", name: "SecurityDefinerExecutableByApiRole", severity: "medium", description: "SECURITY DEFINER function in public can be run by anon or authenticated through the Data API." },
  { id: "R10", name: "AuthenticatedReadsEveryRow", severity: "medium", description: "Policy lets any logged-in user read every row, with USING (true) for authenticated. Low when the table has no owner column (user_id, owner_id, created_by, profile_id, author_id, account_id, tenant_id, org_id)." },
  { id: "R11", name: "PolicyOnlyChecksLoggedIn", severity: "medium", description: "Policy only checks that someone is logged in (auth.uid() IS NOT NULL or auth.role() = 'authenticated'), with no comparison to a column. Not reported when R2 or R3 already reports the policy." },
  { id: "R12", name: "AnonInsertWithoutIdentityCheck", severity: "low", description: "INSERT policy for anon or public whose WITH CHECK never reads auth.uid(), auth.jwt() or auth.email(): anyone can insert rows. Always low: most anonymous inserts in a hand-read sample were intended. The message says when INSERT was revoked from anon." },
];

const DOCS_BASE = "https://github.com/LarytheLord/rls-open-check#";

/** README anchor for a rule: the "### R1" heading slugs to "r1". */
export function ruleDocsUrl(id: RuleId): string {
  return DOCS_BASE + id.toLowerCase();
}
