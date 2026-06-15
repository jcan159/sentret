/**
 * Offline MITRE ATT&CK lookup helper backing the `lookup_mitre_attack` tool.
 *
 * Provides the 14 Enterprise tactics (with the Microsoft Sentinel tactic enum
 * spellings used in scheduled analytics rules) and a curated subset of
 * Enterprise techniques/sub-techniques most relevant to cloud, identity,
 * endpoint and email detection engineering (ATT&CK v14+ naming).
 *
 * This is intentionally an offline snapshot: no network calls, no full corpus.
 * Every lookup result carries a caveat saying so.
 */

import type { MitreLookupResult, MitreTactic, MitreTechnique } from "../types.js";

// ---------------------------------------------------------------------------
// Tactics
// ---------------------------------------------------------------------------

/** All 14 MITRE ATT&CK Enterprise tactics, in kill-chain order. */
export const MITRE_TACTICS: MitreTactic[] = [
  { id: "TA0043", name: "Reconnaissance", sentinelName: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development", sentinelName: "ResourceDevelopment" },
  { id: "TA0001", name: "Initial Access", sentinelName: "InitialAccess" },
  { id: "TA0002", name: "Execution", sentinelName: "Execution" },
  { id: "TA0003", name: "Persistence", sentinelName: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation", sentinelName: "PrivilegeEscalation" },
  { id: "TA0005", name: "Defense Evasion", sentinelName: "DefenseEvasion" },
  { id: "TA0006", name: "Credential Access", sentinelName: "CredentialAccess" },
  { id: "TA0007", name: "Discovery", sentinelName: "Discovery" },
  { id: "TA0008", name: "Lateral Movement", sentinelName: "LateralMovement" },
  { id: "TA0009", name: "Collection", sentinelName: "Collection" },
  { id: "TA0011", name: "Command and Control", sentinelName: "CommandAndControl" },
  { id: "TA0010", name: "Exfiltration", sentinelName: "Exfiltration" },
  { id: "TA0040", name: "Impact", sentinelName: "Impact" },
];

// ---------------------------------------------------------------------------
// Techniques (curated subset, ATT&CK v14+ names)
// ---------------------------------------------------------------------------

// Shorthand tactic-id constants keep the table below readable and typo-proof.
const RECON = "TA0043";
const RESDEV = "TA0042";
const IA = "TA0001";
const EXEC = "TA0002";
const PERS = "TA0003";
const PRIV = "TA0004";
const DEFEV = "TA0005";
const CRED = "TA0006";
const DISC = "TA0007";
const LAT = "TA0008";
const COLL = "TA0009";
const EXFIL = "TA0010";
const C2 = "TA0011";
const IMPACT = "TA0040";

/**
 * Curated subset of Enterprise techniques and key sub-techniques relevant to
 * cloud/identity/endpoint/email detection engineering. Not the full corpus.
 */
export const MITRE_TECHNIQUES: MitreTechnique[] = [
  // --- Reconnaissance / Resource Development -------------------------------
  { id: "T1595", name: "Active Scanning", tacticIds: [RECON] },
  { id: "T1598", name: "Phishing for Information", tacticIds: [RECON] },
  { id: "T1583", name: "Acquire Infrastructure", tacticIds: [RESDEV] },
  { id: "T1586", name: "Compromise Accounts", tacticIds: [RESDEV] },

  // --- Initial Access ------------------------------------------------------
  { id: "T1190", name: "Exploit Public-Facing Application", tacticIds: [IA] },
  { id: "T1133", name: "External Remote Services", tacticIds: [PERS, IA] },
  { id: "T1199", name: "Trusted Relationship", tacticIds: [IA] },
  { id: "T1566", name: "Phishing", tacticIds: [IA] },
  { id: "T1566.001", name: "Spearphishing Attachment", tacticIds: [IA] },
  { id: "T1566.002", name: "Spearphishing Link", tacticIds: [IA] },
  { id: "T1078", name: "Valid Accounts", tacticIds: [DEFEV, PERS, PRIV, IA] },
  { id: "T1078.002", name: "Domain Accounts", tacticIds: [DEFEV, PERS, PRIV, IA] },
  { id: "T1078.003", name: "Local Accounts", tacticIds: [DEFEV, PERS, PRIV, IA] },
  { id: "T1078.004", name: "Cloud Accounts", tacticIds: [DEFEV, PERS, PRIV, IA] },

  // --- Execution -----------------------------------------------------------
  { id: "T1059", name: "Command and Scripting Interpreter", tacticIds: [EXEC] },
  { id: "T1059.001", name: "PowerShell", tacticIds: [EXEC] },
  { id: "T1059.003", name: "Windows Command Shell", tacticIds: [EXEC] },
  { id: "T1059.004", name: "Unix Shell", tacticIds: [EXEC] },
  { id: "T1059.009", name: "Cloud API", tacticIds: [EXEC] },
  { id: "T1047", name: "Windows Management Instrumentation", tacticIds: [EXEC] },
  { id: "T1204", name: "User Execution", tacticIds: [EXEC] },
  { id: "T1204.001", name: "Malicious Link", tacticIds: [EXEC] },
  { id: "T1204.002", name: "Malicious File", tacticIds: [EXEC] },
  { id: "T1648", name: "Serverless Execution", tacticIds: [EXEC] },
  { id: "T1053", name: "Scheduled Task/Job", tacticIds: [EXEC, PERS, PRIV] },
  { id: "T1053.005", name: "Scheduled Task", tacticIds: [EXEC, PERS, PRIV] },

  // --- Persistence ---------------------------------------------------------
  { id: "T1098", name: "Account Manipulation", tacticIds: [PERS, PRIV] },
  { id: "T1098.001", name: "Additional Cloud Credentials", tacticIds: [PERS, PRIV] },
  { id: "T1098.003", name: "Additional Cloud Roles", tacticIds: [PERS, PRIV] },
  { id: "T1098.005", name: "Device Registration", tacticIds: [PERS, PRIV] },
  { id: "T1136", name: "Create Account", tacticIds: [PERS] },
  { id: "T1136.003", name: "Cloud Account", tacticIds: [PERS] },
  { id: "T1547", name: "Boot or Logon Autostart Execution", tacticIds: [PERS, PRIV] },
  { id: "T1547.001", name: "Registry Run Keys / Startup Folder", tacticIds: [PERS, PRIV] },
  { id: "T1543", name: "Create or Modify System Process", tacticIds: [PERS, PRIV] },
  { id: "T1543.003", name: "Windows Service", tacticIds: [PERS, PRIV] },
  { id: "T1505", name: "Server Software Component", tacticIds: [PERS] },
  { id: "T1505.003", name: "Web Shell", tacticIds: [PERS] },
  { id: "T1546", name: "Event Triggered Execution", tacticIds: [PERS, PRIV] },

  // --- Privilege Escalation ------------------------------------------------
  { id: "T1548", name: "Abuse Elevation Control Mechanism", tacticIds: [PRIV, DEFEV] },
  { id: "T1068", name: "Exploitation for Privilege Escalation", tacticIds: [PRIV] },
  { id: "T1484", name: "Domain or Tenant Policy Modification", tacticIds: [DEFEV, PRIV] },

  // --- Defense Evasion -----------------------------------------------------
  { id: "T1562", name: "Impair Defenses", tacticIds: [DEFEV] },
  { id: "T1562.001", name: "Disable or Modify Tools", tacticIds: [DEFEV] },
  { id: "T1562.008", name: "Disable or Modify Cloud Logs", tacticIds: [DEFEV] },
  { id: "T1070", name: "Indicator Removal", tacticIds: [DEFEV] },
  { id: "T1070.001", name: "Clear Windows Event Logs", tacticIds: [DEFEV] },
  { id: "T1027", name: "Obfuscated Files or Information", tacticIds: [DEFEV] },
  { id: "T1036", name: "Masquerading", tacticIds: [DEFEV] },
  { id: "T1112", name: "Modify Registry", tacticIds: [DEFEV] },
  { id: "T1218", name: "System Binary Proxy Execution", tacticIds: [DEFEV] },
  { id: "T1550", name: "Use Alternate Authentication Material", tacticIds: [DEFEV, LAT] },
  { id: "T1550.001", name: "Application Access Token", tacticIds: [DEFEV, LAT] },
  { id: "T1550.004", name: "Web Session Cookie", tacticIds: [DEFEV, LAT] },

  // --- Credential Access ---------------------------------------------------
  { id: "T1110", name: "Brute Force", tacticIds: [CRED] },
  { id: "T1110.001", name: "Password Guessing", tacticIds: [CRED] },
  { id: "T1110.002", name: "Password Cracking", tacticIds: [CRED] },
  { id: "T1110.003", name: "Password Spraying", tacticIds: [CRED] },
  { id: "T1110.004", name: "Credential Stuffing", tacticIds: [CRED] },
  { id: "T1556", name: "Modify Authentication Process", tacticIds: [CRED, DEFEV, PERS] },
  { id: "T1556.006", name: "Multi-Factor Authentication", tacticIds: [CRED, DEFEV, PERS] },
  { id: "T1621", name: "Multi-Factor Authentication Request Generation", tacticIds: [CRED] },
  { id: "T1539", name: "Steal Web Session Cookie", tacticIds: [CRED] },
  { id: "T1528", name: "Steal Application Access Token", tacticIds: [CRED] },
  { id: "T1606", name: "Forge Web Credentials", tacticIds: [CRED] },
  { id: "T1606.002", name: "SAML Tokens", tacticIds: [CRED] },
  { id: "T1003", name: "OS Credential Dumping", tacticIds: [CRED] },
  { id: "T1003.001", name: "LSASS Memory", tacticIds: [CRED] },
  { id: "T1003.006", name: "DCSync", tacticIds: [CRED] },
  { id: "T1555", name: "Credentials from Password Stores", tacticIds: [CRED] },
  { id: "T1552", name: "Unsecured Credentials", tacticIds: [CRED] },
  { id: "T1558", name: "Steal or Forge Kerberos Tickets", tacticIds: [CRED] },
  { id: "T1558.003", name: "Kerberoasting", tacticIds: [CRED] },
  { id: "T1557", name: "Adversary-in-the-Middle", tacticIds: [CRED, COLL] },

  // --- Discovery -----------------------------------------------------------
  { id: "T1087", name: "Account Discovery", tacticIds: [DISC] },
  { id: "T1087.004", name: "Cloud Account", tacticIds: [DISC] },
  { id: "T1069", name: "Permission Groups Discovery", tacticIds: [DISC] },
  { id: "T1018", name: "Remote System Discovery", tacticIds: [DISC] },
  { id: "T1046", name: "Network Service Discovery", tacticIds: [DISC] },
  { id: "T1526", name: "Cloud Service Discovery", tacticIds: [DISC] },
  { id: "T1580", name: "Cloud Infrastructure Discovery", tacticIds: [DISC] },
  { id: "T1082", name: "System Information Discovery", tacticIds: [DISC] },
  { id: "T1083", name: "File and Directory Discovery", tacticIds: [DISC] },

  // --- Lateral Movement ----------------------------------------------------
  { id: "T1021", name: "Remote Services", tacticIds: [LAT] },
  { id: "T1021.001", name: "Remote Desktop Protocol", tacticIds: [LAT] },
  { id: "T1021.002", name: "SMB/Windows Admin Shares", tacticIds: [LAT] },
  { id: "T1021.004", name: "SSH", tacticIds: [LAT] },
  { id: "T1021.007", name: "Cloud Services", tacticIds: [LAT] },
  { id: "T1534", name: "Internal Spearphishing", tacticIds: [LAT] },
  { id: "T1570", name: "Lateral Tool Transfer", tacticIds: [LAT] },

  // --- Collection ----------------------------------------------------------
  { id: "T1530", name: "Data from Cloud Storage", tacticIds: [COLL] },
  { id: "T1114", name: "Email Collection", tacticIds: [COLL] },
  { id: "T1114.002", name: "Remote Email Collection", tacticIds: [COLL] },
  { id: "T1114.003", name: "Email Forwarding Rule", tacticIds: [COLL] },
  { id: "T1005", name: "Data from Local System", tacticIds: [COLL] },
  { id: "T1560", name: "Archive Collected Data", tacticIds: [COLL] },

  // --- Command and Control -------------------------------------------------
  { id: "T1071", name: "Application Layer Protocol", tacticIds: [C2] },
  { id: "T1071.001", name: "Web Protocols", tacticIds: [C2] },
  { id: "T1071.004", name: "DNS", tacticIds: [C2] },
  { id: "T1105", name: "Ingress Tool Transfer", tacticIds: [C2] },
  { id: "T1568", name: "Dynamic Resolution", tacticIds: [C2] },
  { id: "T1568.002", name: "Domain Generation Algorithms", tacticIds: [C2] },
  { id: "T1572", name: "Protocol Tunneling", tacticIds: [C2] },
  { id: "T1102", name: "Web Service", tacticIds: [C2] },

  // --- Exfiltration --------------------------------------------------------
  { id: "T1041", name: "Exfiltration Over C2 Channel", tacticIds: [EXFIL] },
  { id: "T1020", name: "Automated Exfiltration", tacticIds: [EXFIL] },
  { id: "T1048", name: "Exfiltration Over Alternative Protocol", tacticIds: [EXFIL] },
  { id: "T1048.003", name: "Exfiltration Over Unencrypted Non-C2 Protocol", tacticIds: [EXFIL] },
  { id: "T1567", name: "Exfiltration Over Web Service", tacticIds: [EXFIL] },
  { id: "T1567.002", name: "Exfiltration to Cloud Storage", tacticIds: [EXFIL] },
  { id: "T1537", name: "Transfer Data to Cloud Account", tacticIds: [EXFIL] },

  // --- Impact --------------------------------------------------------------
  { id: "T1486", name: "Data Encrypted for Impact", tacticIds: [IMPACT] },
  { id: "T1490", name: "Inhibit System Recovery", tacticIds: [IMPACT] },
  { id: "T1489", name: "Service Stop", tacticIds: [IMPACT] },
  { id: "T1485", name: "Data Destruction", tacticIds: [IMPACT] },
  { id: "T1531", name: "Account Access Removal", tacticIds: [IMPACT] },
  { id: "T1496", name: "Resource Hijacking", tacticIds: [IMPACT] },
];

// ---------------------------------------------------------------------------
// Id validation
// ---------------------------------------------------------------------------

const TACTIC_ID_RE = /^TA\d{4}$/;
const TECHNIQUE_ID_RE = /^T\d{4}(\.\d{3})?$/;

/** True when `id` is a well-formed ATT&CK tactic id, e.g. "TA0001". */
export function isValidTacticId(id: string): boolean {
  return TACTIC_ID_RE.test(id);
}

/** True when `id` is a well-formed technique or sub-technique id, e.g. "T1110" / "T1110.003". */
export function isValidTechniqueId(id: string): boolean {
  return TECHNIQUE_ID_RE.test(id);
}

// ---------------------------------------------------------------------------
// Indexes
// ---------------------------------------------------------------------------

const TACTIC_BY_ID = new Map(MITRE_TACTICS.map((t) => [t.id, t]));
const TECHNIQUE_BY_ID = new Map(MITRE_TECHNIQUES.map((t) => [t.id, t]));

function normalizeKey(value: string): string {
  return value.toLowerCase().replace(/[\s_-]+/g, "");
}

/** Normalised display name / Sentinel name / TA id -> Sentinel enum value. */
const SENTINEL_TACTIC_BY_KEY = new Map<string, string>();
for (const tactic of MITRE_TACTICS) {
  SENTINEL_TACTIC_BY_KEY.set(normalizeKey(tactic.name), tactic.sentinelName);
  SENTINEL_TACTIC_BY_KEY.set(normalizeKey(tactic.sentinelName), tactic.sentinelName);
  SENTINEL_TACTIC_BY_KEY.set(normalizeKey(tactic.id), tactic.sentinelName);
}

// ---------------------------------------------------------------------------
// Sentinel tactic mapping
// ---------------------------------------------------------------------------

/**
 * Maps a tactic display name ("Lateral Movement"), TA id ("TA0008") or
 * already-Sentinel-spelled name ("LateralMovement") to the Sentinel tactic
 * enum value used in analytics rules. Case-insensitive; ignores spaces,
 * hyphens and underscores. Returns undefined when nothing matches.
 */
export function toSentinelTactic(input: string): string | undefined {
  const key = normalizeKey(input.trim());
  if (key === "") return undefined;
  return SENTINEL_TACTIC_BY_KEY.get(key);
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

/**
 * Splits a free-form query into lookup terms. Commas/semicolons/newlines
 * separate terms; within a segment, whitespace-separated tokens that look
 * like ATT&CK ids become their own terms, while the remaining words are
 * kept together as a single phrase (so "brute force" matches as a phrase).
 */
function parseTerms(query: string): string[] {
  const terms: string[] = [];
  for (const segment of query.split(/[,;\n]+/)) {
    const phraseWords: string[] = [];
    for (const token of segment.trim().split(/\s+/)) {
      if (token === "") continue;
      const upper = token.toUpperCase();
      if (TACTIC_ID_RE.test(upper) || TECHNIQUE_ID_RE.test(upper)) {
        terms.push(token);
      } else {
        phraseWords.push(token);
      }
    }
    if (phraseWords.length > 0) terms.push(phraseWords.join(" "));
  }
  return terms;
}

/**
 * For name matching, a sub-technique is also addressable through its
 * ATT&CK-style composite name ("Brute Force: Password Spraying") so that a
 * parent-name phrase like "brute force" returns the whole family.
 */
function techniqueNameMatches(tech: MitreTechnique, needle: string): boolean {
  if (tech.name.toLowerCase().includes(needle)) return true;
  const dot = tech.id.indexOf(".");
  if (dot === -1) return false;
  const parent = TECHNIQUE_BY_ID.get(tech.id.slice(0, dot));
  if (!parent) return false;
  return `${parent.name}: ${tech.name}`.toLowerCase().includes(needle);
}

/**
 * Looks up MITRE ATT&CK tactics, techniques and sub-techniques in the curated
 * offline dataset.
 *
 * Each comma/whitespace-derived term is resolved as follows:
 * - exact TA id -> that tactic; exact T id -> that technique (a sub-technique
 *   id also pulls in its parent technique when present), both case-insensitive;
 * - otherwise, case-insensitive substring match of the whole phrase against
 *   tactic and technique names.
 *
 * Results are deduped. `notes` always carries the offline-subset caveat and
 * lists any terms that matched nothing.
 */
export function lookupMitre(query: string): MitreLookupResult {
  const terms = parseTerms(query);
  const tactics = new Map<string, MitreTactic>();
  const techniques = new Map<string, MitreTechnique>();
  const unmatched: string[] = [];

  for (const term of terms) {
    let matched = false;
    const upper = term.toUpperCase();

    if (TACTIC_ID_RE.test(upper)) {
      const tactic = TACTIC_BY_ID.get(upper);
      if (tactic) {
        tactics.set(tactic.id, tactic);
        matched = true;
      }
    } else if (TECHNIQUE_ID_RE.test(upper)) {
      const tech = TECHNIQUE_BY_ID.get(upper);
      if (tech) {
        const dot = tech.id.indexOf(".");
        if (dot !== -1) {
          const parent = TECHNIQUE_BY_ID.get(tech.id.slice(0, dot));
          if (parent) techniques.set(parent.id, parent);
        }
        techniques.set(tech.id, tech);
        matched = true;
      }
    } else {
      const needle = term.toLowerCase();
      for (const tactic of MITRE_TACTICS) {
        if (
          tactic.name.toLowerCase().includes(needle) ||
          tactic.sentinelName.toLowerCase().includes(needle)
        ) {
          tactics.set(tactic.id, tactic);
          matched = true;
        }
      }
      for (const tech of MITRE_TECHNIQUES) {
        if (techniqueNameMatches(tech, needle)) {
          techniques.set(tech.id, tech);
          matched = true;
        }
      }
    }

    if (!matched) unmatched.push(term);
  }

  const notes: string[] = [
    "Results come from a curated offline subset of MITRE ATT&CK (Enterprise), not the full corpus; a missing entry here does not mean the tactic or technique does not exist in ATT&CK.",
  ];
  if (unmatched.length > 0) {
    notes.push(`No match found in the curated dataset for: ${unmatched.join(", ")}.`);
  }

  return {
    query,
    tactics: [...tactics.values()],
    techniques: [...techniques.values()],
    notes,
  };
}
