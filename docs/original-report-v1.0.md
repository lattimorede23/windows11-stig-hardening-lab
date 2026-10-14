# DISA STIG Compliance Audit and Hardening Report

### Microsoft Windows 11 Pro — Standalone Virtual Machine

|  |  |
| :---- | :---- |
| **Report Title** | Windows 11 STIG Compliance Assessment |
| **System Assessed** | DESKTOP-CRJIC3S (VirtualBox VM) |
| **Operating System** | Windows 11 Pro, Version 22H2, Build 22621.1848 |
| **Auditor** | Derrick Lattimore |
| **Framework** | DISA STIG for Microsoft Windows 11, Version 2 Release 7 (Benchmark Date: 01 Apr 2026\) |
| **Cross-Reference** | NIST SP 800-53 |
| **Tooling** | STIG Viewer 3.7, Local Security Policy (secpol.msc), Local Group Policy Editor, Registry Editor (regedit.exe), Computer Management (compmgmt.msc), Windows PowerShell (Administrator) |
| **Assessment Window** | 26 June 2026 – 01 July 2026 (evidence timestamps) |
| **Report Date** | 01 July 2026 |
| **Classification** | Unclassified |

---

## 1\. Executive Summary

This report documents a manual STIG compliance assessment of a Windows 11 Pro virtual machine against 10 controls drawn from the DISA Microsoft Windows 11 STIG (V2R7). The assessment was performed using STIG Viewer 3.7 to pull authoritative check and fix text, with compliance verified directly against the host via native Windows administrative tools and the registry.

Of the 10 controls audited, 3 were compliant at baseline (**Not a Finding**) and 7 were identified as **Findings**. Of those 7 findings, 6 were remediated during the assessment and verified as closed. One finding — AppLocker application control (WN11-00-000035) — could not be remediated because application allowlisting via AppLocker enforcement requires Windows 11 Enterprise or Education; the assessed system runs Windows 11 Pro, which does not support this capability. This is documented as an accepted risk / platform limitation rather than a closed finding.

**Baseline compliance rate:** 3/10 (30%) **Post-remediation compliance rate:** 9/10 (90%) **Residual open findings:** 1 (CAT II, blocked by OS edition, not resolvable without an edition upgrade)

The most significant control gaps at baseline were in credential and boundary protection: BitLocker pre-boot authentication was not configured, the account lockout threshold was set well above the STIG maximum, and both the built-in Administrator and Guest accounts retained their default, publicly-known names. All of these were corrected. One CAT I item — full-disk encryption itself (WN11-00-000030) — was scoped out of remediation and accepted as Not a Finding per the auditor's baseline determination; this call is flagged in Section 2.1 below because it does not cleanly satisfy the STIG's stated NA criteria and should be revisited before this report is relied upon for an accreditation decision.

---

## 2\. Scope and Methodology

The assessment covered 10 controls selected from the 262 rules published in the Windows 11 STIG (V2R7, 01 Apr 2026), spanning disk encryption, application control, account/authentication hardening, and audit logging. For each control, the auditor:

1. Pulled the official check text, severity (CAT I/II/III), and fix text from STIG Viewer 3.7.  
2. Verified the live system state using the tool specified in the check text (registry inspection via `regedit`, Local Security Policy, Local Group Policy, Computer Management, or PowerShell).  
3. Where a gap was identified, applied the documented fix text or registry remediation and re-verified the resulting state.  
4. Captured before/after screenshots as evidence for each control (provided separately as supporting artifacts to this report).

This was a manual, single-system, point-in-time assessment. It is not a substitute for an automated SCAP scan and does not cover the remaining 252 rules in the full benchmark.

### 2.1 Note on Control 1 (WN11-00-000030) Determination

The auditor recorded WN11-00-000030 (BitLocker full-disk encryption) as **Not a Finding**, citing infrastructure support and "standard for VM baseline" as justification. Evidence collected during the assessment (BitLocker Drive Encryption control panel) confirms BitLocker was **off** on the C: drive at the time of review. The STIG's actual NA criteria for this control are narrow — VDI implementations where the instance is deleted or refreshed on logoff, or AVD implementations with no data at rest. A persistent, standalone VirtualBox VM with a local user profile does not meet either exclusion as written.

This is flagged here rather than silently accepted: as documented, WN11-00-000030 should more accurately be recorded as an open CAT I finding with a compensating-control or risk-acceptance justification (e.g., "non-production lab VM, no sensitive data at rest, snapshot-based recovery"), not as Not a Finding. The distinction matters because CAT I findings are typically the first thing reviewed in an accreditation package, and an NA determination that doesn't match the STIG's own applicability language will not hold up under a second reviewer.

---

## 3\. Detailed Findings

### Control 1 — Full Disk Encryption

- **STIG ID:** WN11-00-000030 | **Group ID:** V-253259 | **Severity:** CAT I  
- **Rule Title:** Windows 11 information systems must use BitLocker to encrypt all disks to protect the confidentiality and integrity of all information at rest.  
- **Finding:** BitLocker Drive Encryption was confirmed **off** on the C: drive via Control Panel → BitLocker Drive Encryption.  
- **Action Taken:** None. Recorded as Not a Finding per auditor determination (see Section 2.1 for caveat on this call).  
- **Status:** **Not a Finding** (as recorded) / flagged for review — does not fully align with STIG NA criteria.

### Control 2 — BitLocker Pre-Boot Authentication (PIN)

- **STIG ID:** WN11-00-000031 | **Group ID:** V-253260 | **Severity:** CAT I  
- **Rule Title:** Windows 11 systems must use a BitLocker PIN for pre-boot authentication.  
- **Finding:** Required registry values under `HKLM\SOFTWARE\Policies\Microsoft\FVE` were absent, meaning pre-boot PIN authentication was not enforced.  
- **Action Taken:** Created/set the following REG\_DWORD values under `HKLM\SOFTWARE\Policies\Microsoft\FVE`:  
  - `UseAdvancedStartup` \= 1  
  - `UseTPMPIN` \= 1  
  - `UseTPMKeyPIN` \= 1  
- **Status:** **Remediated.** Registry verification confirms all three values present and set to `0x00000001 (1)`.

### Control 3 — BitLocker Minimum PIN Length

- **STIG ID:** WN11-00-000032 | **Group ID:** V-253261 | **Severity:** CAT II  
- **Rule Title:** Windows 11 systems must use a BitLocker PIN with a minimum length of six digits for pre-boot authentication.  
- **Finding:** `MinimumPIN` value was not present under the FVE registry path, leaving PIN length unconstrained (below the required 6-digit minimum).  
- **Action Taken:** Created `MinimumPIN` (REG\_DWORD) under `HKLM\SOFTWARE\Policies\Microsoft\FVE`, set to `6`.  
- **Status:** **Remediated.** Registry verification confirms `MinimumPIN = 0x00000006 (6)`.

### Control 4 — Application Allowlisting (AppLocker)

- **STIG ID:** WN11-00-000035 | **Group ID:** V-253262 | **Severity:** CAT II  
- **Rule Title:** The operating system must employ a deny-all, permit-by-exception policy to allow the execution of authorized software programs.  
- **Finding:** `Get-AppLockerPolicy -Effective -XML` run from an elevated PowerShell session returned an empty policy (`<AppLockerPolicy Version="1" />`), confirming no AppLocker rules are in effect — the system defaults to allow-all execution.  
- **Action Taken:** **None.** AppLocker enforcement (deny-by-default rule enforcement mode) is a feature gated to Windows 11 Enterprise and Education editions. The assessed system runs Windows 11 **Pro**, which does not expose the AppLocker enforcement UI/policy engine required to satisfy this control.  
- **Status:** **Open Finding — Not Remediated (OS edition limitation).** This is a genuine platform constraint, not an oversight, and is the kind of gap auditors are expected to document rather than paper over. Compensating controls to consider: Windows Defender Application Control (WDAC), which is available on Pro, or an edition upgrade to Enterprise if AppLocker specifically is required by policy.

### Control 5 — Alternate Operating System Restriction

- **STIG ID:** WN11-00-000055 | **Severity:** CAT II  
- **Rule Title:** Alternate operating systems must not be permitted to boot with the standard Windows 11 installation.  
- **Finding:** None. Verified via Settings → System → About → Advanced system settings → Startup and Recovery: the boot menu lists only "Windows 11" as the default operating system.  
- **Action Taken:** None required.  
- **Status:** **Not a Finding.**

### Control 6 — Account Lockout Threshold

- **STIG ID:** WN11-00-000036 | **Severity:** CAT II  
- **Rule Title:** Account lockout threshold must be configured to meet the maximum allowed invalid logon attempts before lockout.  
- **Finding:** Local Security Policy → Account Policies → Account Lockout Policy showed "Account lockout threshold" set to **10 invalid logon attempts**, exceeding the STIG-required maximum.  
- **Action Taken:** Reconfigured via Local Security Policy to **3 invalid logon attempts**.  
- **Status:** **Remediated.** Verified in Local Security Policy console post-change.

### Control 7 — Anonymous SAM Enumeration Restriction

- **STIG ID:** WN11-SO-000020 | **Severity:** CAT II  
- **Rule Title:** Anonymous enumeration of SAM accounts must not be allowed (RestrictAnonymousSAM).  
- **Finding:** None. Registry verification under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa` confirmed `restrictanonymoussam` was already set to `1`.  
- **Action Taken:** None required.  
- **Status:** **Not a Finding.**

### Control 8 — Built-in Administrator Account Name

- **STIG ID:** WN11-00-000060 | **Severity:** CAT II  
- **Rule Title:** The built-in administrator account must be renamed.  
- **Finding:** Computer Management → Local Users and Groups → Users showed the built-in administrator account retaining its default name, "Administrator" — a known target for credential-stuffing and brute-force attacks.  
- **Action Taken:** Renamed to `LocalAdmin` via Computer Management.  
- **Status:** **Remediated.** Verified in Computer Management user list; account description ("Built-in account for administering...") confirms it is the same underlying built-in SID under its new name.

### Control 9 — Audit Logon Events

- **STIG ID:** WN11-AU-000500 | **Severity:** CAT II  
- **Rule Title:** The system must be configured to audit Logon/Logoff → Logon events for both success and failure.  
- **Finding:** Local Security Policy → Advanced Audit Policy Configuration → System Audit Policies → Logon/Logoff → Audit Logon was set to **Not Configured**.  
- **Action Taken:** Set "Audit Logon" to **Success and Failure** via Advanced Audit Policy Configuration.  
- **Status:** **Remediated.** Verified in the Advanced Audit Policy console.

### Control 10 — Built-in Guest Account Name

- **STIG ID:** WN11-00-000085 | **Severity:** CAT II  
- **Rule Title:** The built-in guest account must be renamed.  
- **Finding:** The built-in guest account retained its default name, "Guest," in Computer Management → Local Users and Groups. (Note: the account was already disabled, which satisfies a separate, related control, but the naming requirement is independent.)  
- **Action Taken:** Renamed to `LocalGuest` via Computer Management.  
- **Status:** **Remediated.** Verified in Computer Management user list; account description ("Built-in account for guest access...") confirms it is the same built-in account under its new name.

---

## 4\. Compliance Summary Table

| \# | STIG ID | Severity | Rule Title | Baseline Status | Action Taken | Final Status |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| 1 | WN11-00-000030 | CAT I | Full disk encryption via BitLocker | Non-compliant (BitLocker off) | None | Not a Finding *(see 2.1 caveat)* |
| 2 | WN11-00-000031 | CAT I | BitLocker PIN for pre-boot authentication | Finding | Set `UseAdvancedStartup`, `UseTPMPIN`, `UseTPMKeyPIN` \= 1 | Remediated |
| 3 | WN11-00-000032 | CAT II | Minimum 6-digit BitLocker PIN | Finding | Set `MinimumPIN` \= 6 | Remediated |
| 4 | WN11-00-000035 | CAT II | Deny-all, permit-by-exception (AppLocker) | Finding | None — requires Enterprise/Education edition | Open (edition limitation) |
| 5 | WN11-00-000055 | CAT II | Alternate OS boot restriction | Compliant | None required | Not a Finding |
| 6 | WN11-00-000036 | CAT II | Account lockout threshold ≤ policy max | Finding (10 attempts) | Reconfigured to 3 attempts | Remediated |
| 7 | WN11-SO-000020 | CAT II | RestrictAnonymousSAM | Compliant | None required | Not a Finding |
| 8 | WN11-00-000060 | CAT II | Rename built-in Administrator account | Finding | Renamed to `LocalAdmin` | Remediated |
| 9 | WN11-AU-000500 | CAT II | Audit Logon success/failure | Finding | Set to Success and Failure | Remediated |
| 10 | WN11-00-000085 | CAT II | Rename built-in Guest account | Finding | Renamed to `LocalGuest` | Remediated |

**Summary:** 10 controls audited · 3 compliant at baseline · 7 findings identified · 6 remediated · 1 open (platform-limited) · 1 baseline determination flagged for reviewer follow-up.

---

## 5\. Residual Risk and Recommendations

**WN11-00-000035 (AppLocker, CAT II — Open):** The system cannot enforce a deny-all, permit-by-exception execution policy on Windows 11 Pro. Recommended paths, in order of preference: (1) upgrade the system to Windows 11 Enterprise or Education if AppLocker specifically is mandated; (2) implement Windows Defender Application Control (WDAC), which is available on Pro and can achieve a comparable deny-by-default posture; (3) if neither is feasible, document this as a formally accepted risk with compensating controls (e.g., restricted local admin rights, endpoint detection and response tooling) and revisit at the next accreditation cycle.

**WN11-00-000030 (BitLocker full-disk encryption, CAT I — Determination flagged):** As noted in Section 2.1, recording this as Not a Finding does not match the STIG's stated NA criteria for a persistent VM. Recommend either enabling BitLocker on the C: drive (low cost given TPM/PIN infrastructure is already configured per Controls 2–3) or reclassifying this as an open finding with an explicit risk acceptance memo if encryption is genuinely out of scope for this lab environment.

**General:** This assessment covered 10 of 262 published rules in the V2R7 benchmark. A full SCAP-based scan (e.g., via the DISA-provided SCAP Compliance Checker or STIG Viewer's checklist import) is recommended before this system is treated as STIG-compliant in any formal sense.

---

## 6\. Conclusion

Six of seven identified findings were remediated and verified during this assessment, moving the audited control set from 30% to 90% compliance. The one unresolved finding (AppLocker) is a documented, edition-driven platform constraint rather than a remediation failure, and is the type of real-world limitation that should be recorded rather than worked around. One baseline "Not a Finding" determination (BitLocker full-disk encryption) is flagged for reviewer attention, as it does not cleanly satisfy the STIG's own applicability language and should be resolved before this report is used to support an accreditation or ATO decision.

---

*Evidence: Before/after screenshots for each control (STIG Viewer rule text, registry state, Local Security Policy, Advanced Audit Policy, Computer Management, PowerShell output, and BitLocker Control Panel) were captured during the assessment and are maintained as supporting artifacts to this report.*  
