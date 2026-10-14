# Windows 11 DISA STIG Assessment and Hardening Lab

A hands-on DISA STIG assessment of a Windows 11 Pro virtual machine: 10 controls audited manually and remediated with native Windows tools, then validated with a full SCAP Compliance Checker (SCC) scan of the 262-rule benchmark.

**Report revision 1.1 (2026-10-14).** This revision corrects STIG rule IDs and two control determinations found in an evidence review of the original July 2026 report. The original report is preserved unchanged in [`docs/original-report-v1.0.md`](docs/original-report-v1.0.md), and every correction is listed under [Revision history](#revision-history).

---

## At a glance

| | |
| :-- | :-- |
| System | `DESKTOP-CRJIC3S`, Oracle VirtualBox VM, standalone (not domain-joined) |
| Operating system | Windows 11 Pro 22H2, build 22621.1848 ([`system_info.png`](evidence/system_info.png)) |
| Manual assessment | 10 controls from the DISA Microsoft Windows 11 STIG V2R7 (benchmark date 01 Apr 2026), rule text pulled from STIG Viewer 3.7 |
| Automated validation | SCAP Compliance Checker 5.14.1, Windows 11 STIG SCAP benchmark version 002.008 (262 rules), run 2026-07-02 after remediation |
| Assessment window | 26 Jun 2026 to 02 Jul 2026 (evidence and scan timestamps) |
| Tools | STIG Viewer 3.7, SCC 5.14.1, Local Security Policy, Local Group Policy Editor, Registry Editor, Computer Management, PowerShell |
| Frameworks | DISA STIG, NIST SP 800-53 Rev 5 (via CCI mappings in the STIG content) |

---

## Results for the 10 assessed controls

Of the 10 controls, 2 were compliant at baseline and 8 were findings. Six findings were remediated and verified. Two remain open: BitLocker full-disk encryption (CAT I) and application allowlisting (CAT II).

**Baseline: 2 of 10 compliant (20%). After remediation: 8 of 10 compliant (80%).**

The SCAP scan on 2 July independently confirms every remediated control and both baseline-compliant controls.

| # | Control | STIG ID | Vuln ID | CAT | Baseline | Action taken | Final status | SCAP result (2 Jul) |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| 1 | BitLocker full-disk encryption | WN11-00-000030 | V-253259 | I | Finding (BitLocker off) | None | **Open** | Fail |
| 2 | BitLocker pre-boot PIN | WN11-00-000031 | V-253260 | I | Finding | Set `UseAdvancedStartup`, `UseTPMPIN`, `UseTPMKeyPIN` = 1 | Remediated | Pass |
| 3 | BitLocker minimum PIN length (6) | WN11-00-000032 | V-253261 | II | Finding | Set `MinimumPIN` = 6 | Remediated | Pass |
| 4 | Application allowlisting | WN11-00-000035 | V-253262 | II | Finding (no policy) | None | **Open** | Not Checked (manual rule) |
| 5 | No alternate operating systems | WN11-00-000055 | V-253266 | II | Compliant | None needed | Not a Finding | Pass |
| 6 | Account lockout threshold (3 or less, not 0) | WN11-AC-000010 | V-253298 | II | Finding (10 attempts) | Set to 3 attempts | Remediated | Pass |
| 7 | No anonymous SAM enumeration | WN11-SO-000145 | V-253453 | I | Compliant | None needed | Not a Finding | Pass |
| 8 | Rename built-in Administrator | WN11-SO-000020 | V-253435 | II | Finding | Renamed to `LocalAdmin` | Remediated | Pass |
| 9 | Audit Logon failures and successes | WN11-AU-000070, WN11-AU-000075 | V-253316, V-253317 | II | Finding (Not Configured) | Set Audit Logon to Success and Failure | Remediated | Pass, Pass |
| 10 | Rename built-in Guest | WN11-SO-000025 | V-253436 | II | Finding | Renamed to `LocalGuest` | Remediated | Pass |

Control 9 is one setting (Advanced Audit Policy, Logon/Logoff > Audit Logon) that satisfies two STIG rules, so it is counted as one control.

Controls 2 and 3 set the BitLocker policy values the STIG checks for, and SCAP passes them. Those values only take effect once BitLocker is turned on, so while control 1 is open they are configured but not in force.

---

## Full-benchmark SCAP scan

After the manual work, the full benchmark was scanned with SCC 5.14.1 on 2 July 2026. The reports are in [`scap-results/`](scap-results/) and summarized in [`scap-results/README.md`](scap-results/README.md).

| Severity | Pass | Fail | Not Applicable | Not Checked |
| :-- | --: | --: | --: | --: |
| CAT I | 13 | 12 | 0 | 2 |
| CAT II | 62 | 136 | 14 | 6 |
| CAT III | 4 | 10 | 1 | 2 |
| **Total (262 rules)** | **79** | **158** | **15** | **10** |

**SCC score: 33.33%** (79 passed of 237 scored). SCC marks the score as provisional because 10 manual questions were left unanswered.

This number and the 80% above measure different things. The 80% covers only the 10 controls selected for this assessment. The 33.33% covers the entire benchmark, and most of those rules were outside this assessment's scope.

Limitations of the scan:

- No scan was run before remediation, so there is no full-benchmark baseline and no before/after delta.
- The scan used the `MAC-1_Classified` profile. An unclassified lab system would normally use a different profile, which can change the applicability of some rules.
- The SCAP benchmark (version 002.008) is a different release from the V2R7 manual STIG used for the 10-control review. The STIG IDs, Vuln IDs, and severities in this report are taken from the SCAP content.

Related rules outside the 10-control scope also failed. For example, [`WN11-00-000036_lockout_after.png`](evidence/WN11-00-000036_lockout_after.png) shows a 10-minute lockout duration and reset counter. SCAP fails both: WN11-AC-000005 requires 15 minutes or more, and WN11-AC-000015 requires 15 minutes.

---

## Control details

### 1. BitLocker full-disk encryption (WN11-00-000030, CAT I): Open

The [BitLocker control panel](evidence/WN11-00-000030_BitLocker_off.png) shows the C: drive with BitLocker off, and SCAP reports this rule as Fail. The STIG allows N/A only for VDI instances deleted or refreshed at logoff, and for AVD with no data at rest. A persistent VirtualBox VM matches neither, so this is an **open CAT I finding**.

This was not remediated during the assessment. Whether the VM has a virtual TPM was not recorded, so the evidence cannot show whether BitLocker could have been enabled with TPM-based protectors. For a non-production lab VM holding no sensitive data, a reasonable disposition is formal risk acceptance with that rationale. In a production system, the remediation is to enable BitLocker on all fixed drives.

### 2–3. BitLocker pre-boot PIN and PIN length (WN11-00-000031/032): Remediated

The three PIN values and `MinimumPIN` = 6 were created under `HKLM\SOFTWARE\Policies\Microsoft\FVE`. The evidence and its timing:

| Time | Screenshot | What it shows |
| :-- | :-- | :-- |
| 26 Jun, 2:15 PM | [`WN11-00-000031_registry_before.png`](evidence/WN11-00-000031_registry_before.png) | The three PIN values already set to 1, and `MinimumPIN` not yet present |
| 26 Jun, 2:28 PM | [`WN11-00-000031_registry_remediated.png`](evidence/WN11-00-000031_registry_remediated.png) | All four values present |

The 2:15 PM screenshot is therefore the after state for control 2 and the before state for control 3. No screenshot of control 2's original, unconfigured state exists. SCAP confirms both controls pass.

### 4. Application allowlisting (WN11-00-000035, CAT II): Open

`Get-AppLockerPolicy -Effective -XML` returned an empty policy ([screenshot](evidence/WN11-00-000035_AppLocker_empty.png)), so no allowlisting was in effect. That is correctly a finding.

**Correction:** the original report said this could not be fixed on Windows 11 Pro because AppLocker enforcement is limited to Enterprise and Education. The STIG check text does describe AppLocker as built into Enterprise. However, Microsoft removed AppLocker's edition checks in [KB5024351](https://support.microsoft.com/en-us/topic/kb5024351-removal-of-windows-edition-checks-for-applocker-e3a763c9-6a3e-4d9c-8623-0ffe69046470), starting with Windows 11 22H2 build 22621.608. This VM runs build 22621.1848, so it could have enforced AppLocker rules set through local policy.

The finding is open because it was not remediated within the assessment, not because of a platform limitation. Remediation options:

- Deploy AppLocker deny-by-default rules, including packaged-app rules, which the STIG requires.
- Deploy App Control for Business (WDAC), which the STIG accepts because it allows any allowlisting program.

### 5. Alternate operating systems (WN11-00-000055): Not a Finding

Startup and Recovery lists only Windows 11 ([screenshot](evidence/WN11-00-000055_startup_recovery.png)). SCAP: Pass.

### 6. Account lockout threshold (WN11-AC-000010): Remediated

The threshold was changed from 10 to 3 invalid attempts ([before](evidence/WN11-00-000036_lockout_before.png), [after](evidence/WN11-00-000036_lockout_after.png)). The STIG treats both more than 3 and exactly 0 (lockout disabled) as findings. SCAP: Pass.

### 7. Anonymous SAM enumeration (WN11-SO-000145, CAT I): Not a Finding

`HKLM\SYSTEM\CurrentControlSet\Control\Lsa` contains two values whose names are truncated in the [screenshot](evidence/WN11-SO-000020_RestrictAnonymousSAM.png). They are listed in alphabetical order, so the first (0) is `RestrictAnonymous` and the second (1) is `RestrictAnonymousSAM`. SCAP confirms Pass.

The original report rated this rule CAT II. The STIG content rates it CAT I.

### 8. Built-in Administrator renamed (WN11-SO-000020): Remediated

The account was renamed from `Administrator` to `LocalAdmin` ([before](evidence/WN11-00-000060_admin_before.png), [after](evidence/WN11-00-000060_admin_after.png)). The account description confirms this is the same built-in account. SCAP: Pass.

### 9. Audit Logon (WN11-AU-000070 and WN11-AU-000075): Remediated

Audit Logon was set to Success and Failure ([after](evidence/WN11-AU-000500_audit_logon_after.png)). No before screenshot was captured; the original report recorded the baseline as Not Configured. SCAP passes both rules.

### 10. Built-in Guest renamed (WN11-SO-000025): Remediated

The account was renamed from `Guest` to `LocalGuest` ([before, in the admin screenshot](evidence/WN11-00-000060_admin_before.png), [after](evidence/WN11-00-000085_guest_renamed.png)). The Guest account was already disabled ([screenshot](evidence/WN11-00-000065_guest_disabled.png)), which separately satisfies WN11-SO-000010; SCAP passes that rule as well.

---

## Evidence

All screenshots are original and unedited. Their filenames carry the STIG IDs used in the original report, several of which were wrong. [`evidence/README.md`](evidence/README.md) maps every file to its correct rule, capture time, and contents.

---

## Revision history

**v1.1 (2026-10-14).** Corrections from an evidence review against the SCAP content and screenshots. No new testing was performed and no evidence was changed.

1. **Corrected STIG IDs for 5 controls.** The original IDs were either nonexistent or belonged to unrelated rules in the SCAP content:

   | Control | Original ID | Corrected ID |
   | :-- | :-- | :-- |
   | Lockout threshold | WN11-00-000036 | WN11-AC-000010 |
   | Anonymous SAM | WN11-SO-000020 | WN11-SO-000145 |
   | Administrator rename | WN11-00-000060 | WN11-SO-000020 |
   | Audit Logon | WN11-AU-000500 | WN11-AU-000070 / 000075 |
   | Guest rename | WN11-00-000085 | WN11-SO-000025 |

   The guest-disabled screenshot is labeled WN11-00-000065; the correct ID is WN11-SO-000010.
2. **Corrected the severity of anonymous SAM enumeration** from CAT II to CAT I.
3. **Reclassified WN11-00-000030 (BitLocker) from Not a Finding to Open.** The original report had already flagged this determination as inconsistent with the STIG's N/A criteria.
4. **Corrected the WN11-00-000035 (AppLocker) rationale.** The original said the finding could not be fixed on Windows 11 Pro. Per KB5024351 it was remediable on this build, so it is now recorded as an open finding that was not remediated, rather than a platform limitation.
5. **Corrected the compliance figures**, from 30% baseline / 90% after remediation to 20% / 80%, as a result of items 3 and 4.
6. **Added the 2 July SCAP scan results**, which the v1.0 report predated, along with their limitations.
7. **Corrected the description of the control 2 "before" screenshot**, which actually shows the after state.
8. **Removed the claim that "TPM/PIN infrastructure is already configured."** The PIN policy values neither require nor demonstrate a TPM.

**v1.0 (2026-07-01).** Original report: [`docs/original-report-v1.0.md`](docs/original-report-v1.0.md).

---

## Related work

- [stig-powershell-remediation](https://github.com/lattimorede23/stig-powershell-remediation): PowerShell audit and remediation script for the same controls.
- [nist-rmf-authorization-package](https://github.com/lattimorede23/nist-rmf-authorization-package): RMF authorization artifacts for a fictional Windows 11 workstation.

**Author:** Derrick Lattimore Jr. · B.S. Information Security, Shawnee State University
