# SCAP Compliance Checker results

Unmodified reports from a SCAP Compliance Checker (SCC) scan of the assessment VM. The scan ran after the manual remediation documented in the main [README](../README.md).

| | |
| :-- | :-- |
| Tool | SCAP Compliance Checker 5.14.1 |
| Target | `DESKTOP-CRJIC3S`, Windows 11 Pro 22H2, VirtualBox |
| Scan time | 2026-07-02 15:35 (from the report filenames) |
| Content | Microsoft Windows 11 STIG SCAP Benchmark, NIWC Enhanced with Manual Questions, benchmark version 002.008, 262 rules, digital signature valid |
| Profile | `MAC-1_Classified` |
| Score | 33.33% (provisional; 10 manual questions unanswered) |

| Result | Count |
| :-- | --: |
| Pass | 79 |
| Fail | 158 |
| Not Applicable | 15 |
| Not Checked | 10 |
| Error | 0 |
| **Total** | **262** |

## Files

- `...All-Settings...html`: every rule with its check, expected value, and result.
- `...Non-Compliance...html`: failed rules only.

Open either file in a browser. GitHub shows them as source, so download them or use a raw-HTML viewer.

## How to read these results

- **Assessed-control results.** The 10 assessed controls are cross-referenced in the main README's results table. In this scan:
  - Every remediated control passes.
  - BitLocker full-disk encryption (WN11-00-000030) fails.
  - Application allowlisting (WN11-00-000035) is a manual rule and was not checked.
- **No baseline.** No pre-remediation scan was run, so the reports can't show how much the score improved.
- **Profile choice.** `MAC-1_Classified` was used on an unclassified lab system. A different profile may change rule applicability.
