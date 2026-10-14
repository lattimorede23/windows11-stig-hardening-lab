# Evidence index

All screenshots are original, unedited captures from the assessment VM (`DESKTOP-CRJIC3S`). Filenames are kept as originally uploaded, so several carry an incorrect STIG ID. The **Correct rule** column gives the rule each file actually supports, taken from the SCAP benchmark content.

| File | Captured | Shows | Correct rule |
| :-- | :-- | :-- | :-- |
| [`system_info.png`](system_info.png) | 26 Jun 2026, 2:20 PM | Settings > About: VirtualBox VM, Windows 11 Pro 22H2, build 22621.1848, installed 6/26/2026 | System identification |
| [`WN11-00-000030_BitLocker_off.png`](WN11-00-000030_BitLocker_off.png) | 26 Jun 2026, 2:23 PM | BitLocker Drive Encryption control panel: C: BitLocker off | WN11-00-000030 (V-253259), open finding |
| [`WN11-00-000031_registry_before.png`](WN11-00-000031_registry_before.png) | 26 Jun 2026, 2:15 PM | `HKLM\SOFTWARE\Policies\Microsoft\FVE` with `UseAdvancedStartup`, `UseTPMPIN`, `UseTPMKeyPIN` = 1 and no `MinimumPIN` | **After** state for WN11-00-000031; **before** state for WN11-00-000032. Despite the filename, this is not a baseline capture of 000031. |
| [`WN11-00-000031_registry_remediated.png`](WN11-00-000031_registry_remediated.png) | 26 Jun 2026, 2:28 PM | Same key with all four values, including `MinimumPIN` = 6 | WN11-00-000031 and WN11-00-000032, after |
| [`WN11-00-000035_AppLocker_empty.png`](WN11-00-000035_AppLocker_empty.png) | 26 Jun 2026, 2:31 PM | `Get-AppLockerPolicy -Effective -XML` returns an empty policy | WN11-00-000035 (V-253262), open finding |
| [`WN11-00-000055_startup_recovery.png`](WN11-00-000055_startup_recovery.png) | 1 Jul 2026, 12:10 PM | Startup and Recovery: only "Windows 11" listed | WN11-00-000055 (V-253266) |
| [`WN11-00-000036_lockout_before.png`](WN11-00-000036_lockout_before.png) | 1 Jul 2026, 12:13 PM | Account lockout threshold: 10 invalid logon attempts | **WN11-AC-000010** (V-253298), before |
| [`WN11-00-000036_lockout_after.png`](WN11-00-000036_lockout_after.png) | 1 Jul 2026, 12:14 PM | Account lockout threshold: 3. Lockout duration and reset counter remain at 10 minutes (see WN11-AC-000005/000015 in the SCAP results) | **WN11-AC-000010** (V-253298), after |
| [`WN11-SO-000020_RestrictAnonymousSAM.png`](WN11-SO-000020_RestrictAnonymousSAM.png) | 1 Jul 2026, 1:20 PM | `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`: two truncated `restrictanonymo...` values (0, then 1). In alphabetical order these are `RestrictAnonymous` and `RestrictAnonymousSAM`. | **WN11-SO-000145** (V-253453). SCAP confirms Pass. |
| [`WN11-00-000060_admin_before.png`](WN11-00-000060_admin_before.png) | 1 Jul 2026, 1:21 PM | Local users: `Administrator` and `Guest` still have their default names | **WN11-SO-000020** (V-253435) and **WN11-SO-000025** (V-253436), before |
| [`WN11-00-000060_admin_after.png`](WN11-00-000060_admin_after.png) | 1 Jul 2026, 1:23 PM | Built-in administrator renamed to `LocalAdmin` | **WN11-SO-000020** (V-253435), after |
| [`WN11-00-000065_guest_disabled.png`](WN11-00-000065_guest_disabled.png) | 1 Jul 2026, 1:24 PM | Guest Properties: "Account is disabled" checked | **WN11-SO-000010** (V-253433). Supporting evidence only; outside the 10-control scope. |
| [`WN11-AU-000500_audit_logon_after.png`](WN11-AU-000500_audit_logon_after.png) | 1 Jul 2026, 1:27 PM | Advanced Audit Policy > Logon/Logoff > Audit Logon: Success and Failure | **WN11-AU-000070** (V-253316) and **WN11-AU-000075** (V-253317), after. No before capture exists. |
| [`WN11-00-000085_guest_renamed.png`](WN11-00-000085_guest_renamed.png) | 1 Jul 2026, 1:44 PM | Built-in guest renamed to `LocalGuest` | **WN11-SO-000025** (V-253436), after |

Capture times are read from the Windows taskbar clock visible in each screenshot.

## Gaps in the evidence

- **WN11-00-000031:** no capture of the original, unconfigured state.
- **Audit Logon:** no before capture.
- **TPM status:** no capture (for example, `Get-Tpm` or `tpm.msc` output). Without it, the evidence cannot show whether BitLocker could have been enabled on this VM.
