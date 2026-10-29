# M6 MUI interaction qualification

Status: PASS on 2026-10-29. This record applies M6-A1 through M6-A4 in
docs/plans/ami-rust-0.1.md to the repository revision containing this file.
GitHub issue #12 owns the execution state. This is not a release qualification
or publication.

## Pinned inputs

| Input | Exact identity |
| --- | --- |
| M5 dependency | Accepted commit 614908ca22ba0787e7cb3d6e9da2cba507a49979 |
| ABI1 source | AROS-NX commit e0d5e367d15cc7da4ebac8f9db17868756c79569 |
| ABI11 source | Deadwood AROS commit fbc242c1046cffb5e5827a4626ee62bdd45664e9 (ABIv11_2026.09) |
| ABI1 boot image | SHA-256 9c89b54802ea51c0cd9d07f48d2e069c2644a21ee59e87a0b09ba3837b1247b1 |
| ABI11 boot image | SHA-256 2228f09c73f8c7650372543e9a97f93020a1fab7ebbf4865b194c5aa9cc8ccd7 |
| ABI1 target | targets/x86_64-unknown-aros-abi1.json, SHA-256 0e9cde740c93949d4cab27690cb9d93dc9fb89dc96388ff5be0eb7296ba38807 |
| ABI11 target | targets/x86_64-unknown-aros-abi11.json, SHA-256 5616c1e062232b43154237fe40826795cc48e148f903f0a1a8087d224d8a49c9 |
| Rust and Cargo | Unchanged accepted M5 inputs recorded in docs/m5-qualification.md |
| QEMU | 11.1.3, binary SHA-256 0dba441e49c3cda068f3b33916ad9d2146d173d9bb65a6a62ce2e61d3211baaf |
| Firmware | bios-256k.bin SHA-256 ae6f6aa973aaccc143f57aa960fb035fd9de4daee4ad0cd713322f8c259e7650; vgabios-stdvga.bin SHA-256 e8fc9e55790dbe3cb31f019a3deb57206ba6c54f5e581adb2ab2677a9d391472 |

QEMU 11.1.3 is the authoritative emulator pin from M6 onward. Historical M1
through M5 records remain bound to QEMU 11.1.2. The AROS source revisions,
boot images, machine type, CPU model and firmware bytes did not change. The
AROS-NX checkout retained only its pre-existing untracked build directory; the
ABI11 checkout remained clean. Neither AROS-NX nor aros-tools was modified.

The native SDK objects changed only where M6 required the signal-mask wait and
canonical BOOPSI method adapters. The adapters use the AROS `OCLASS` and
`CALLHOOKPKT` definitions instead of reconstructing the call in Rust.

| Object set | SHA-256 |
| --- | --- |
| ABI1 startup.o | 0ca30233bb169b694f552929627962f8be7935f0674565e6ed1114a86d00d99b |
| ABI1 entry.o | a2b6b80ccad4a3c459bb95f33904d90b0f9f99a94b61f6600667194b007eb7b2 |
| ABI1 sdk.o | 49defa2833262a510a6d15ee6660ffecb4e6f7f6feea1590aa8321cb0957f0fa |
| ABI1 layout.o | de661b23f7725307138a6c4358af8f90c1c9a1b6aa097ac193a5afcf93af874c |
| ABI11 sdk.o | 5b420762bfe070043af9c9fd7044cb0b87665d5507a27fba9c1be60544f397d2 |
| ABI11 layout.o | 137c6a384f591c82c7040032c0d2d969387643b08bd0e2b30c701add77a02b65 |
| ABI11 eh-frame-start.o | 92357dddfb6c5d7d793599b6f5c2e10609dde6f5d70010ae9066fc15054cefea |

## Implemented boundary

Typed notifications bind a generated readable source attribute to a checked
trigger and one of three safe actions: an Application return ID, a typed
no-notify attribute write, or a scope-retained Hook. Hook handles borrow their
owning scope. Their erased state remains retained until native objects have been
disposed, rejects reentrant mutable entry, and cannot be used after the scope
in safe Rust. The application-wide nonreturning panic handler prevents unwind
across the native hook or custom-class ABI.

`Application::run` uses `MUIM_Application_NewInput`, handles return IDs and
waits on the returned signal mask through the task-affine `aros::Context`.
Requesters accept only non-format strings; `%` conversions remain outside the
safe boundary. Generated menu objects continue to use the ownership ledger.

The regular custom-class workflow registers one scope-owned class, allocates
fallible per-instance Rust data during `OM_NEW`, releases it during
`OM_DISPOSE`, dispatches only declared argument-free methods, rejects
reentrant mutable dispatch, and forwards every other message unchanged to the
native superclass. Arbitrary foreign custom message layouts remain raw.

## Verification

The following focused checks passed:

- cargo check -p aros-mui --all-targets --locked --offline;
- cargo test -p aros-mui --locked --offline;
- cargo clippy -p aros-mui --all-targets --no-deps --locked --offline -- -D warnings;
- RUSTDOCFLAGS="-D warnings" cargo doc -p aros-mui --no-deps --locked --offline;
- release builds of the M6 interaction application for ABI1 and ABI11;
- cold execution of the exact ABI1 and ABI11 candidates under the pinned QEMU
  profile.

Both boots used pc-i440fx-11.1, qemu64-v1, single-threaded TCG, one vCPU,
512 MiB RAM, the pinned BIOS and VGA ROM, no network, and a read-only IDE CD at
index 2. The shell fixture used a 128 KiB stack. A successful process exit
requires all tracked allocation, backing-charge, file, library, port, signal
and message counters to be zero after object-scope and library cleanup.

| Target | Application SHA-256 | Qualification ISO SHA-256 | Durable observation | Result |
| --- | --- | --- | --- | --- |
| x86_64-unknown-aros-abi1 | 809bbea2496485e6c2c2b45349a86a9f49b58c60c039bb0cb2e3105e285131f7 | d981ef90144d0489c7520674def22f564cc4a79637d2ce7f42be1319d6a228a4 | serial log SHA-256 537b21807795091639e93ff95e6592a4e153a9fb24ffccabc1199e901b46dcc4; screenshot SHA-256 91d62a9a500ebf5ccbe28db2d04c3f583c796469e7ab4013abf542dd0929e108 | PASS, return code 0 |
| x86_64-unknown-aros-abi11 | ea13728111fcd85d53e8e446f883b392d77d3a2fd14964be854641690f9840b2 | 99c332be5a358799122c87d3e624d2d6e9576a721d28514a01c8b3f289d3dda4 | screenshot SHA-256 0332fb343a00f3ab112646316928db55464a784dde930c616d63e65ff4ab023f | PASS, return code 0 |

The ABI1 serial record contains custom dispatch, retained callback, event loop,
interaction, cleanup and final pass markers. Both guest consoles report
`ami-rust M6 process returned 0`.

## Acceptance mapping

- M6-A1: PASS. Typed notifications and the safe Application event loop execute
  successfully on ABI1 and ABI11.
- M6-A2: PASS. Hook state is scope-retained, non-reentrant and inaccessible
  after scope expiration in safe Rust; panic uses the existing nonreturning
  application boundary.
- M6-A3: PASS. Safe requesters, generated menu ownership and the regular
  custom-class workflow are present; unproven foreign message layouts remain
  explicitly raw.
- M6-A4: PASS. The reference application executes notification delivery, one
  retained callback with value 42, the quit return-ID event loop and one custom
  class on both pinned ABIs, followed by complete tracked-resource cleanup.
