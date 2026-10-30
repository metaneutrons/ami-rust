# ami-rust-qualification

Native qualification fixture for the retained host harness. Its
argument-selected modes exercise ABI callbacks, allocation, files, libraries,
ports and messages, diagnostics, fault injection and cleanup. It uses ordinary
Cargo with the pinned `aros-native-build` helper and the
`x86_64-unknown-aros-abi1` target
libraries. The test build enables the native `bind.o` hooks; one passing mode is
not an overall qualification claim.
