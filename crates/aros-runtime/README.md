# aros-runtime

The `no_std` application frame for the selected native x86-64 AROS ABI-v1 bridge. It exposes the borrowed task context, application status, argument access, diagnostics, and entry macro. The optional `alloc` feature exposes the Exec-backed allocator; the default feature set is empty.
