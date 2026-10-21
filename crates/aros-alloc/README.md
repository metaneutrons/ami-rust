# aros-alloc

An explicit `no_std` global allocator backed by the native Exec allocation bridge. Applications opt in by enabling `aros-runtime/alloc` and installing the runtime entry allocator. The retained contract is limited to the single application task described by the SDK.
