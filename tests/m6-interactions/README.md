# Native reference application

This private application is the maintained native reference application. It
exercises DOS file I/O, owned-handle and MUI-scope cleanup on deliberate error
returns, typed notifications, one scope-retained callback, the safe Application
event loop, a menu hierarchy, and the regular custom-class lifecycle through
`aros-mui`.

The application contains no raw MUI call, tag list, native pointer, or unsafe
block. M6 results remain recorded in `docs/m6-qualification.md`; final M7
results belong to the exact release-candidate qualification record.
