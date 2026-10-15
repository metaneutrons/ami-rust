# Contributing

Changes should preserve the documented target and safety boundaries. Please
include a concise explanation of the affected crate, native interface, or
installer behavior and identify any change to generated or measured bytes.

The public CI check runs only the black-box installer fixture suite:

    python3 -I -B release/test_install.py

Those tests create disposable local signing keys and small synthetic archives.
They do not test the actual publisher, protected build provenance, R1
qualification, cross-host reproducibility, or AROS execution. Do not describe
them as evidence for those properties.

Do not commit credentials, private signing keys, local machine paths, generated
SDK archives, or qualification evidence. Include license and provenance details
for any new third-party source or binary. The repository does not accept binary
SDK release assets through pull requests.
