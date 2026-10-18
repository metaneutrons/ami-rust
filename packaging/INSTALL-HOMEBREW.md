# Homebrew installation — macOS 26 Apple Silicon

These are the delivery commands for SDK 0.1.0, packaging revision 1.
Channel availability is recorded separately in the distribution status.

```sh
brew install metaneutrons/tap/ami-rust
brew test metaneutrons/tap/ami-rust
ami-rust verify-package
```

Then follow the [explicit user preparation and first build](README.md).
Homebrew owns the launcher and read-only package inputs. Preparation retains a
private interpreter and SDK snapshot for locked projects, so `brew uninstall
ami-rust` and later Python cleanup preserve their retained launcher.
