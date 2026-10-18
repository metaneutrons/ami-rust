# APT installation — Ubuntu 24.04 amd64

These are the delivery commands for SDK 0.1.0, Debian packaging revision 1.
Channel availability is recorded separately in the distribution status.
Run them on Ubuntu 24.04 x86-64. The archive's pinned primary fingerprint is
`1B7B79417383648BBFBE282E01AB8296EF0FCD76`; its signing subkey is
`A0C21782FC507CCBD666F3ED242072FEC8BE54A4`.

```sh
KEY=$(mktemp)
curl --fail --silent --show-error https://deb.metaneutrons.cc/metaneutrons-archive-keyring.pgp --output "$KEY"
printf 'e663577e0e5769a6b1a83f1cd44751dfc60bd0820ae0724df5cb6a60fb3a2b74  %s\n' "$KEY" | sha256sum --check --status
sudo install -m 0644 "$KEY" /usr/share/keyrings/metaneutrons-archive-keyring.pgp
rm -f "$KEY"
printf '%s\n' 'Types: deb' 'URIs: https://deb.metaneutrons.cc' 'Suites: rolling' 'Components: main' 'Architectures: amd64' 'Signed-By: /usr/share/keyrings/metaneutrons-archive-keyring.pgp' | sudo tee /etc/apt/sources.list.d/metaneutrons.sources >/dev/null
sudo apt-get update
sudo apt-get install --yes ami-rust=0.1.0-1
ami-rust verify-package
```

Then follow the [explicit user preparation and first build](README.md).
No compiler build or prerequisite download runs as root during installation.
The trust-anchor checksum deliberately fails on an unreviewed key rotation.
Removing the package with `sudo apt-get remove ami-rust` keeps prepared user
states and projects. Their retained launcher continues to build locked projects.
