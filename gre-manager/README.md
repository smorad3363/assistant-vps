# GRE Manager 1.0

A compact Persian web panel for GRE and direct TCP/UDP port forwarding.
All create, edit, delete, pause, test, speed-limit, statistics, backup/restore and
update actions live in three pages: **GRE**, **IPTables**, and **Settings**.
The Bash installer has no interactive management menu.

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre.sh | sudo bash
```

Run on the Iran server. The installer prints the HTTPS URL (default port 8787)
and first-install login credentials. Add the foreign server under Settings for
automatic GRE setup over SSH; direct forwarding does not require outside SSH.
SSH and panel ports are protected. Existing pair profiles and saved MTU values
are adopted without deleting live GRE interfaces. Updates retain configuration
and telemetry.

See [PANEL.md](PANEL.md) for requirements, SSH/TLS setup, automatic MTU behavior,
speed-limit semantics, telemetry, safe migration, backups, recovery and tests.

The old original installation URL is also retained:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-manager/install.sh | sudo bash
```

