# GRE Manager 2.1

A Persian web panel for managing tunnel groups and direct TCP/UDP forwarding
across Linux servers. It includes weighted routing, failover, path tests,
per-host SSH protection and recovery after reboot.
Each tunnel method has its own page for setup and existing routes. Use Groups to share an entry point across multiple destinations.

```bash
curl -fsSLo gre-install.sh https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre.sh && sudo bash gre-install.sh
```

Run on a Linux server with systemd and apt or dnf. The installer prints the HTTPS URL (default port 8787)
and random first-install login credentials. Public IPv4 installations request a
trusted IP certificate with automatic renewal. Add the foreign server under Settings for
automatic GRE setup over SSH; direct forwarding does not require outside SSH.
The worker discovers SSH ports on each managed server. Existing pair profiles and saved MTU values
are adopted without deleting live GRE interfaces. Updates retain configuration
and telemetry.

See [PANEL.md](PANEL.md) for requirements, SSH/TLS setup, automatic MTU behavior,
speed-limit semantics, telemetry, safe migration, backups, recovery and tests.

The old original installation URL is also retained:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-manager/install.sh | sudo bash
```

## Idle TCP state on a GRE ingress

Run `sudo bash gre-manager/ingress-conntrack.sh` from a repository checkout on
an ingress host that accumulates idle TCP NAT entries. It applies a two-hour
idle TCP conntrack timeout, preserves a stricter live timeout, and arranges for
the kernel module to load before the boot-time sysctl service. Existing entries
age out on their current timers or pick up the setting when traffic resumes.
The provider manages its upstream connection tracking separately.

