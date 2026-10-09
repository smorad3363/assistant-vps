# Port Manager V1 (original) — installation alias

**This directory does not contain a second implementation of V1.** The original
installer and payload remain untouched under `portmanager-dashboard/`.

Original, permanent V1 install URL:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
```

New alias URL (also runs the same original installer from master):

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-v1/install.sh | sudo bash
```

Both result in the existing `portmanager` command and use the same V1
configuration, data, cron and traffic-control rules. The alias fetches the
**original** installer at runtime and preserves its exit code. It does not
install V2.

WARNING: the original V1 installer includes potentially disruptive
`tc` operations. Evaluate on a VM, especially if V2 is already installed.
Do not treat an alias as a security update to the original application.
