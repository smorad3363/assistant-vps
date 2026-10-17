# GRE Tunnel Manager

**Status: 0.1.0-dev — configuration-only preview, NOT production-ready.**

This project follows the attached GRE Tunnel Manager contract v1.0.0. It is intended for Ubuntu Server 22.04 / 24.04. Python 3 standard library is used for the runtime CLI. The frozen contract package is included in this source tree.

## Permanent install and update command

The **same command for initial installation and all future updates**:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-tun/install.sh | sudo bash
```

This URL is only usable after this complete `gre-tun/` source tree has been committed to the specified branch. Do not deploy by treating a GitHub path that has not yet been published as available.

For local source installation, after extracting the release on the target server:

```bash
sudo bash install.sh --local "$PWD"
```

Launch and inspect:

```bash
sudo gre-tun
gre-tun --version
gre-tun status --json
gre-tun config validate --file /etc/gre-tun/config.json
gre-tun test all
```

**Important:** The development release only saves tunnel and port *desired configurations*. It does NOT install live GRE interfaces, NAT, tc queues, or routes, and never reports a tunnel as connected. `gre-tun apply` refuses to activate non-empty configurations with `E_NOT_READY`. There is no functional live uninstall/rollback in this release. Do not use it to replace an existing tunnel manager.

## Safety / updates

- Installer downloads source to a staging directory, validates Python/JSON, protects preexisting nonowned application paths, and preserves `/etc/gre-tun` and `/var/lib/gre-tun` across updates.
- Every install/update uses the same URL and Git branch. The reference stays constant as new versions appear at that path.
- Runtime programs and installer output use English ASCII; Persian quick start lives outside terminal output.
- The preview systemd service executes a read-only status command at startup. It does not reconcile real networking.
- For production, the runtime must implement complete native nftables forwarding, bidirectional QoS and accounting, bounded diagnostics, transactional rollback, and ownership-scoped uninstall; then pass isolated netns/VM tests.

## Test commands

```bash
bash RUN_CONTRACT_TESTS.sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
bash -n install.sh templates/gre-tun
```

See `IMPLEMENTATION_STATUS.md` and `TEST_RESULTS.md` for the verified state. Only offline tests have been executed in this environment. No production or live GRE test has been conducted.
