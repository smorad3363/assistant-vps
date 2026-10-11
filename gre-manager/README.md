# GRE Manager

Minimal interactive GRE tunnel manager for Linux.

## Install / Update

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-manager/install.sh | sudo bash
```

Then run:

```bash
gremgr
```

## Menu

- Test GRE: creates a temporary GRE tunnel, waits for the peer, tests ping/MTU, and always cleans up on exit/Ctrl+C.
- Add Tunnel: auto-detects WAN interface/IP, creates a persistent GRE tunnel, and enables restore after reboot.
- Tunnels: status, manual restart, edit, enable/disable, delete.
- Port Forward: TCP/UDP forwarding to the peer tunnel IP.
- Status / Logs: tunnel state, current-boot systemd restore log, and manager log.

## Notes

Run the same tool on both servers. For a new tunnel, enter the other server's public IP on each side.

The script does not require entering the local public IP or interface; it detects them automatically. Multiple tunnels are supported.
