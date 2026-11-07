# GRE Manager 0.2.2

Role-aware interactive GRE setup for Linux with IPv4, root access and systemd.

## Permanent installation / update command

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre.sh | sudo bash
```

The original permanent entry point continues to work unchanged:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/gre-manager/install.sh | sudo bash
```

Run on **both** servers. The wizard reads `/dev/tty`, so prompts work when the
installer is piped to Bash. Application downloads are pinned to one commit and
verified against SHA256 values embedded in the installer. Updates preserve all
existing configuration, pair profiles, backups and traffic-history files.
The installer does not restart active tunnels merely to update application files.

## Questions

1. Role: `1` Iran, `2` Foreign.
2. Local GRE IPv4, detected by default. On a server with several IPs this may be
   different from the service IP.
3. Other server's **GRE endpoint** IPv4. Enter complementary endpoint addresses
   on the two servers; the wizard prints exactly what to enter on the other side.
4. Iran listen IP, or Foreign local service/destination IP.
5. **Iran only:** `all` or comma-separated ports, optionally `input:output`.

Examples:

- `all`: all TCP and UDP ports, unchanged, **except Iran input port 22**.
- `80,443,2096`: the same three TCP and UDP ports on the foreign service.
- `443,8080:80,2053:2096`: preserve 443, forward Iran 8080 to Foreign 80, and
  forward Iran 2053 to Foreign 2096.

Foreign never forwards its public input back to Iran. It accepts traffic arriving
inside this pair's GRE interface and delivers it to the selected local service IP.
Mappings happen once, on Iran. There is no duplicated mapping list to synchronize.
Input 22 cannot be included in a specific-port list and stays on the Iran server;
an explicit mapping such as `2222:22` intentionally targets Foreign SSH.
Services must already listen on the Foreign service IP or on all addresses.
GRE requires protocol 47 connectivity; this tool cannot bypass an upstream GRE block.
Directly assigned local IPv4 endpoints are supported; upstream NAT is not inferred.

### Current Iran / Finland pair

The earlier `/etc/gre-ir-fi.conf` deployment is recognized, with its saved GRE
endpoints and service IP as defaults. Matching setup migrates that pair only after
all answers validate, retains the old files, and rolls back the old service if
local activation fails. Run the wizard on **both ends** to complete migration;
expect a brief interruption while the second end is configured.
For this deployment GRE uses `94.184.22.49` and `65.109.240.226`, while the Foreign
service IP remains `2.29.39.22`. The migration does not change that service IP.
Unrelated existing port forwards cause an explicit conflict instead of being
silently overwritten. Multiple saved pairs work when their Iran input ports do
not overlap; `all` consumes that Iran listen IP's complete non-SSH port space.

## Management

```bash
sudo gremgr --wizard
sudo gremgr-pair list
sudo gremgr-pair status PAIR_ID
sudo systemctl restart gremgr-pair@PAIR_ID.service
sudo systemctl disable --now gremgr-pair@PAIR_ID.service
```

Saved profiles live in `/etc/gremgr/pairs/`; edit backups live in its `backups/`
subdirectory. Program-install backups live in `/etc/gremgr/backups/`.
Each pair has its own boot-enabled systemd service, keyed GRE interface,
private /30, scoped firewall rules, Iran SNAT and TCP MSS adjustment.
Repeated activation is idempotent. Stop removes only the exact rules of that pair.

### Conservative MTU on unreliable links

New GRE pairs use MTU **1400** (conservative, not the largest possible value).
The wizard now asks for GRE MTU explicitly and retains the saved value by default.
On a variable path, do not raise GRE MTU to the largest one-off successful ping.
A smaller GRE MTU leaves more headroom for underlay variability, but may increase
fragmentation of large UDP datagrams; check packet loss and fragmentation counters.
WireGuard `wg0` MTU (commonly 1280) and existing client MTUs are independent.

Change an existing pair safely on **both** endpoints, without restarting GRE,
touching ports or changing WireGuard clients:

```bash
sudo gremgr-pair set-mtu PAIR_ID 1400
sudo gremgr-pair status PAIR_ID
```

`set-mtu` changes only the owned GRE interface MTU, its saved profile and, on
Iran, the corresponding TCP MSS rules. It keeps a timestamped backup in
`/etc/gremgr/pairs/backups/` and rolls back the live changes on failure.
The saved MTU survives reboot and subsequent GRE Manager upgrades. Existing
pairs are **not** automatically changed during an installer update.

### Docker WireGuard behind GRE

On a Foreign GRE endpoint, when Docker publishes UDP/51820, GRE Manager
installs a narrowly scoped jump to Docker's DNAT chain **before** its broad
GRE receive rule. This avoids the UDP userland-proxy path under heavy load.
A lightweight timer rechecks the rule after Docker/Compose starts or rewrites
its firewall chains; it does not restart Docker, WireGuard, or GRE.
No public port or unrelated Docker firewall rule is modified. Existing GRE
pairs keep their saved MTU (for example, 1420) when reconfigured. Fresh pairs
default to 1400, not 1280; `wg0`/client MTU is separate and is not changed.

Manual refresh and inspection:

```bash
sudo gremgr-pair docker-sync-all
sudo systemctl status gremgr-docker-sync.timer
sudo iptables -t nat -S PREROUTING | grep docker-wg
```

A failed configuration edit restores the previous profile and active service.
No blanket firewall flush, default-route replacement, IPv6 change or VPN service
restart is performed. Existing tracked sessions can retain their old mapping until
reconnection; the tool does not flush unrelated conntrack state.

`gremgr` retains the original tunnel/forward menus and adds option 6 for this wizard.
Legacy menu-created tunnels are kept separate from the new pair profiles.

## Validation

```bash
python3 -m unittest discover -s gre-manager -p test_pair.py -v
sudo unshare --mount --net --fork bash gre-manager/test-netns.sh
```

The network lab refuses the host network namespace. Its private mount/network
namespaces contain three hosts with DROP policies and real keyed GRE. It checks
TCP and UDP mappings, all-port mode, port 65535, a destination bound to a separate
service IP, local SSH, repeated restore and exact-rule cleanup with an unrelated
baseline rule retained. Completed successfully on Ubuntu 24.04, 2026-11-02.
