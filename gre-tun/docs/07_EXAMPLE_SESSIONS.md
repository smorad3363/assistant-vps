# Canonical example workflows

These are synthetic walkthroughs, not commands to apply on a real host. IPs are documentation addresses. Actual input/output text must use the catalog; bracketed descriptions below describe events and are not product UI.

## A. Fresh pair

First server: run gre-tun, choose role 1, let the single discovered local IP be selected automatically. Main 1 -> New tunnel 1. Enter peer IP, accept `Tunnel 1`, inspect summary and press Enter to apply. Local tunnel is created, health Unverified, and a GT1 setup token is printed.

Second server: install and run gre-tun, choose role 2. Main 1 -> Import setup code 2. Paste the token, inspect summary and press Enter. If candidate 0 and MTU are usable, no second configuration wizard is needed. On the first server use Main 3 -> T0001. The test only says PASS when local structure matches and an inner reply is observed.

If the second server chooses a different inner candidate/MTU, copy its updated GT1 token back to the first server through the same Import option. If all candidates conflict, copy its conflict token back; the first server proposes the next deterministic candidate set. Do not manually invent inner addresses or infer a route from a country label.

## B. Three ports with a remap

First server: Main 2 -> T0001 -> Ports 1 -> Add ports 1.

```text
Ports (443,5445:5454):
443,5445:5454,8080
Protocol [1=TCP, 2=UDP, 3=Both] (3):
3
Target IP [<discovered peer inner IP>]:
198.51.100.20
```

The discovered address placeholder above is descriptive documentation only. The application displays its actual validated default. There is no target-port prompt. A multi-address host additionally receives the one Listen IP question in the specified position. One summary and Apply creates P0001=443:443, P0002=5445:5454 and P0003=8080:8080; all use Both. The peer must already have the target services listening; the tunnel tool does not create those applications.

## C. Cap one port

Manage -> T0001 -> Ports -> Edit port -> P0002 -> Speed limits.

```text
Upload limit in Mbps [Unlimited] (0=Unlimited, b=Back):
10
Download limit in Mbps [Unlimited] (0=Unlimited, b=Back):
20
Apply changes? [Y/n]:
```

After Enter: P0002 shares 10 Mbps upload and 20 Mbps download across all TCP+UDP clients. Other ports remain Unlimited. TCP and UDP are not each granted 20 Mbps. Changing a cap does not reset the port's history or disconnect it.

## D. Read history

Manage -> T0001 -> Ports -> Traffic -> P0002. Display current rates, caps, Last 1h and Last 24h, coverage and Updated timestamp exactly in the example fixture's order. `r` takes one fresh bounded observation; `0` returns. A quiet port can have measured 0.00 Mbps. A missing observation is N/A.

## E. Remove and reinstall

Main 4 prints the impact notice and the one keep-data prompt. Enter keeps saved settings/history and removes active local resources. Reinstall validates those saved records and returns to the same definitions if no new conflict exists. Entering `n` at the prompt removes saved data too. `0` cancels. The other endpoint is not remotely changed in either mode.

## F. Editing a peer versus a target

Edit tunnel changes the physical GRE peer and produces updated pair setup for both ends. Edit mapping changes only that port's destination service address/port through the selected tunnel. These are different fields and operations. A target equal to the physical peer's public IP is allowed by the policy-routing design and tested explicitly; the tool does not solve it by refusing the target or rewriting the host's default route.
