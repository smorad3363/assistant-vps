# Primary technical references

Checked during specification preparation on 2026-10-17. These establish underlying mechanics, not proof that this application's implementation works. Normative app choices are specified by this package. Do not copy historical or obsolete examples from a source without validating them on the release target.

| Topic | Primary source |
|---|---|
| GRE header and IPv4 protocol 47 | https://www.rfc-editor.org/rfc/rfc2784.html |
| Stateful NAT: only first packet traverses NAT rule lookup | https://wiki.nftables.org/wiki-nftables/index.php/Performing_Network_Address_Translation_(NAT) |
| nft hook priorities and ACCEPT versus another chain's DROP | https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains |
| HTB traffic classes, rate/ceil and bursts | https://man7.org/linux/man-pages/man8/tc-htb.8.html |
| IFB redirection mechanism | https://man7.org/linux/man-pages/man8/tc-mirred.8.html |
| Conntrack classification in tc | https://man7.org/linux/man-pages/man8/tc-ct.8.html |
| Restoring connection mark for ingress classification | https://man7.org/linux/man-pages/man8/tc-ctinfo.8.html |
| Policy-routing selectors | https://man7.org/linux/man-pages/man8/ip-rule.8.html |
| Kernel IPv4 forwarding and reverse-path controls | https://docs.kernel.org/networking/ip-sysctl.html |
| Model/effort selection | https://learn.chatgpt.com/docs/models |

The man7 iproute2 pages identify their upstream project source. The application must test the installed distro versions, not assume the latest online syntax is available everywhere.
