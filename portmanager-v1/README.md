# Port Manager 11 — frozen original version

V1 is deliberately preserved as a separate legacy implementation under
`portmanager-v1/legacy-install.sh`, byte-for-byte matching the former
`portmanager-dashboard/install.sh`. Its compressed Bash payload remains
unchanged under `portmanager-dashboard/portmanager.sh.gz.b64`.

## One shared installation URL

**Default V2** (installs the separate `portmanager2` command):

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
```

**Explicit old V1** (installs the original `portmanager` command):

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- v1
```

`sudo bash v1` **does not** work in a pipe: Bash treats `v1` as a script
filename and ignores stdin. Always use `bash -s -- v1` to route an argument.

Alternative direct V1 URL:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-v1/install.sh | sudo bash
```

V1 installs exactly the original binary/config/cron/accounting/tc behavior.
Do not run V1 on a host with active V2 scheduled `tc` enforcement; the
new V1 alias refuses that conflict. A direct legacy installer has no such
guard and is only for recovery on a controlled VM.

V2 is independently installed; it never automatically removes V1.
