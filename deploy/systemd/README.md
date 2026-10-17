# Bicameral fleet daemon — systemd deployment

Resident fleet heartbeat: `bicameral/fleet.py daemon` re-runs the exact
`check` round every `--interval` seconds, prints a loud
`*** STATE device: A -> B ***` line to the journal on every state
transition (ONLINE/STALE/OFFLINE, `new`, GONE), appends each round to the
daemon-owned hash chain `<registry dir>/audit.jsonl` (A2: `seq` +
`prev_sha256_16`) and writes the chain tail `sha256_16` into the separate
anchor file `audit.anchor`. Stdlib-only, unprivileged, no timers needed —
the process sleeps between rounds and exits gracefully (exit 0) on
SIGTERM/SIGINT after finishing the current round, so evidence and anchor
are always mutually consistent.

## Files

| file | purpose |
|---|---|
| `bicameral-fleet.service` | the daemon (env-var paths, `Restart=on-failure`, `OnFailure=`) |
| `bicameral-fleet-failure@.service` | OnFailure handler: appends one marker line to `/var/lib/bicameral/fleet/failures.log` |

## Install (three steps)

Step 0 (once, on the master host): an unprivileged user and the state dir —
the daemon only ever writes its registry/audit/anchor/reports under
`/var/lib/bicameral/fleet`.

```sh
sudo useradd -r -s /usr/sbin/nologin bicameral
sudo mkdir -p /var/lib/bicameral/fleet
sudo chown -R bicameral:bicameral /var/lib/bicameral/fleet
# repo at /opt/bicameral (adjust paths in the unit if it lives elsewhere)
```

Then the three steps:

```sh
sudo cp deploy/systemd/bicameral-fleet.service \
        deploy/systemd/bicameral-fleet-failure@.service \
        /etc/systemd/system/          # 1. copy the units
sudo systemctl daemon-reload         # 2. make systemd see them
sudo systemctl enable --now bicameral-fleet.service   # 3. start + boot-persist
```

Watch it work:

```sh
journalctl -u bicameral-fleet -f          # rounds, STATE events, anchored tails
systemctl status bicameral-fleet
```

## Configuration (environment variables)

Override without editing the unit: create `/etc/default/bicameral-fleet`
(`EnvironmentFile=-` in the unit — absence is fine), then
`sudo systemctl daemon-reload && sudo systemctl restart bicameral-fleet`.

| variable | default | meaning |
|---|---|---|
| `BICAMERAL_HOME` | `/opt/bicameral` | repo root (`WorkingDirectory`) |
| `BICAMERAL_DEVICES` | `/opt/bicameral/examples/devices.json` | devices/1 manifest |
| `BICAMERAL_REGISTRY` | `/var/lib/bicameral/fleet/registry.json` | fleet-registry/1 evidence file; the fleet audit is written beside it as `audit.jsonl`, probe reports beside it under `reports/` |
| `BICAMERAL_ANCHOR` | `/var/lib/bicameral/fleet/audit.anchor` | receives the audit tail `sha256_16` after every round |
| `BICAMERAL_INTERVAL` | `300` | seconds between rounds |

Failure behaviour: a crash is restarted with `Restart=on-failure`
(10 s pause, max 5 starts / 10 min) and `OnFailure=` drops a marker line;
a clean SIGTERM exit is never restarted. Verify the OnFailure path with
`systemctl start bicameral-fleet-failure@test.service` (adds one line to
`failures.log`; delete the line afterwards).

## Anchor hygiene — closing the A2 residual (one cron line)

In-file hash chaining cannot see deletion of the LAST audit row; the
anchor file is the external anchor that does. It only works if the anchor
survives an attacker who can rewrite the host — so copy it OFF-HOST after
every round. One line in the MASTER's crontab (`%` must be escaped as
`\%` in cron):

```cron
* * * * * scp -q /var/lib/bicameral/fleet/audit.anchor backup@backuphost:/srv/bicameral/anchors/audit.anchor.$(date +\%s) 2>/dev/null
```

Every minute is deliberate: it bounds the window in which a last-row
deletion could hide between copies. `backuphost` needs the key installed
(`ssh-keygen` + one `ssh-copy-id`); any second machine works — the point
is that it is not the machine the audit lives on.

Later, compare any external copy against the on-host audit (the anchor is
one JSON line: `tail_sha256_16`, `seq`, `audit_path`, `updated_utc`).
Compute the audit's current tail exactly as the daemon does (raw line
bytes, trailing newline excluded):

```sh
python3 -c "import sys,hashlib;ls=[l for l in open(sys.argv[1],'rb') if l.strip()];print(hashlib.sha256(ls[-1].rstrip(b'\n')).hexdigest()[:16])" /var/lib/bicameral/fleet/audit.jsonl
```

Read it as: run the expression on the host, compare the printed hash with
`tail_sha256_16` in the off-host anchor copy — equal means no last-row
deletion since that anchor was taken; different (or a smaller top `seq`
than the anchor's) means the audit was truncated and the off-host copy is
your proof.
