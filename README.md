# unf2json

Read a UniFi Network controller backup (`.unf`) without restoring it. The script decrypts
the backup, dumps the database to JSON, and builds an HTML report of networks, port
profiles, network lists, WiFi SSIDs, AP groups, and switch port assignments.

Use it to look up an old config (for example, which port profile was on which switch port)
when the controller or device is gone.

## Requirements

- Python 3.10 or later
- [`cryptography`](https://pypi.org/project/cryptography/) (the only dependency)

## Setup

```bash
cd unf2json
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
# .venv/bin/python -m pip install -r requirements.txt     # Linux / macOS
```

## Usage

```bash
python unf2json.py <backup.unf> [--out DIR] [--include-secrets] [--no-open] [--dry-run]
```

| Option | Effect |
|---|---|
| `--out DIR` | Output directory. Default: `<backup name>_json` next to the backup file. |
| `--include-secrets` | Keep passphrases, password hashes and keys in `collections/`. Default: redacted. |
| `--no-open` | Do not open `report.html` in the browser when done. |
| `--dry-run` | Print backup metadata and collection counts. Write nothing. |

Examples:

```bash
# Dump and open the report
python unf2json.py network_backup_10.21.2026.unf

# Look inside first, write nothing
python unf2json.py network_backup_10.21.2026.unf --dry-run

# Write to a given folder, do not launch the browser (e.g. on a server)
python unf2json.py backup.unf --out ./dump --no-open
```

Exit code is `0` on success and `1` on error (missing file, not a `.unf`, corrupt data).

## Output

```
<out>/
├── collections/     One JSON file per MongoDB collection (raw data, secrets redacted)
├── summary.json     Name-resolved view of the site config
└── report.html      Self-contained visual report (no network access needed)
```

### summary.json

| Key | Contents |
|---|---|
| `backup` | File name, controller version, timestamp, format |
| `networks` | Name, purpose, VLAN, subnet, DHCP range, domain, IGMP snooping |
| `port_profiles` | Native / tagged / voice VLANs, port settings, and `used_on` (device → port ranges) |
| `network_lists` | Firewall groups (IPv4, IPv6, port lists) and their members |
| `wlans` | SSID, network, VLAN, security, WPA3/PMF, bands, isolation, AP groups, user group |
| `ap_groups` | Group name, member APs, SSIDs using the group |
| `devices` | Model, IP, MAC, firmware, and every port with its profile, VLANs and settings |
| `collection_counts` | Document count per collection |

Network IDs are replaced with network names. The tagged VLAN list is calculated from the
profile's forward mode: `all` = every LAN network, `customize` = every LAN network minus
the excluded ones, `native` = none.

Port `profile` values:

- A profile name: the port uses that port profile.
- `(custom)`: the port has its own settings, with no profile.
- `(controller default)`: the backup has no override for this port. It uses the
  controller's default profile, which is not stored per port.

### report.html

Sections: Networks, Port Profiles, Network Lists, WiFi SSIDs, AP Groups, Devices.

The Devices section draws each switch as a faceplate (odd ports on top, SFP ports apart):

- **Fill color**: native VLAN
- **Bottom stripe**: tagged VLANs
- **V**: voice VLAN
- **Hatched**: no override (controller default)

Click a port to see its settings. Click a VLAN in the legend to dim the ports that do not
carry it. A full port table is below each faceplate.

The report is built from `summary.json`, so it never holds secrets, even with
`--include-secrets`. It needs `report_template.html` in the same folder as the script.
If the template is missing, the script writes the JSON and skips the report.

## Security

- A `.unf` file is **not** protected. Every UniFi controller uses the same fixed AES key,
  so anyone with the file can read it. Store backups like you store passwords.
- By default, `collections/` has these fields replaced with `<redacted>`: all `x_*` fields
  (WLAN passphrases, admin password hashes, RADIUS secrets, SSH keys, device auth keys)
  and `psk`, `syslog_key`, `fingerbank_key`, `private_preshared_keys`. Boolean `x_*`
  flags (for example `x_ssh_enabled`) stay, because they are settings, not secrets.
- With `--include-secrets`, the output has secrets in plain text. Delete it when done.
- The script runs offline. It sends nothing over the network.

## How it works

1. **Decrypt**: AES-128-CBC with UniFi's fixed key and IV gives a zip file.
2. **Unzip**: the script reads the zip's local file headers directly. UniFi zips often
   have a broken central directory, so Python's `zipfile` can fail on them.
3. **Parse**: `db.gz` is a gzip stream of BSON documents. A `{"__cmd": "select",
   "collection": X}` document marks the start of each collection. A small built-in BSON
   parser reads it, so `pymongo` is not needed.
4. **Summarize**: IDs are resolved to names and the report template is filled in.

## Limitations

- **Supported**: UniFi Network application backups (`.unf`), self-hosted or Cloud Key.
  Tested on controller version 10.1.85.
- **Not supported**: UniFi OS console backups (`.unifi` from UDM, UCG, Cloud Key Gen2+).
  They use a different format.
- **Older controllers**: field names may differ. The raw dump in `collections/` will
  still work, but some `summary.json` fields can be empty.
- **Backup timestamp**: the `timestamp` file in the backup may not be the backup date.
  The date in the backup file name is more reliable.
- **VLAN colors**: given out by VLAN order. The same network can get a different color
  in a backup with a different set of networks.

## Troubleshooting

| Message | Cause |
|---|---|
| `Missing dependency: pip install cryptography` | Run setup, or use the venv's Python. |
| `Decrypted data is not a zip` | The file is not a UniFi Network `.unf` backup (maybe a `.unifi` console backup). |
| `db.gz not found in backup` | The backup is incomplete or from an unknown format. Run `--dry-run` and check the listed entries. |
| `Unsupported BSON type ...` | A data type the parser does not handle. Add a case for that type code in `_bson_doc()`. |
| Report does not open | Use `--no-open` and open `report.html` by hand, or check your default browser setting. |
