#!/usr/bin/env python3
"""Decrypt a UniFi Network controller backup (.unf) and dump it to JSON plus an HTML report.

Output:
    <out>/collections/<name>.json  Raw MongoDB collections, one file per collection.
    <out>/summary.json             Networks, port profiles, network lists, SSIDs, AP groups
                                   and per-device port maps, with object IDs resolved to names.
    <out>/report.html              Self-contained visual report (opened in the browser by default).

Secrets (x_* fields, PSKs, etc.) are redacted unless --include-secrets is given.

Not supported: UniFi OS console backups (.unifi), which use a different format.
"""
from __future__ import annotations

import argparse
import gzip
import json
import struct
import sys
import webbrowser
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

# Fixed key/IV used by every UniFi Network controller for .unf backups.
UNF_KEY = b"bcyangkmluohmars"
UNF_IV = b"ubntenterpriseap"

# Non-x_ fields that also hold secrets. x_* fields are always treated as secret.
SECRET_KEYS = {"psk", "syslog_key", "fingerbank_key", "private_preshared_keys"}
REDACTED = "<redacted>"

# Network purposes that can be carried on a switch port (excludes WAN, VPN, etc.).
LAN_PURPOSES = {"corporate", "vlan-only", "guest"}

TEMPLATE = Path(__file__).with_name("report_template.html")
TEMPLATE_MARKER = "__SUMMARY_JSON__"

Doc = dict[str, Any]


def decrypt_unf(data: bytes) -> bytes:
    """Decrypt .unf bytes into the inner zip archive.

    Args:
        data: Raw .unf file contents.

    Returns:
        Decrypted zip bytes.

    Raises:
        ValueError: If the result is not a zip (wrong file type or corrupt file).
    """
    if len(data) % 16:
        # Backups are block-aligned; trim a trailing partial block rather than fail.
        data = data[: len(data) - len(data) % 16]
    dec = Cipher(algorithms.AES(UNF_KEY), modes.CBC(UNF_IV)).decryptor()
    out = dec.update(data) + dec.finalize()
    if not out.startswith(b"PK\x03\x04"):
        raise ValueError("Decrypted data is not a zip. Is this a UniFi Network .unf backup?")
    return out


def read_zip_entries(data: bytes) -> dict[str, bytes]:
    """Extract entries by walking local file headers.

    UniFi zips often have a truncated or invalid central directory, so zipfile cannot
    be trusted. Local headers are enough because entries are written sequentially.
    """
    entries: dict[str, bytes] = {}
    pos = 0
    while (pos := data.find(b"PK\x03\x04", pos)) >= 0:
        try:
            (_, _, method, _, _, _, csize, _, nlen, xlen) = struct.unpack(
                "<HHHHHIIIHH", data[pos + 4 : pos + 30]
            )
        except struct.error:
            break
        name = data[pos + 30 : pos + 30 + nlen].decode(errors="replace")
        start = pos + 30 + nlen + xlen
        if method == 8:
            # Sizes may be zero in the header (data descriptor), so inflate until stream end.
            inflater = zlib.decompressobj(-15)
            try:
                body = inflater.decompress(data[start:])
            except zlib.error as exc:
                raise ValueError(f"Corrupt zip entry {name!r}: {exc}") from exc
            consumed = len(data) - start - len(inflater.unused_data)
        elif method == 0:
            body = data[start : start + csize]
            consumed = csize
        else:
            raise ValueError(f"Unsupported zip compression method {method} for {name!r}")
        entries[name] = body
        pos = start + max(consumed, 1)
    return entries


def _bson_doc(b: bytes, i: int) -> tuple[Doc, int]:
    """Parse one BSON document starting at offset i. Returns (doc, next_offset)."""
    size = struct.unpack_from("<i", b, i)[0]
    end = i + size - 1
    i += 4
    doc: Doc = {}
    while i < end:
        t = b[i]
        k_end = b.index(b"\x00", i + 1)
        key = b[i + 1 : k_end].decode(errors="replace")
        i = k_end + 1
        v: Any
        if t == 0x01:  # double
            v = struct.unpack_from("<d", b, i)[0]
            i += 8
        elif t in (0x02, 0x0D, 0x0E):  # string, JS code, symbol
            n = struct.unpack_from("<i", b, i)[0]
            v = b[i + 4 : i + 3 + n].decode(errors="replace")
            i += 4 + n
        elif t in (0x03, 0x04):  # document, array
            sub, i = _bson_doc(b, i)
            v = list(sub.values()) if t == 0x04 else sub
        elif t == 0x05:  # binary
            n = struct.unpack_from("<i", b, i)[0]
            v = b[i + 5 : i + 5 + n].hex()
            i += 5 + n
        elif t == 0x07:  # ObjectId
            v = b[i : i + 12].hex()
            i += 12
        elif t == 0x08:
            v = bool(b[i])
            i += 1
        elif t == 0x09:  # UTC datetime (ms)
            ms = struct.unpack_from("<q", b, i)[0]
            i += 8
            try:
                v = datetime.fromtimestamp(ms / 1000, timezone.utc).isoformat()
            except (OverflowError, OSError, ValueError):
                v = ms
        elif t in (0x06, 0x0A, 0x7F, 0xFF):  # undefined, null, max/min key
            v = None
        elif t == 0x0B:  # regex: two cstrings
            p_end = b.index(b"\x00", i)
            o_end = b.index(b"\x00", p_end + 1)
            v = f"/{b[i:p_end].decode(errors='replace')}/{b[p_end + 1:o_end].decode()}"
            i = o_end + 1
        elif t == 0x10:
            v = struct.unpack_from("<i", b, i)[0]
            i += 4
        elif t in (0x11, 0x12):  # timestamp, int64
            v = struct.unpack_from("<q", b, i)[0]
            i += 8
        elif t == 0x13:  # decimal128, kept raw
            v = b[i : i + 16].hex()
            i += 16
        else:
            raise ValueError(f"Unsupported BSON type {t:#04x} for key {key!r} at offset {i}")
        doc[key] = v
    return doc, end + 1


def parse_db_dump(raw: bytes) -> dict[str, list[Doc]]:
    """Split the db.gz BSON stream into collections.

    The stream is a flat run of documents; a {"__cmd": "select", "collection": X}
    marker switches the target collection for the documents that follow.
    """
    colls: dict[str, list[Doc]] = {}
    current: str | None = None
    i = 0
    while i < len(raw):
        doc, i = _bson_doc(raw, i)
        if doc.get("__cmd") == "select":
            current = str(doc.get("collection"))
            colls.setdefault(current, [])
        elif current is not None:
            colls[current].append(doc)
    return colls


def redact(obj: Any) -> Any:
    """Return a copy of obj with secret fields replaced. Booleans are kept (they are flags)."""
    if isinstance(obj, dict):
        out: Doc = {}
        for k, v in obj.items():
            secret = k.startswith("x_") or k in SECRET_KEYS
            if secret and v not in (None, "", []) and not isinstance(v, bool):
                out[k] = REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(obj, list):
        return [redact(v) for v in obj]
    return obj


def _ranges(nums: list[int]) -> str:
    """Compress [1,2,3,5] into '1-3, 5'."""
    out: list[str] = []
    nums = sorted(set(nums))
    i = 0
    while i < len(nums):
        j = i
        while j + 1 < len(nums) and nums[j + 1] == nums[j] + 1:
            j += 1
        out.append(str(nums[i]) if i == j else f"{nums[i]}-{nums[j]}")
        i = j + 1
    return ", ".join(out)


def _effective_vlans(cfg: Doc, lan_ids: list[str], net_name: dict[str, str]) -> Doc:
    """Work out which networks a port profile/override actually carries.

    UniFi stores intent (forward mode + exclusions), not the final tagged list, so
    "all" and "customize" must be expanded against the site's LAN networks.
    """
    native = cfg.get("native_networkconf_id") or None
    fwd = cfg.get("forward")
    if fwd == "disabled":
        native, tagged = None, []
    elif fwd == "all":
        tagged = [i for i in lan_ids if i != native]
    elif fwd == "customize":
        if cfg.get("tagged_networkconf_ids"):  # older controllers store an include list
            tagged = list(cfg["tagged_networkconf_ids"])
        else:
            excl = set(cfg.get("excluded_networkconf_ids", []))
            tagged = [i for i in lan_ids if i not in excl and i != native]
    else:  # "native" or unset
        tagged = []
    voice = cfg.get("voice_networkconf_id") or None
    return {
        "native": net_name.get(native, native) if native else None,
        "tagged": [net_name.get(i, i) for i in tagged],
        "voice": net_name.get(voice, voice) if voice else None,
    }


def _port_settings(cfg: Doc) -> Doc:
    """Pick the non-VLAN port settings worth showing."""
    out: Doc = {
        "forward": cfg.get("forward"),
        "poe_mode": cfg.get("poe_mode"),
        "lldpmed_enabled": cfg.get("lldpmed_enabled"),
        "isolation": cfg.get("isolation"),
        "port_security_enabled": cfg.get("port_security_enabled"),
        "dot1x_ctrl": cfg.get("dot1x_ctrl"),
        "stormctrl": any(cfg.get(f"stormctrl_{t}_enabled") for t in ("bcast", "mcast", "ucast")),
        "stp_port_mode": cfg.get("stp_port_mode"),
        "op_mode": cfg.get("op_mode"),
        "speed": None if cfg.get("autoneg", True) else cfg.get("speed"),
    }
    return {k: v for k, v in out.items() if v is not None}


def build_summary(colls: dict[str, list[Doc]], meta: dict[str, str]) -> Doc:
    """Build a name-resolved view of the site configuration.

    Args:
        colls: Parsed collections from the backup.
        meta: Backup metadata (file name, version, timestamp).

    Returns:
        A JSON-serializable summary dict.
    """
    sites = {s["_id"]: s.get("desc") or s.get("name") for s in colls.get("site", [])}
    nets = colls.get("networkconf", [])
    net_name = {n["_id"]: n.get("name", n["_id"]) for n in nets}
    net_vlan = {n.get("name"): (n.get("vlan") if n.get("vlan_enabled") else None) for n in nets}
    lan_ids_by_site: dict[str, list[str]] = {}
    for n in nets:
        if n.get("purpose") in LAN_PURPOSES and n.get("enabled", True):
            lan_ids_by_site.setdefault(n.get("site_id", ""), []).append(n["_id"])
    profiles = {p["_id"]: p for p in colls.get("portconf", [])}
    devices_raw = colls.get("device", [])
    dev_by_mac = {d.get("mac"): d for d in devices_raw}
    user_groups = {g["_id"]: g.get("name") for g in colls.get("usergroup", [])}

    networks = [
        {
            "site": sites.get(n.get("site_id")),
            "name": n.get("name"),
            "purpose": n.get("purpose"),
            "vlan": n.get("vlan") if n.get("vlan_enabled") else None,
            "subnet": n.get("ip_subnet"),
            "dhcp": (
                f"{n.get('dhcpd_start')} - {n.get('dhcpd_stop')}"
                if n.get("dhcpd_enabled") else None
            ),
            "domain": n.get("domain_name") or None,
            "igmp_snooping": n.get("igmp_snooping"),
            "enabled": n.get("enabled", True),
        }
        for n in nets
    ]

    # Devices first, so port profiles can list where they are used.
    devices: list[Doc] = []
    used_on: dict[str, dict[str, list[int]]] = {}
    for d in devices_raw:
        lan_ids = lan_ids_by_site.get(d.get("site_id", ""), [])
        overrides = {o.get("port_idx"): o for o in d.get("port_overrides", [])}
        table = {p.get("port_idx"): p for p in d.get("port_table", [])}
        ports = []
        # port_table lists every physical port; overrides only list changed ones.
        for idx in sorted(i for i in set(table) | set(overrides) if i is not None):
            o = overrides.get(idx, {})
            phys = table.get(idx, {})
            entry: Doc = {
                "port": idx,
                "name": o.get("name") or phys.get("name") or f"Port {idx}",
                "media": phys.get("media"),
                "poe_capable": phys.get("port_poe"),
            }
            if o.get("portconf_id"):
                prof = profiles.get(o["portconf_id"], {})
                entry["profile"] = prof.get("name", o["portconf_id"])
                entry["vlans"] = _effective_vlans(prof, lan_ids, net_name)
                entry["settings"] = _port_settings(prof)
                used_on.setdefault(o["portconf_id"], {}).setdefault(
                    d.get("name") or d.get("mac"), []).append(idx)
            elif o:
                entry["profile"] = "(custom)"
                entry["vlans"] = _effective_vlans(o, lan_ids, net_name)
                entry["settings"] = _port_settings(o)
            else:
                entry["profile"] = "(controller default)"
            if o.get("poe_mode"):
                entry.setdefault("settings", {})["poe_mode"] = o["poe_mode"]
            ports.append({k: v for k, v in entry.items() if v is not None})
        devices.append({
            "site": sites.get(d.get("site_id")),
            "name": d.get("name"),
            "model": d.get("model"),
            "type": d.get("type"),
            "mac": d.get("mac"),
            "ip": d.get("ip"),
            "serial": d.get("serial"),
            "firmware": d.get("version"),
            "adopted": d.get("adopted"),
            "ports": ports,
        })

    port_profiles = [
        {
            "site": sites.get(p.get("site_id")),
            "name": p.get("name"),
            "vlans": _effective_vlans(p, lan_ids_by_site.get(p.get("site_id", ""), []), net_name),
            "settings": _port_settings(p),
            "used_on": {dev: _ranges(idxs) for dev, idxs in used_on.get(pid, {}).items()},
        }
        for pid, p in profiles.items()
    ]

    # Network Lists (UI name) are stored as firewall groups.
    network_lists = [
        {
            "site": sites.get(g.get("site_id")),
            "name": g.get("name"),
            "type": g.get("group_type"),
            "members": g.get("group_members", []),
        }
        for g in colls.get("firewallgroup", [])
    ]

    ap_group_docs = colls.get("apgroup", [])
    ap_group_name = {g["_id"]: g.get("name") for g in ap_group_docs}
    all_aps = [d.get("name") or d.get("mac") for d in devices_raw if d.get("type") == "uap"]

    wlans = []
    ssids_by_group: dict[str, list[str]] = {}
    for w in colls.get("wlanconf", []):
        net = net_name.get(w.get("networkconf_id", ""), w.get("networkconf_id"))
        group_ids = w.get("ap_group_ids", [])
        for gid in group_ids:
            ssids_by_group.setdefault(gid, []).append(w.get("name"))
        wlans.append({
            "site": sites.get(w.get("site_id")),
            "ssid": w.get("name"),
            "enabled": w.get("enabled"),
            "network": net,
            "vlan": net_vlan.get(net),
            "security": w.get("security"),
            "wpa_mode": w.get("wpa_mode"),
            "wpa3": w.get("wpa3_support"),
            "wpa3_transition": w.get("wpa3_transition"),
            "pmf_mode": w.get("pmf_mode"),
            "bands": w.get("wlan_bands"),
            "hidden": w.get("hide_ssid"),
            "guest": w.get("is_guest"),
            "l2_isolation": w.get("l2_isolation"),
            "fast_roaming": w.get("fast_roaming_enabled"),
            "mac_filter": (
                f"{w.get('mac_filter_policy', 'allow')} ({len(w.get('mac_filter_list', []))})"
                if w.get("mac_filter_enabled") else None
            ),
            "ap_group_mode": w.get("ap_group_mode"),
            "ap_groups": [ap_group_name.get(g, g) for g in group_ids],
            "user_group": user_groups.get(w.get("usergroup_id", ""), w.get("usergroup_id")),
            # Hidden system SSIDs (e.g. wireless-uplink "element-*") lack networkconf_id.
            "system": "networkconf_id" not in w,
        })

    ap_groups = []
    for g in ap_group_docs:
        macs = g.get("device_macs", [])
        if g.get("attr_hidden_id") == "default" and not macs:
            members = all_aps  # the built-in "All APs" group has no explicit member list
        else:
            members = [(dev_by_mac.get(m) or {}).get("name") or m for m in macs]
        ap_groups.append({
            "site": sites.get(g.get("site_id")),
            "name": g.get("name"),
            "builtin": bool(g.get("attr_no_delete")),
            "aps": members,
            "ssids": ssids_by_group.get(g["_id"], []),
        })

    return {
        "backup": meta,
        "sites": [v for v in sites.values() if v],
        "networks": networks,
        "port_profiles": port_profiles,
        "network_lists": network_lists,
        "wlans": wlans,
        "ap_groups": ap_groups,
        "devices": devices,
        "collection_counts": {k: len(v) for k, v in colls.items() if v},
    }


def write_report(summary: Doc, out_file: Path) -> bool:
    """Render report_template.html with the summary embedded. Returns False if no template."""
    if not TEMPLATE.is_file():
        print(f"Warning: {TEMPLATE.name} not found next to script; skipping HTML report.",
              file=sys.stderr)
        return False
    # Escape "</" so data like an SSID named "</script>" cannot break out of the script tag.
    payload = json.dumps(summary, default=str).replace("</", "<\\/")
    html = TEMPLATE.read_text(encoding="utf-8").replace(TEMPLATE_MARKER, payload, 1)
    out_file.write_text(html, encoding="utf-8")
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("backup", type=Path, help="UniFi Network .unf backup file")
    ap.add_argument("--out", type=Path, help="Output directory (default: <backup name>_json)")
    ap.add_argument("--include-secrets", action="store_true",
                    help="Keep passphrases, password hashes and keys in the JSON output")
    ap.add_argument("--no-open", action="store_true",
                    help="Do not open report.html in the browser when done")
    ap.add_argument("--dry-run", action="store_true",
                    help="Print collections and counts; write nothing")
    args = ap.parse_args()

    if not args.backup.is_file():
        print(f"Error: file not found: {args.backup}", file=sys.stderr)
        return 1

    try:
        entries = read_zip_entries(decrypt_unf(args.backup.read_bytes()))
        if "db.gz" not in entries:
            raise ValueError(f"db.gz not found in backup (entries: {sorted(entries)})")
        colls = parse_db_dump(gzip.decompress(entries["db.gz"]))
    except (ValueError, OSError, EOFError, struct.error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    meta = {
        "file": args.backup.name,
        "version": entries.get("version", b"").decode(errors="replace").strip(),
        "timestamp": entries.get("timestamp", b"").decode(errors="replace").strip(),
        "format": entries.get("format", b"").decode(errors="replace").strip(),
    }
    if meta["timestamp"].isdigit():
        meta["timestamp"] = datetime.fromtimestamp(
            int(meta["timestamp"]) / 1000, timezone.utc).isoformat()

    if args.dry_run:
        print(json.dumps(meta, indent=2))
        for name, docs in sorted(colls.items()):
            if docs:
                print(f"  {name:32} {len(docs):>6}")
        return 0

    if not args.include_secrets:
        colls = {k: redact(v) for k, v in colls.items()}

    out = args.out or args.backup.with_name(f"{args.backup.stem}_json")
    (out / "collections").mkdir(parents=True, exist_ok=True)
    for name, docs in colls.items():
        if docs:
            (out / "collections" / f"{name}.json").write_text(
                json.dumps(docs, indent=2, default=str), encoding="utf-8")
    # The summary never contains secrets, so it is safe to embed in the report either way.
    summary = build_summary(redact(colls), meta)
    (out / "summary.json").write_text(
        json.dumps(summary, indent=2, default=str), encoding="utf-8")

    print(f"Wrote {sum(1 for d in colls.values() if d)} collections + summary.json to {out}")
    report = out / "report.html"
    if write_report(summary, report):
        print(f"Wrote {report}")
        if not args.no_open:
            webbrowser.open(report.resolve().as_uri())
    if args.include_secrets:
        print("WARNING: collections/ contains secrets (passphrases, hashes, keys).",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
