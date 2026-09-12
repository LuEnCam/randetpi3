#!/usr/bin/env python3
"""randnetpi3 - answer a dial-up call from a Nintendo 64 Randnet modem and hand
the line to pppd.

  * Python 3.9+, and pyserial is the only third party dependency.
    Gone: sh, python-iptables (iptc), urllib2, netifaces, wvdialconf, net-tools.
  * pppd runs as a supervised child process (nodetach) instead of being fired
    off with `pon` and then detected as gone by tailing /var/log/messages.
  * All tunables live in an ini file, including the option to pin the PPP
    address pair so the console's IP stops moving between sessions.
  * No fork()/pidfile daemon.  Run it under systemd and log to the journal.

Run with --self-test to exercise the pure logic with no hardware and no root,
or with --dry-run to print every file, command and rule it would produce
without touching the system.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import errno
import json
import logging
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import termios
import time

logger = logging.getLogger("randnetpi3")

VERSION = "3.0"

DEFAULTS = {
    "modem": {
        "device": "",
        "speed": "57600",
        "usb_id": "",
        "dial_tone": "yes",
        "dial_tone_wav": "",
        "answer_delay": "8.0",
        "post_answer_delay": "5.0",
        "reconnect_delay": "5.0",
    },
    "ppp": {
        "pppd": "",
        "peers_name": "randnet",
        "local_ip": "",
        "peer_ip": "",
        "ip_search_start": "",
        "chap_client": "*",
        "chap_name": "Randnet",
        "chap_secret": "K1QU0K@N",
        "chap_secret_b64": "",
        "ms_dns": "",
        "record_file": "",
        "log_file": "",
        "extra_options": "",
    },
    "network": {
        "restart_dnsmasq": "yes",
        "randnet_redirect": "host",
        "randnet_domain": "randnet.ne.jp",
        "randnet_hostnames": (
            "randnet.ne.jp, www.randnet.ne.jp, peach.randnet.ne.jp, "
            "dd.randnet.ne.jp, smtp.dd.randnet.ne.jp, pop.dd.randnet.ne.jp"
        ),
        "dnsmasq_redirect_file": "/etc/dnsmasq.d/randnetpi3-redirect.conf",
        "dns_redirect": "172.16.10.30, 172.16.10.31",
        "proxy_hosts": "172.16.10.40:8080, 172.16.10.41:8080",
        "proxy_target_port": "",
        "transparent_http": "yes",
        "transparent_http_port": "8080",
        "manage_etc_hosts": "yes",
        "randnet_tls": "no",
        "randnet_tls_host": "",
        "randnet_tls_port": "443",
        "randnet_tunnel_port": "8443",
        "ppp_interface": "ppp+",
    },
}

PEERS_DIR = "/etc/ppp/peers"
CHAP_SECRETS = "/etc/ppp/chap-secrets"
PPP_OPTIONS = "/etc/ppp/options"

CHAP_MARKER = "# managed by randnetpi3 - do not edit this line by hand"

INTERNET_CHECK_HOSTS = (
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "208.67.222.222",
    "208.67.220.220",
)

DTMF_CHARS = "0123456789ABCD*#"

DLE = 0x10



def load_config(path=None):

    parser = configparser.ConfigParser(interpolation=None)
    parser.read_dict(DEFAULTS)

    if path:
        if not os.path.exists(path):
            raise SystemExit("config file not found: %s" % path)
        read = parser.read(path)
        if not read:
            raise SystemExit("could not parse config file: %s" % path)
        logger.info("Loaded config from %s", path)

    return parser



def run(argv, check=True, quiet=False):

    if not quiet:
        logger.debug("exec: %s", " ".join(argv))
    try:
        result = subprocess.run(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )
    except FileNotFoundError:
        if check:
            raise
        logger.debug("%s is not installed", argv[0])
        return ""
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, argv, result.stdout, result.stderr
        )
    return result.stdout.decode("utf-8", "replace")


def parse_default_route(payload):

    try:
        routes = json.loads(payload)
    except (ValueError, TypeError):
        routes = None

    if isinstance(routes, list):
        for route in routes:
            if route.get("dst") == "default" and route.get("gateway"):
                return route["gateway"], route.get("dev")
        return None, None

    for line in payload.splitlines():
        fields = line.split()
        if not fields or fields[0] != "default":
            continue
        gateway = iface = None
        for index, field in enumerate(fields):
            if field == "via" and index + 1 < len(fields):
                gateway = fields[index + 1]
            elif field == "dev" and index + 1 < len(fields):
                iface = fields[index + 1]
        if gateway:
            return gateway, iface

    return None, None


def parse_used_addresses(neigh_payload, addr_payload):

    used = set()

    try:
        neighbours = json.loads(neigh_payload)
    except (ValueError, TypeError):
        neighbours = []

    for entry in neighbours or []:
        dst = entry.get("dst")
        if not dst:
            continue
        states = [state.upper() for state in entry.get("state", [])]
        if "FAILED" in states or "INCOMPLETE" in states:
            continue
        used.add(dst)

    try:
        links = json.loads(addr_payload)
    except (ValueError, TypeError):
        links = []

    for link in links or []:
        for info in link.get("addr_info", []):
            if info.get("family") == "inet" and info.get("local"):
                used.add(info["local"])

    return used


def find_ip_pair(start, used):

    parts = [int(octet) for octet in start.split(".")]
    if len(parts) != 4:
        raise ValueError("not a dotted quad: %s" % start)

    found = []
    candidate = parts[3] - 1
    while candidate > 0 and len(found) < 2:
        test = "%d.%d.%d.%d" % (parts[0], parts[1], parts[2], candidate)
        if test not in used:
            found.append(test)
        candidate -= 1

    if len(found) < 2:
        raise RuntimeError("unable to find two free addresses below %s" % start)

    return found[0], found[1]


def discover_addresses(cfg):

    local = cfg.get("ppp", "local_ip").strip()
    peer = cfg.get("ppp", "peer_ip").strip()
    if local and peer:
        logger.info("Using pinned addresses: local=%s peer=%s", local, peer)
        return local, peer

    route_payload = run(["ip", "-j", "route"], check=False)
    gateway, iface = parse_default_route(route_payload)
    if not gateway:
        route_payload = run(["ip", "route", "show", "default"], check=False)
        gateway, iface = parse_default_route(route_payload)
    if not gateway:
        raise RuntimeError("no default route; cannot work out the local subnet")

    logger.info("Default route via %s on %s", gateway, iface)

    start = cfg.get("ppp", "ip_search_start").strip()
    if not start:
        octets = gateway.split(".")
        start = ".".join(octets[:3] + ["100"])

    neigh_argv = ["ip", "-j", "neigh"]
    if iface:
        neigh_argv += ["show", "dev", iface]
    used = parse_used_addresses(
        run(neigh_argv, check=False), run(["ip", "-j", "addr"], check=False)
    )
    logger.debug("Addresses considered in use: %s", sorted(used))

    auto_local, auto_peer = find_ip_pair(start, used)
    local = local or auto_local
    peer = peer or auto_peer

    logger.info("Local (this host) IP: %s", local)
    logger.info("Randnet (console) IP: %s", peer)
    logger.info(
        "These come from the ARP cache and can move between sessions. "
        "Set local_ip/peer_ip in the config to pin them."
    )
    return local, peer


def default_interface():

    payload = run(["ip", "-j", "route"], check=False)
    _, iface = parse_default_route(payload)
    if not iface:
        _, iface = parse_default_route(run(["ip", "route", "show", "default"],
                                           check=False))
    return iface


def is_loopback(address):
    return bool(address) and address.startswith("127.")


def pick_host_address(addr_payload, iface=None):

    try:
        links = json.loads(addr_payload)
    except (ValueError, TypeError):
        return None

    candidates = []
    for link in links or []:
        name = link.get("ifname")
        flags = link.get("flags") or []
        if name == "lo" or "LOOPBACK" in flags:
            continue
        for info in link.get("addr_info", []):
            if info.get("family") != "inet" or not info.get("local"):
                continue
            if info.get("scope") not in (None, "global"):
                continue
            if is_loopback(info["local"]):
                continue
            candidates.append((name, info["local"]))

    if iface:
        for name, address in candidates:
            if name == iface:
                return address

    return candidates[0][1] if candidates else None


def local_host_address():

    _, iface = parse_default_route(run(["ip", "-j", "route"], check=False))
    return pick_host_address(run(["ip", "-j", "addr"], check=False), iface)


def check_internet_connection(timeout=3):

    for host in INTERNET_CHECK_HOSTS:
        try:
            with socket.create_connection((host, 53), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def render_dns_redirect(hostnames, domain, iface, target_ip, dynamic=True):

    lines = [
        "# Generated by randnetpi3 %s every time the service starts." % VERSION,
        "# Do not edit: your changes will be overwritten.",
    ]

    if dynamic and iface:
        lines += [
            "#",
            "# Hostnames from the Randnet 64DD disk. interface-name makes",
            "# dnsmasq answer with whatever address %s currently has, resolved"
            % iface,
            "# at query time, so a DHCP lease change cannot make these stale.",
        ]
        for name in hostnames:
            lines.append("interface-name=%s,%s" % (name, iface))
    elif dynamic:
        lines.append("# (no default-route interface found, so no dynamic entries)")
    else:
        lines += [
            "#",
            "# The server is at a fixed address, so the wildcard below is used",
            "# on its own. No interface-name entries: they resolve from a local",
            "# interface and take precedence over the wildcard, which would send",
            "# these names back to this machine instead of to the server.",
        ]

    if domain and target_ip:
        lines += [
            "",
            "# Catch-all for Randnet subdomains not listed above. Static, but",
            "# rewritten on every service start.",
            "address=/%s/%s" % (domain, target_ip),
        ]

    lines += [
        "",
        "# dnsmasq's default for locally answered names, stated explicitly so a",
        "# cached reply cannot outlive an address change.",
        "local-ttl=0",
    ]
    return "\n".join(lines) + "\n"


HOSTNAME_RE = re.compile(
    r"\A(?=.{1,253}\Z)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?\Z"
)


def is_ipv4_literal(value):

    parts = (value or "").split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit() or not 0 <= int(part) <= 255:
            return False
        if len(part) > 1 and part[0] == "0":
            return False
    return True


def resolve_hostname_a(name, timeout=5.0):

    previous = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(name, None, family=socket.AF_INET,
                                   type=socket.SOCK_STREAM)
    except (socket.gaierror, OSError, UnicodeError):
        return None
    finally:
        socket.setdefaulttimeout(previous)

    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        return None
    if len(addresses) > 1:
        logger.info("%s has %d addresses (%s); using the first",
                    name, len(addresses), ", ".join(addresses))
    return addresses[0]


def previous_redirect_target(path, domain):

    if not path or not domain or not os.path.exists(path):
        return None
    prefix = "address=/%s/" % domain
    try:
        with open(path) as handle:
            for line in handle:
                line = line.strip()
                if line.startswith(prefix):
                    candidate = line[len(prefix):].strip()
                    if is_ipv4_literal(candidate):
                        return candidate
    except (IOError, OSError):
        return None
    return None


def resolve_randnet_target(cfg):

    setting = cfg.get("network", "randnet_redirect").strip()
    path = cfg.get("network", "dnsmasq_redirect_file").strip()
    domain = cfg.get("network", "randnet_domain").strip()
    previous = previous_redirect_target(path, domain)

    if setting.lower() in ("off", "no", "none", ""):
        return None, previous, "disabled"

    if setting.lower() == "host":
        address = local_host_address()
        if not address:
            return None, previous, "this machine's address could not be detected"
        return address, previous, "this machine"

    if is_ipv4_literal(setting):
        return setting, previous, "fixed address"

    if not HOSTNAME_RE.match(setting):
        logger.error(
            "network.randnet_redirect is neither an address, a hostname, nor "
            "'host' or 'off': %r", setting)
        return None, previous, "unusable setting"

    resolved = resolve_hostname_a(setting)
    if resolved:
        if is_loopback(resolved):
            logger.error(
                "%s resolves to %s, which the console cannot reach. Point the "
                "record at the address the bridge sees.", setting, resolved)
            return None, previous, "resolved to loopback"
        return resolved, previous, "%s resolved to %s" % (setting, resolved)

    if previous:
        logger.warning(
            "could not resolve %s; keeping the last known address %s. "
            "Restart randnetpi3 once name resolution works.", setting, previous)
        return previous, previous, "%s unresolved, reused %s" % (setting, previous)

    logger.error(
        "could not resolve %s and there is no previous address to fall back "
        "on, so the Randnet names will not be redirected.", setting)
    return None, previous, "%s unresolved" % setting


def pinned_randnet_server(cfg):

    setting = cfg.get("network", "randnet_redirect").strip()
    if not setting or setting.lower() in ("host", "off", "no", "none"):
        return None
    if is_loopback(setting):
        return None
    return setting


ETC_HOSTS = "/etc/hosts"
HOSTS_BEGIN = "# BEGIN randnetpi3 - managed, do not edit inside these markers"
HOSTS_END = "# END randnetpi3"


def render_etc_hosts_block(hostnames, address):
    if not address or not hostnames:
        return ""
    return "\n".join([
        HOSTS_BEGIN,
        "# Rewritten by randnetpi3 %s on every start, from the same resolved" % VERSION,
        "# address as the dnsmasq drop-in, so the two cannot disagree.",
        "#",
        "# Why this machine needs them at all: the dnsmasq drop-in answers the",
        "# console on its own interface but deliberately not loopback, so that it",
        "# can coexist with systemd-resolved. Processes here therefore resolve",
        "# through the system resolver, which knows nothing about these names -",
        "# and the browsing proxy has to resolve them to fetch pages on the",
        "# console's behalf.",
        "%s %s" % (address, " ".join(hostnames)),
        HOSTS_END,
        "",
    ])


def replace_managed_block(text, block):
    lines = text.splitlines(keepends=True)
    start = end = None
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == HOSTS_BEGIN and start is None:
            start = index
        elif stripped == HOSTS_END and start is not None:
            end = index
            break

    if start is not None and end is not None:
        kept = lines[:start] + lines[end + 1:]
    elif start is not None:
        logger.warning("%s has an unterminated randnetpi3 block; rewriting it",
                       ETC_HOSTS)
        kept = lines[:start]
    else:
        kept = list(lines)

    head = "".join(kept)
    if block:
        if head and not head.endswith("\n"):
            head += "\n"
        result = head + block
    else:
        result = head

    return result, result != text


def update_etc_hosts(cfg, address, dry_run=False, path=ETC_HOSTS):
    if not cfg.getboolean("network", "manage_etc_hosts"):
        return False

    hostnames = parse_host_list(cfg.get("network", "randnet_hostnames"))
    block = render_etc_hosts_block(hostnames, address)

    try:
        with open(path, "r") as handle:
            original = handle.read()
    except FileNotFoundError:
        original = ""
    except OSError as exc:
        logger.warning("Could not read %s (%s); leaving it alone", path, exc)
        return False

    updated, changed = replace_managed_block(original, block)
    if not changed:
        return False

    if dry_run:
        print("--- would update the managed block in %s ---" % path)
        print(block or "(removing the block)", end="")
        return True

    try:
        backup = path + ".randnetpi3.bak"
        if original and not os.path.exists(backup):
            write_file(backup, original, mode=0o644)
        temp = "%s.randnetpi3.%d.tmp" % (path, os.getpid())
        try:
            write_file(temp, updated, mode=0o644)
            try:
                os.replace(temp, path)
            except OSError as exc:
                if exc.errno not in (errno.EBUSY, errno.EXDEV):
                    raise
                logger.info("%s cannot be replaced by rename (%s); writing it "
                            "in place instead", path, exc.strerror)
                write_file(path, updated, mode=0o644)
                os.unlink(temp)
        except BaseException:
            if os.path.exists(temp):
                os.unlink(temp)
            raise
    except OSError as exc:
        logger.warning("Could not update %s (%s); the browsing proxy may not "
                       "resolve the Randnet names", path, exc)
        return False

    if block:
        logger.info("%s: Randnet names -> %s for this machine's own processes",
                    path, address)
    else:
        logger.info("%s: removed the managed block", path)
    return True


def configure_dns_redirect(cfg, dry_run=False):

    path = cfg.get("network", "dnsmasq_redirect_file").strip()
    setting = cfg.get("network", "randnet_redirect").strip()

    if not path:
        return None

    target_ip, previous_ip, note = resolve_randnet_target(cfg)

    if setting.lower() in ("off", "no", "none", ""):
        if os.path.exists(path) and not dry_run:
            os.remove(path)
            logger.info("Removed %s (randnet_redirect is off)", path)
        update_etc_hosts(cfg, None, dry_run=dry_run)
        logger.warning(
            "Randnet hostname redirect is off. Those names resolve upstream, "
            "where the domain now belongs to someone else."
        )
        return None, previous_ip

    if is_loopback(target_ip):
        logger.warning(
            "Ignoring loopback address %s for the Randnet redirect: the console "
            "cannot reach 127.0.0.0/8 on this machine.", target_ip
        )
        target_ip = None

    iface = default_interface()
    hostnames = parse_host_list(cfg.get("network", "randnet_hostnames"))
    domain = cfg.get("network", "randnet_domain").strip()

    remote = pinned_randnet_server(cfg)
    content = render_dns_redirect(hostnames, domain, iface, target_ip,
                                 dynamic=remote is None)

    if dry_run:
        print("--- would write %s (mode 644) ---" % path)
        print(content, end="")
        update_etc_hosts(cfg, target_ip, dry_run=True)
        return target_ip, previous_ip

    write_file(path, content, mode=0o644)
    update_etc_hosts(cfg, target_ip)
    logger.info(
        "Randnet names -> %s (%s; %d dynamic entries on %s, wildcard *.%s)",
        target_ip or "n/a", note,
        len(hostnames) if (remote is None and iface) else 0,
        iface or "n/a", domain,
    )
    if previous_ip and target_ip and previous_ip != target_ip:
        logger.info("The address moved from %s to %s since the last start",
                    previous_ip, target_ip)
    return target_ip, previous_ip


def _skip_dns_name(data, off):

    while off < len(data):
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += length + 1
    return off


def parse_dns_response(data, query_id):

    import struct

    if len(data) < 12 or struct.unpack(">H", data[:2])[0] != query_id:
        return None
    answers = struct.unpack(">H", data[6:8])[0]
    if not answers:
        return None

    off = _skip_dns_name(data, 12) + 4
    for _ in range(answers):
        off = _skip_dns_name(data, off)
        if off + 10 > len(data):
            return None
        rtype, _rclass, _ttl, rdlength = struct.unpack(">HHIH", data[off:off + 10])
        off += 10
        rdata = data[off:off + rdlength]
        off += rdlength
        if rtype == 1 and rdlength == 4:
            return ".".join(str(byte) for byte in rdata)
    return None


def dns_query_a(name, server="127.0.0.1", port=53, timeout=3.0):

    import random
    import struct

    query_id = random.randint(0, 0xFFFF)
    packet = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        encoded = label.encode("ascii", "ignore")
        packet += bytes([len(encoded)]) + encoded
    packet += b"\x00" + struct.pack(">HH", 1, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return None
    finally:
        sock.close()

    return parse_dns_response(data, query_id)


def restart_dnsmasq():

    result = subprocess.run(
        ["systemctl", "restart", "dnsmasq"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode == 0:
        logger.info("Restarted dnsmasq")
        return True

    logger.error(
        "dnsmasq FAILED to restart (rc=%d): %s",
        result.returncode,
        result.stderr.decode("utf-8", "replace").strip() or "no error output",
    )
    logger.error(
        "The console will have no working DNS. Diagnose with: "
        "%s --check-dns", os.path.abspath(sys.argv[0])
    )
    for line in describe_port_53():
        logger.error("port 53: %s", line)
    return False


def describe_port_53():

    lines = []
    for args in (["-lnup"], ["-lntp"]):
        output = run(["ss", "-H"] + args + ["sport", "=", ":53"], check=False)
        for line in output.splitlines():
            if line.strip():
                lines.append(" ".join(line.split()))
    return lines or ["nothing is listening on port 53"]


def parse_host_list(value):
    return [item.strip() for item in re.split(r"[,\s]+", value or "") if item.strip()]


def parse_addr_port(value):

    if ":" not in value:
        raise ValueError("expected ADDR:PORT, got %r" % value)
    addr, _, port = value.rpartition(":")
    if not addr or not port.isdigit():
        raise ValueError("expected ADDR:PORT, got %r" % value)
    return addr, port


def randnet_server_address(cfg, server_ip=None):
    if server_ip:
        return server_ip
    pinned = pinned_randnet_server(cfg)
    return pinned if is_ipv4_literal(pinned or "") else None


def tls_tunnel_wanted(cfg):
    return cfg.getboolean("network", "randnet_tls")


def tls_tunnel_host(cfg):
    explicit = cfg.get("network", "randnet_tls_host").strip()
    if explicit:
        return explicit
    setting = pinned_randnet_server(cfg)
    return setting or ""


def build_nat_rules(cfg, server_ip=None):

    iface = cfg.get("network", "ppp_interface").strip() or "ppp+"
    rules = []

    for host in parse_host_list(cfg.get("network", "dns_redirect")):
        for proto in ("udp", "tcp"):
            rules.append((
                "PREROUTING",
                ["-i", iface, "-p", proto, "-d", host, "--dport", "53",
                 "-j", "REDIRECT", "--to-ports", "53"],
            ))

    override_port = cfg.get("network", "proxy_target_port").strip()
    for entry in parse_host_list(cfg.get("network", "proxy_hosts")):
        addr, port = parse_addr_port(entry)
        rules.append((
            "PREROUTING",
            ["-i", iface, "-p", "tcp", "-d", addr, "--dport", port,
             "-j", "REDIRECT", "--to-ports", override_port or port],
        ))

    remote = randnet_server_address(cfg, server_ip)

    if tls_tunnel_wanted(cfg):
        tunnel_port = cfg.get("network", "randnet_tunnel_port").strip() or "8443"
        if remote:
            rules.append((
                "PREROUTING",
                ["-i", iface, "-p", "tcp", "-d", remote, "--dport", "80",
                 "-j", "REDIRECT", "--to-ports", tunnel_port],
            ))
            rules.append((
                "OUTPUT",
                ["-p", "tcp", "-d", remote, "--dport", "80",
                 "-j", "REDIRECT", "--to-ports", tunnel_port],
            ))
        else:
            logger.warning(
                "network.randnet_tls is on but the Randnet server's address is "
                "not known yet, so the tunnel rule cannot be installed and "
                "servlet traffic stays in the clear")

    if cfg.getboolean("network", "transparent_http"):
        target = cfg.get("network", "transparent_http_port").strip() or "8080"
        spec = ["-i", iface, "-p", "tcp", "--dport", "80"]
        if remote:
            spec += ["!", "-d", remote]
        spec += ["-m", "addrtype", "!", "--dst-type", "LOCAL",
                 "-j", "REDIRECT", "--to-ports", target]
        rules.append(("PREROUTING", spec))

    return rules


def build_obsolete_nat_rules(cfg, server_ip=None, previous_ip=None):

    iface = cfg.get("network", "ppp_interface").strip() or "ppp+"
    target = cfg.get("network", "transparent_http_port").strip() or "8080"
    remote = pinned_randnet_server(cfg)

    def shape(exclude=None):
        spec = ["-i", iface, "-p", "tcp", "--dport", "80"]
        if exclude:
            spec += ["!", "-d", exclude]
        return ("PREROUTING",
                spec + ["-m", "addrtype", "!", "--dst-type", "LOCAL",
                        "-j", "REDIRECT", "--to-ports", target])

    current = server_ip or (remote if is_ipv4_literal(remote or "") else None)

    tunnel_port = cfg.get("network", "randnet_tunnel_port").strip() or "8443"

    def tunnel_shape(address):
        return ("PREROUTING",
                ["-i", iface, "-p", "tcp", "-d", address, "--dport", "80",
                 "-j", "REDIRECT", "--to-ports", tunnel_port])

    def tunnel_output_shape(address):
        return ("OUTPUT",
                ["-p", "tcp", "-d", address, "--dport", "80",
                 "-j", "REDIRECT", "--to-ports", tunnel_port])

    tunnel_obsolete = []
    if not tls_tunnel_wanted(cfg):
        for address in (current, previous_ip):
            if address:
                tunnel_obsolete.append(tunnel_shape(address))
                tunnel_obsolete.append(tunnel_output_shape(address))
    elif previous_ip and previous_ip != current:
        tunnel_obsolete.append(tunnel_shape(previous_ip))
        tunnel_obsolete.append(tunnel_output_shape(previous_ip))

    obsolete = []

    if not cfg.getboolean("network", "transparent_http"):
        obsolete.append(shape())
        for address in (current, previous_ip):
            if address:
                obsolete.append(shape(address))
        return _unique_rules(obsolete + tunnel_obsolete)

    if current:
        obsolete.append(shape())
        if previous_ip and previous_ip != current:
            obsolete.append(shape(previous_ip))
    return _unique_rules(obsolete + tunnel_obsolete)


def _unique_rules(rules):
    seen = []
    for chain, spec in rules:
        if (chain, spec) not in seen:
            seen.append((chain, spec))
    return seen


def port_is_listening(port, host="127.0.0.1", timeout=1.0):

    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def iptables_argv(verb, chain, spec):
    return ["iptables", "-t", "nat", verb, chain] + list(spec)


class NatRules(object):

    def __init__(self, rules):
        self._rules = rules
        self._added = []

    def apply(self):
        if not self._rules:
            return
        if shutil.which("iptables") is None:
            logger.warning("iptables not found; skipping NAT redirects")
            return

        for chain, spec in self._rules:
            check = subprocess.run(
                iptables_argv("-C", chain, spec),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            if check.returncode == 0:
                logger.debug("NAT rule already present, adopting: %s",
                             " ".join(spec))
                self._added.append((chain, spec))
                continue
            add = subprocess.run(
                iptables_argv("-A", chain, spec),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                check=False,
            )
            if add.returncode != 0:
                logger.warning(
                    "Could not add NAT rule (%s): %s",
                    add.stderr.decode("utf-8", "replace").strip(),
                    " ".join(spec),
                )
                continue
            self._added.append((chain, spec))
            logger.info("NAT redirect added: %s", " ".join(spec))

    def purge(self, rules):

        if not rules or shutil.which("iptables") is None:
            return
        for chain, spec in rules:
            result = subprocess.run(
                iptables_argv("-D", chain, spec),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
            if result.returncode == 0:
                logger.info("Removed obsolete NAT rule: %s", " ".join(spec))

    def remove(self):
        while self._added:
            chain, spec = self._added.pop()
            subprocess.run(
                iptables_argv("-D", chain, spec),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            logger.info("NAT redirect removed: %s", " ".join(spec))



def render_peers(cfg, device, speed, local_ip, peer_ip, debug=False):

    ms_dns = cfg.get("ppp", "ms_dns").strip() or local_ip

    lines = [
        "# Generated by randnetpi3 %s - regenerated on every start" % VERSION,
        device,
        str(speed),
        "%s:%s" % (local_ip, peer_ip),
        "nopcomp",
        "noaccomp",
        "require-chap",
        "name %s" % cfg.get("ppp", "chap_name"),
        "ms-dns %s" % ms_dns,
        "proxyarp",
        "ktune",
        "noccp",
    ]

    if debug:
        lines.append("debug")

    record_file = cfg.get("ppp", "record_file").strip()
    if record_file:
        lines.append("record %s" % record_file)

    log_file = cfg.get("ppp", "log_file").strip()
    if log_file:
        lines.append("logfile %s" % log_file)

    for extra in cfg.get("ppp", "extra_options").splitlines():
        extra = extra.strip()
        if extra:
            lines.append(extra)

    return "\n".join(lines) + "\n"

SAFE_SECRET_CHARS = re.compile(r"\A[A-Za-z0-9@._+:/-]+\Z")


def quote_secret(secret):

    if secret and SAFE_SECRET_CHARS.match(secret):
        return secret
    return '"%s"' % secret.replace("\\", "\\\\").replace('"', '\\"')


def resolve_chap_secret(cfg):

    encoded = cfg.get("ppp", "chap_secret_b64", fallback="").strip()
    if encoded:
        try:
            return base64.b64decode(encoded, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise SystemExit("ppp.chap_secret_b64 is not valid base64: %s" % exc)
    return cfg.get("ppp", "chap_secret")


def merge_chap_secrets(existing, client, server, secret, addresses="*"):

    wanted = "%s\t%s\t%s\t%s" % (client, server, quote_secret(secret), addresses)

    kept = []
    for line in (existing or "").splitlines():
        if line.strip() == CHAP_MARKER:
            continue
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            fields = stripped.split()
            if len(fields) >= 2 and fields[0] == client and fields[1] == server:
                continue
        kept.append(line)

    while kept and not kept[-1].strip():
        kept.pop()

    kept.append(CHAP_MARKER)
    kept.append(wanted)
    return "\n".join(kept) + "\n"


def write_file(path, content, mode=0o644, dry_run=False):
    if dry_run:
        print("--- would write %s (mode %o) ---" % (path, mode))
        print(content, end="" if content.endswith("\n") else "\n")
        return

    directory = os.path.dirname(path)
    if directory and not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(path, flags, mode)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, mode)
    logger.info("Wrote %s (mode %o)", path, mode)


def warn_about_stale_ppp_options():

    try:
        with open(PPP_OPTIONS, "r") as handle:
            content = handle.read()
    except (IOError, OSError):
        return

    interesting = [
        line.strip()
        for line in content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not interesting:
        return

    logger.warning(
        "%s is not empty and pppd reads it in addition to the peers file. "
        "Leftovers from the old script (%s) should be removed.",
        PPP_OPTIONS,
        ", ".join(interesting[:6]),
    )
    if any(line.startswith("record ") for line in interesting):
        logger.warning(
            "%s contains a `record` directive: that capture file grows without "
            "bound and pppd will fail to start if its directory is missing.",
            PPP_OPTIONS,
        )


def configure_ppp(cfg, device, speed, dry_run=False, debug=False):

    local_ip, peer_ip = discover_addresses(cfg)

    peers_name = cfg.get("ppp", "peers_name")
    peers_path = os.path.join(PEERS_DIR, peers_name)
    peers_content = render_peers(cfg, device, speed, local_ip, peer_ip, debug=debug)
    write_file(peers_path, peers_content, mode=0o644, dry_run=dry_run)

    try:
        with open(CHAP_SECRETS, "r") as handle:
            existing = handle.read()
    except (IOError, OSError):
        existing = ""

    secrets_content = merge_chap_secrets(
        existing,
        cfg.get("ppp", "chap_client"),
        cfg.get("ppp", "chap_name"),
        resolve_chap_secret(cfg),
    )
    write_file(CHAP_SECRETS, secrets_content, mode=0o600, dry_run=dry_run)

    if not dry_run:
        warn_about_stale_ppp_options()
        check_pppd_output_paths(cfg)

    return peers_path, local_ip, peer_ip


def check_pppd_output_paths(cfg):

    for key, option in (("record_file", "record"), ("log_file", "logfile")):
        path = cfg.get("ppp", key).strip()
        if not path:
            continue
        directory = os.path.dirname(os.path.abspath(path)) or "/"
        if not os.path.isdir(directory):
            raise SystemExit(
                "ppp.%s is set to %s but %s does not exist. pppd would fail to "
                "start with `%s`. Create the directory or clear the setting."
                % (key, path, directory, option)
            )


def pppd_argv(cfg):
    pppd = cfg.get("ppp", "pppd").strip()
    if not pppd:
        pppd = shutil.which("pppd") or "/usr/sbin/pppd"
    return [pppd, "call", cfg.get("ppp", "peers_name"), "nodetach"]



def decode_dtmf(raw):

    if not raw:
        return None
    try:
        char = raw.decode("ascii").upper()
    except (UnicodeDecodeError, AttributeError):
        return None
    return char if char in DTMF_CHARS else None


class TonePacer(object):

    CHUNK = 1000
    RATE = 8000

    def __init__(self, data, clock=time.monotonic):
        self._data = data
        self._clock = clock
        self._interval = float(self.CHUNK) / self.RATE
        self._offset = 0
        self._deadline = None

    def start(self):
        self._offset = 0
        self._deadline = self._clock()

    def due(self):
        return self._deadline is not None and self._clock() >= self._deadline

    def next_chunk(self):
        chunk = self._data[self._offset : self._offset + self.CHUNK]
        self._offset += self.CHUNK
        if self._offset >= len(self._data):
            self._offset = 0
        now = self._clock()
        self._deadline += self._interval
        if self._deadline < now:
            self._deadline = now + self._interval
        return chunk


class Modem(object):
    VALID_RESPONSES = (b"OK", b"ERROR", b"CONNECT", b"VCON")

    def __init__(self, device, speed, dial_tone_wav=None):
        self.device = device
        self.speed = int(speed)
        self._serial = None
        self._sending_tone = False
        self._pacer = TonePacer(dial_tone_wav) if dial_tone_wav else None


    @property
    def is_open(self):
        return self._serial is not None

    def connect(self):
        import serial

        if self._serial:
            self.disconnect()
        logger.info("Opening serial interface to %s at %d", self.device, self.speed)
        self._serial = serial.Serial(self.device, self.speed, timeout=0)

    def disconnect(self, keep_dtr=True):
        if not self._serial:
            return
        if keep_dtr:
            self._clear_hupcl()
        try:
            self._serial.close()
        except Exception:
            logger.exception("Error closing serial port")
        self._serial = None
        logger.info("Serial interface closed")

    def _clear_hupcl(self):

        try:
            fd = self._serial.fileno()
            attrs = termios.tcgetattr(fd)
            attrs[2] &= ~termios.HUPCL
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except Exception as exc:
            logger.debug("Could not clear HUPCL: %s", exc)


    def send_command(self, command, timeout=60, ignore_responses=()):
        if self._serial is None:
            raise IOError("not connected")

        expected = [
            resp for resp in self.VALID_RESPONSES if resp not in ignore_responses
        ]

        if isinstance(command, str):
            command = command.encode("ascii")
        self._serial.write(command + b"\r\n")
        logger.debug("-> %s", command.decode("ascii", "replace"))

        deadline = time.monotonic() + timeout
        line = b""
        while True:
            chunk = self._serial.readline().strip()
            if not chunk:
                if time.monotonic() > deadline:
                    raise IOError(
                        "timed out waiting for a response to %s"
                        % command.decode("ascii", "replace")
                    )
                time.sleep(0.002)
                continue

            line += chunk
            for resp in expected:
                if resp in line:
                    logger.debug("<- %s", line.decode("ascii", "replace"))
                    return resp

    def send_escape(self):
        time.sleep(1.0)
        self._serial.write(b"+++")
        time.sleep(1.0)

    def reset(self):
        self.send_command(b"ATZ0")  
        self.send_command(b"ATE0")  

    @property
    def sending_tone(self):
        return self._sending_tone

    def start_dial_tone(self):
        if not self._pacer:
            return
        self.reset()
        self.send_command(b"AT+FCLASS=8")  
        self.send_command(b"AT+VLS=1")  
        self.send_command(b"AT+VSM=1,8000")  
        self.send_command(b"AT+VTX")  
        self._pacer.start()
        self._sending_tone = True
        logger.info("Listening for a call")

    def stop_dial_tone(self):
        if not self._sending_tone:
            return
        self._serial.write(b"\x00\x10\x03\r\n")  
        self.send_escape()
        self.send_command(b"ATH0")  
        self.reset()
        self._sending_tone = False

    def pump_dial_tone(self):

        if not self._sending_tone or not self._pacer.due():
            return False
        self._serial.write(self._pacer.next_chunk())
        return True

    def read_byte(self):
        return self._serial.read(1)

    def answer(self):
        self.reset()
        self.send_command(b"ATA", ignore_responses=(b"OK",))
        logger.info("Call answered")

    def hang_up(self):
        try:
            self.send_escape()
            self.send_command(b"ATH0", timeout=5)
        except Exception as exc:
            logger.debug("Could not hang up cleanly: %s", exc)


def read_dial_tone(path):
    with open(path, "rb") as handle:
        data = handle.read()
    return data[44:]


def detect_device(cfg):

    configured = cfg.get("modem", "device").strip()
    if configured:
        if not configured.startswith("/"):
            configured = "/dev/" + configured
        logger.info("Using configured device %s", configured)
        return configured

    try:
        import serial.tools.list_ports
    except ImportError:
        logger.warning("pyserial is not installed, so no device can be detected")
        return None

    ports = list(serial.tools.list_ports.comports())
    if not ports:
        return None

    usb_id = cfg.get("modem", "usb_id").strip().lower()
    if usb_id:
        try:
            want_vid, want_pid = (int(part, 16) for part in usb_id.split(":", 1))
        except ValueError:
            raise SystemExit("usb_id must look like 0572:1329, got %r" % usb_id)
        for port in ports:
            if port.vid == want_vid and port.pid == want_pid:
                logger.info("Matched %s by USB id %s", port.device, usb_id)
                return port.device
        logger.warning("No serial device matches USB id %s", usb_id)
        return None

    for port in sorted(ports, key=lambda p: p.device):
        if "ttyACM" in port.device:
            logger.info(
                "Auto-detected %s (%s)", port.device, port.description or "no description"
            )
            return port.device

    port = sorted(ports, key=lambda p: p.device)[0]
    logger.info("Falling back to %s (%s)", port.device, port.description or "?")
    return port.device


class GracefulKiller(object):
    def __init__(self):
        self.kill_now = False
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, signum, _frame):
        logger.warning("Received signal %s, shutting down", signum)
        self.kill_now = True


def wait_for_prerequisites(cfg, killer):

    while not killer.kill_now:
        connected = check_internet_connection()
        device = detect_device(cfg)
        if connected and device:
            logger.info("Internet is up and modem found at %s", device)
            return device
        if not connected:
            logger.warning("No internet connection yet, waiting")
        if not device:
            logger.warning("No modem device found, waiting")
        time.sleep(5)
    return None


def serve(cfg, args, killer, target=None):
    device = wait_for_prerequisites(cfg, killer)
    if device is None:
        return 0

    speed = cfg.getint("modem", "speed")

    dial_tone_data = None
    if cfg.getboolean("modem", "dial_tone") and not args.disable_dial_tone:
        wav = cfg.get("modem", "dial_tone_wav").strip()
        if not wav:
            wav = os.path.join(
                os.path.dirname(os.path.abspath(os.path.realpath(__file__))),
                "dial-tone.wav",
            )
        if not os.path.exists(wav):
            raise SystemExit(
                "dial tone file not found: %s\n"
                "Copy dial-tone.wav next to this script, point dial_tone_wav at "
                "it, or start with --disable-dial-tone." % wav
            )
        dial_tone_data = read_dial_tone(wav)
        logger.info("Loaded %d bytes of dial tone from %s", len(dial_tone_data), wav)

    _, local_ip, peer_ip = configure_ppp(
        cfg, device, speed, dry_run=False, debug=args.pppd_debug
    )

    server_ip, previous_ip = target or (None, None)
    nat = NatRules(build_nat_rules(cfg, server_ip))
    nat.purge(build_obsolete_nat_rules(cfg, server_ip, previous_ip))
    nat.apply()

    if cfg.getboolean("network", "transparent_http"):
        target = cfg.get("network", "transparent_http_port").strip() or "8080"
        if port_is_listening(target):
            logger.info(
                "Transparent HTTP on: the console's port 80 goes to the local "
                "proxy on %s, which terminates TLS for it", target)
        else:
            logger.warning(
                "Transparent HTTP is on but nothing is listening on port %s. "
                "The console's web requests will be refused until you start "
                "the proxy (randnet_server.py serve). Set "
                "network.transparent_http = no to pass port 80 straight "
                "through instead.", target)

    argv = pppd_argv(cfg)
    logger.info("pppd command: %s", " ".join(argv))

    answer_delay = cfg.getfloat("modem", "answer_delay")
    post_answer_delay = cfg.getfloat("modem", "post_answer_delay")
    reconnect_delay = cfg.getfloat("modem", "reconnect_delay")

    modem = Modem(device, speed, dial_tone_data)
    pppd = None

    try:
        modem.connect()
        modem.start_dial_tone()

        mode = "LISTENING"
        digit_heard_at = None

        while not killer.kill_now:
            if mode == "LISTENING":
                sent = modem.pump_dial_tone()
                raw = modem.read_byte()
                if not raw:
                    if not sent:
                        time.sleep(0.005)
                    continue

                if raw[0] != DLE:
                    continue

                digit = decode_dtmf(modem.read_byte())
                if digit is None:
                    continue

                logger.info("Heard DTMF digit %s, taking the line off dial tone", digit)
                modem.stop_dial_tone()
                digit_heard_at = time.monotonic()
                mode = "ANSWERING"

            elif mode == "ANSWERING":
                remaining = answer_delay - (time.monotonic() - digit_heard_at)
                if remaining > 0:
                    time.sleep(min(0.1, remaining))
                    continue

                modem.answer()
                time.sleep(post_answer_delay)

                pppd = subprocess.Popen(argv)
                logger.info("Started pppd (pid %d)", pppd.pid)
                time.sleep(1.0)
                if pppd.poll() is not None:
                    logger.error("pppd exited immediately (rc=%s)", pppd.returncode)
                    pppd = None
                    modem.disconnect()
                    time.sleep(reconnect_delay)
                    modem.connect()
                    modem.start_dial_tone()
                    mode = "LISTENING"
                    continue

                modem.disconnect()
                logger.info("Connected; console should be at %s", peer_ip)
                mode = "CONNECTED"

            elif mode == "CONNECTED":
                if pppd.poll() is None:
                    time.sleep(0.25)
                    continue

                logger.info("pppd exited (rc=%s), going back to listening", pppd.returncode)
                pppd = None
                time.sleep(reconnect_delay)
                modem.connect()
                modem.start_dial_tone()
                mode = "LISTENING"

    finally:
        if pppd is not None and pppd.poll() is None:
            logger.info("Terminating pppd (pid %d)", pppd.pid)
            pppd.terminate()
            try:
                pppd.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pppd.kill()
        if modem.is_open:
            modem.hang_up()
            modem.disconnect(keep_dtr=False)
        nat.remove()

    return 0


def do_dry_run(cfg, args):
    device = detect_device(cfg) or "/dev/ttyACM0"
    speed = cfg.getint("modem", "speed")

    print("# device: %s @ %d" % (device, speed))
    print()

    try:
        _, local_ip, peer_ip = configure_ppp(
            cfg, device, speed, dry_run=True, debug=args.pppd_debug
        )
    except (RuntimeError, subprocess.CalledProcessError, FileNotFoundError) as exc:
        print("# address discovery failed (%s); using placeholders" % exc)
        local_ip, peer_ip = "192.168.1.99", "192.168.1.98"
        print()
        print("--- would write %s (mode 644) ---" % os.path.join(PEERS_DIR, cfg.get("ppp", "peers_name")))
        print(render_peers(cfg, device, speed, local_ip, peer_ip, debug=args.pppd_debug), end="")
        print()
        print("--- would write %s (mode 600) ---" % CHAP_SECRETS)
        print(
            merge_chap_secrets(
                "",
                cfg.get("ppp", "chap_client"),
                cfg.get("ppp", "chap_name"),
                resolve_chap_secret(cfg),
            ),
            end="",
        )

    print()
    configure_dns_redirect(cfg, dry_run=True)

    print()
    print("--- pppd command ---")
    print(" ".join(pppd_argv(cfg)))

    print()
    print("--- NAT rules ---")
    rules = build_nat_rules(cfg)
    if not rules:
        print("(none configured)")
    for chain, spec in rules:
        print(" ".join(iptables_argv("-A", chain, spec)))

    return 0


def service_state(name):
    output = run(["systemctl", "is-active", name], check=False).strip()
    return output or "unknown"


def diagnose_resolver():

    print("\nNothing resolved. Diagnosing.\n")

    dnsmasq_state = service_state("dnsmasq")
    resolved_state = service_state("systemd-resolved")
    print("  dnsmasq service          %s" % dnsmasq_state)
    print("  systemd-resolved         %s" % resolved_state)

    print("\n  Listening on port 53:")
    for line in describe_port_53():
        print("    %s" % line)

    print("\n  dnsmasq config test:")
    helper = "/usr/share/dnsmasq/systemd-helper"
    if os.path.exists(helper):
        result = subprocess.run(
            [helper, "checkconfig"], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
    else:
        result = subprocess.run(
            ["dnsmasq", "--test"], stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, check=False,
        )
    output = result.stdout.decode("utf-8", "replace").strip()
    print("    %s" % (output or "(no output)"))
    print("    exit status %d" % result.returncode)

    print("\n  Last dnsmasq log lines:")
    log = run(["journalctl", "-u", "dnsmasq", "-n", "20", "--no-pager"], check=False)
    for line in log.splitlines()[-8:] or ["(nothing)"]:
        print("    %s" % line.strip())

    print("\n  Most likely cause:")
    for message in explain_resolver_failure(
        dnsmasq_state, resolved_state, describe_port_53(), log
    ):
        print("    %s" % message)
    print()


DNSMASQ_ERRORS = (
    (
        "cannot set --bind-interfaces and --bind-dynamic",
        [
            "dnsmasq refuses to start because both bind-interfaces and",
            "bind-dynamic are set, and they contradict each other.",
            "",
            "Find which file has the stray option:",
            "  grep -rn 'bind-interfaces\\|bind-dynamic' /etc/dnsmasq.conf "
            "/etc/dnsmasq.d/",
            "",
            "Keep bind-dynamic and remove bind-interfaces: only the dynamic form",
            "picks up ppp0 when a call comes in. Then:",
            "  sudo systemctl restart dnsmasq randnetpi3",
        ],
    ),
    (
        "failed to create listening socket for port 53",
        [
            "dnsmasq could not bind port 53, so something else holds it.",
            "Stop dnsmasq binding loopback by adding to",
            "/etc/dnsmasq.d/randnetpi3.conf:",
            "  bind-dynamic",
            "  except-interface=lo",
            "then: sudo systemctl restart dnsmasq randnetpi3",
            "It then binds only the LAN interface and ppp0, leaving 127.0.0.53",
            "to systemd-resolved. /etc/resolv.conf is untouched.",
        ],
    ),
    (
        "unknown option",
        [
            "dnsmasq rejected an option in its configuration.",
            "The offending line is named in the log above. Check the files in",
            "/etc/dnsmasq.d/ and validate with:  dnsmasq --test",
        ],
    ),
    (
        "bad option",
        [
            "dnsmasq rejected a malformed option.",
            "The log above names the file and line. Validate with: dnsmasq --test",
        ],
    ),
    (
        "no such interface",
        [
            "dnsmasq was told to use an interface that does not exist.",
            "If a config file names a fixed interface, that name may have",
            "changed (ens33 to ens160, for example). randnetpi3 regenerates its",
            "own drop-in on every start; check any others in /etc/dnsmasq.d/.",
        ],
    ),
)


def dnsmasq_error_from_log(log_text):

    if not log_text:
        return None

    for line in reversed(log_text.splitlines()):
        lowered = line.lower()
        for signature, advice in DNSMASQ_ERRORS:
            if signature.lower() in lowered:
                return ['dnsmasq said: "%s"' % signature, ""] + advice
    return None


def dnsmasq_binds_dynamically(paths=("/etc/dnsmasq.conf", "/etc/dnsmasq.d")):

    files = []
    for path in paths:
        if os.path.isdir(path):
            files += [
                os.path.join(path, name)
                for name in sorted(os.listdir(path))
                if name.endswith(".conf")
            ]
        elif os.path.isfile(path):
            files.append(path)

    for path in files:
        try:
            with open(path) as handle:
                for line in handle:
                    if line.strip() in ("bind-dynamic", "bind-interfaces"):
                        return True
        except (IOError, OSError):
            continue
    return False


def explain_resolver_failure(dnsmasq_state, resolved_state, port_53_lines,
                            log_text=None):

    from_log = dnsmasq_error_from_log(log_text)
    if from_log:
        return from_log

    joined = " ".join(port_53_lines).lower()
    nothing_bound = "nothing is listening" in joined
    others = sorted({
        name for name in ("systemd-resolve", "named", "bind9", "unbound",
                          "connmand", "dnscrypt-proxy", "stubby", "python3")
        if name in joined
    })

    if not nothing_bound and others:
        advice = [
            "port 53 is already held by: %s" % ", ".join(others),
            "dnsmasq is trying to bind 0.0.0.0:53, which overlaps that, so it",
            "cannot start. The fix is to stop dnsmasq binding loopback:",
            "",
            "  add these two lines to /etc/dnsmasq.d/randnetpi3.conf",
            "    bind-dynamic",
            "    except-interface=lo",
            "  then: sudo systemctl restart dnsmasq randnetpi3",
            "",
            "dnsmasq then binds only the LAN interface and ppp0, leaving",
            "127.0.0.53 to systemd-resolved. Nothing else has to change: the",
            "machine keeps its own resolver and /etc/resolv.conf is untouched.",
        ]
        if not dnsmasq_binds_dynamically():
            advice.append(
                "Your base drop-in does not have these yet, which is why this "
                "is happening."
            )
        return advice

    if nothing_bound and dnsmasq_state in ("inactive", "failed", "unknown"):
        return [
            "dnsmasq is %s and nothing is bound to port 53." % dnsmasq_state,
            "Read the config test and log lines above: it is failing on its",
            "own account rather than losing a fight for the port.",
        ]

    if dnsmasq_state == "active":
        return [
            "dnsmasq is running but not answering for these names.",
            "Most often it is not reading /etc/dnsmasq.d at all. Debian only",
            "picks that directory up through CONFIG_DIR, so check:",
            "  grep -n CONFIG_DIR /etc/default/dnsmasq",
            "and confirm dnsmasq was started via systemd, not by hand.",
        ]

    return [
        "dnsmasq is %s. Nothing conclusive from the evidence above;" % dnsmasq_state,
        "the config test and log lines are the place to look.",
    ]


def do_check_dns(cfg):

    def line(label, value):
        print("  %-26s %s" % (label, value))

    print("\nThis machine")
    iface = default_interface()
    line("default route interface", iface or "NONE FOUND")
    detected = local_host_address()
    line("address on it", detected or "NONE FOUND")

    print("\nConfiguration")
    setting = cfg.get("network", "randnet_redirect").strip()
    line("network.randnet_redirect", setting)
    if setting.lower() in ("off", "no", "none", ""):
        target = None
        line("resolved target", "none (redirect disabled)")
    elif setting.lower() == "host":
        target = detected
        line("resolved target", "%s  (re-detected at every start)"
             % (target or "NONE - wildcard will be skipped"))
    else:
        target = setting
        line("resolved target", "%s  (fixed in the config)" % target)
    if is_loopback(target):
        line("WARNING", "that is loopback and will be discarded")
        target = None

    path = cfg.get("network", "dnsmasq_redirect_file").strip()
    exists = os.path.exists(path)
    line("redirect drop-in", "%s  (%s)" % (path, "present" if exists else "ABSENT"))

    print("\nDrop-in contents")
    if exists:
        with open(path) as handle:
            body = [
                l for l in handle.read().splitlines()
                if l.strip() and not l.startswith("#")
            ]
        if not body:
            print("  (empty)")
        for entry in body:
            note = ""
            if entry.startswith("interface-name="):
                note = "  <- resolved live from the interface, no IP stored here"
            elif entry.startswith("address="):
                note = "  <- static wildcard, rewritten at each service start"
            print("  %s%s" % (entry, note))
    else:
        print("  Not written yet. It is created when randnetpi3 starts.")
        print("  Start the service, or run without --check-dns.")

    hostnames = parse_host_list(cfg.get("network", "randnet_hostnames"))
    domain = cfg.get("network", "randnet_domain").strip()

    candidates = ["127.0.0.1"]
    if detected and detected not in candidates:
        candidates.append(detected)

    probe_name = hostnames[0] if hostnames else domain
    server = None
    for candidate in candidates:
        if probe_name and dns_query_a(probe_name, server=candidate):
            server = candidate
            break

    if server is None:
        print("\nWhat the local resolver answers")
        for candidate in candidates:
            print("  tried %s:53 -> no answer" % candidate)
        diagnose_resolver()
        return 1

    print("\nWhat the local resolver answers (queried at %s:53)" % server)
    if server != "127.0.0.1":
        print("  (not on loopback: dnsmasq is bound per-interface so that")
        print("   systemd-resolved can keep 127.0.0.53. This is expected.)")

    probes = [(name, "listed") for name in hostnames]
    if domain:
        probes.append(("not-a-real-host." + domain, "wildcard only"))

    any_answer = False
    mismatch = False
    for name, kind in probes:
        got = dns_query_a(name, server=server)
        any_answer = any_answer or bool(got)
        flag = ""
        if got and target and got != target:
            flag = "  MISMATCH, expected %s" % target
            mismatch = True
        elif not got:
            flag = "  no answer"
        print("  %-30s -> %-15s %-14s%s" % (name, got or "-", kind, flag))

    if not any_answer:
        diagnose_resolver()
        return 1

    print()
    if mismatch:
        print("Some answers do not match the target. If dnsmasq was not")
        print("restarted after the last change, restart it and re-check.")
        return 1
    print("Consistent: the resolver agrees with the configuration.")
    return 0


def do_self_test():

    failures = []

    def check(name, got, want):
        if got == want:
            print("  ok   %s" % name)
        else:
            print("  FAIL %s\n         got:  %r\n         want: %r" % (name, got, want))
            failures.append(name)

    print("route parsing")
    route_json = json.dumps(
        [
            {"dst": "192.168.1.0/24", "dev": "eth0"},
            {"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"},
        ]
    )
    check("json default route", parse_default_route(route_json), ("192.168.1.1", "eth0"))
    check(
        "text default route",
        parse_default_route("default via 10.0.0.1 dev enp3s0 proto dhcp metric 100"),
        ("10.0.0.1", "enp3s0"),
    )
    check("no default route", parse_default_route("[]"), (None, None))

    print("neighbour parsing")
    neigh = json.dumps(
        [
            {"dst": "192.168.1.1", "state": ["REACHABLE"]},
            {"dst": "192.168.1.99", "state": ["FAILED"]},
            {"dst": "192.168.1.98", "state": ["INCOMPLETE"]},
            {"dst": "192.168.1.97", "state": ["STALE"]},
        ]
    )
    addrs = json.dumps(
        [{"ifname": "eth0", "addr_info": [{"family": "inet", "local": "192.168.1.50"}]}]
    )
    check(
        "stale entries ignored",
        parse_used_addresses(neigh, addrs),
        {"192.168.1.1", "192.168.1.97", "192.168.1.50"},
    )

    print("address allocation")
    check(
        "walks down from .100",
        find_ip_pair("192.168.1.100", set()),
        ("192.168.1.99", "192.168.1.98"),
    )
    check(
        "skips occupied",
        find_ip_pair("192.168.1.100", {"192.168.1.99", "192.168.1.97"}),
        ("192.168.1.98", "192.168.1.96"),
    )
    try:
        find_ip_pair("192.168.1.2", set())
        check("exhaustion raises", "no exception", "RuntimeError")
    except RuntimeError:
        print("  ok   exhaustion raises")

    print("chap-secrets merge")
    check(
        "fresh file",
        merge_chap_secrets("", "*", "Randnet", "K1QU0K@N"),
        CHAP_MARKER + "\n*\tRandnet\tK1QU0K@N\t*\n",
    )
    check(
        "preserves unrelated entries",
        merge_chap_secrets(
            "# comment\nfoo\tbar\tbaz\t*\n*\tRandnet\tOLDKEY\t*\n",
            "*",
            "Randnet",
            "K1QU0K@N",
        ),
        "# comment\nfoo\tbar\tbaz\t*\n"
        + CHAP_MARKER
        + "\n*\tRandnet\tK1QU0K@N\t*\n",
    )
    check(
        "idempotent",
        merge_chap_secrets(
            merge_chap_secrets("", "*", "Randnet", "K1QU0K@N"), "*", "Randnet", "K1QU0K@N"
        ),
        merge_chap_secrets("", "*", "Randnet", "K1QU0K@N"),
    )
    print("secret quoting for chap-secrets")
    check("factory key stays bare", quote_secret("K1QU0K@N"), "K1QU0K@N")
    check("space quoted", quote_secret("two words"), '"two words"')
    check("hash quoted", quote_secret("PC#4x!9q"), '"PC#4x!9q"')
    check("semicolon quoted", quote_secret("a;b"), '"a;b"')
    check("single quote quoted", quote_secret("it's"), '"it\'s"')
    check("percent quoted", quote_secret("50%pow"), '"50%pow"')
    check("dollar quoted", quote_secret("pa$$"), '"pa$$"')
    check("double quote escaped", quote_secret('qu"te'), '"qu\\"te"')
    check("backslash escaped", quote_secret("back\\slash"), '"back\\\\slash"')
    check("tab quoted", quote_secret("a\tb"), '"a\tb"')
    check("empty quoted", quote_secret(""), '""')
    check("digits and dots bare", quote_secret("1.2.3-4_5+6:7/8"), "1.2.3-4_5+6:7/8")

    print("secret round-trip through the ini file")
    hard_secrets = [
        "K1QU0K@N", "PC#4x!9q", "50%pow3r", "a;b<c>d", 'qu"te', "back\\slash",
        "it's", "pa$$w0rd", "sp ace", "equal=s", "brack[et]", "colon:x",
    ]
    for secret in hard_secrets:
        text = (
            "[ppp]\nchap_secret = %s\nchap_secret_b64 =\n" % secret
        )
        probe = configparser.ConfigParser(interpolation=None)
        probe.read_dict(DEFAULTS)
        probe.read_string(text)
        check("ini round-trip %r" % secret, resolve_chap_secret(probe), secret)

    print("base64 fallback for whitespace-edged secrets")
    for secret in (" lead", "trail ", "  both  ", "\ttab-edge\t"):
        probe = configparser.ConfigParser(interpolation=None)
        probe.read_dict(DEFAULTS)
        probe.read_string(
            "[ppp]\nchap_secret =\nchap_secret_b64 = %s\n"
            % base64.b64encode(secret.encode()).decode()
        )
        check("b64 round-trip %r" % secret, resolve_chap_secret(probe), secret)
    probe = configparser.ConfigParser(interpolation=None)
    probe.read_dict(DEFAULTS)
    probe.read_string("[ppp]\nchap_secret = ignored\nchap_secret_b64 = %s\n"
                      % base64.b64encode(b"winner").decode())
    check("b64 takes precedence", resolve_chap_secret(probe), "winner")

    print("peers rendering")
    cfg = load_config()
    peers = render_peers(cfg, "/dev/ttyACM0", 57600, "192.168.1.99", "192.168.1.98")
    for needed in (
        "/dev/ttyACM0",
        "57600",
        "192.168.1.99:192.168.1.98",
        "nopcomp",
        "noaccomp",
        "require-chap",
        "name Randnet",
        "ms-dns 192.168.1.99",
        "proxyarp",
        "ktune",
        "noccp",
    ):
        check("peers contains %r" % needed, needed in peers.split("\n"), True)
    check("no debug by default", "debug" in peers.split("\n"), False)
    check(
        "no record by default",
        any(line.startswith("record ") for line in peers.split("\n")),
        False,
    )
    cfg_rec = load_config()
    cfg_rec.set("ppp", "record_file", "/var/log/randnetpi/ppp.bin")
    cfg_rec.set("ppp", "log_file", "/var/log/randnetpi/pppd.log")
    cfg_rec.set("ppp", "extra_options", "lcp-echo-interval 0\nmtu 1500")
    rendered = render_peers(cfg_rec, "/dev/ttyACM0", 57600, "1.1.1.1", "1.1.1.2")
    check("record rendered", "record /var/log/randnetpi/ppp.bin" in rendered.split("\n"), True)
    check("logfile rendered", "logfile /var/log/randnetpi/pppd.log" in rendered.split("\n"), True)
    check("extra options rendered", "mtu 1500" in rendered.split("\n"), True)
    check(
        "debug when asked",
        "debug"
        in render_peers(
            cfg, "/dev/ttyACM0", 57600, "1.1.1.1", "1.1.1.2", debug=True
        ).split("\n"),
        True,
    )

    print("NAT rules")
    rules = build_nat_rules(cfg)
    specs = [" ".join(spec) for _chain, spec in rules]
    dns_specs = [s for s in specs if "--dport 53" in s]
    proxy_specs = [s for s in specs if "-d 172.16.10.4" in s]
    check("2 DNS hosts x 2 protocols", len(dns_specs), 4)
    check("2 proxy hosts", len(proxy_specs), 2)
    check(
        "DNS rule uses REDIRECT, no address needed",
        iptables_argv("-A", *rules[0]),
        [
            "iptables", "-t", "nat", "-A", "PREROUTING",
            "-i", "ppp+", "-p", "udp", "-d", "172.16.10.30",
            "--dport", "53", "-j", "REDIRECT", "--to-ports", "53",
        ],
    )
    check("no DNAT anywhere (no detected address to get wrong)",
          any("DNAT" in s for s in specs), False)
    check("primary proxy redirected on 8080",
          "-i ppp+ -p tcp -d 172.16.10.40 --dport 8080 -j REDIRECT --to-ports 8080"
          in specs, True)
    check("secondary proxy redirected on 8080",
          "-i ppp+ -p tcp -d 172.16.10.41 --dport 8080 -j REDIRECT --to-ports 8080"
          in specs, True)
    check("proxy enabled by default (browsing needs it)", len(proxy_specs), 2)

    override = load_config()
    override.set("network", "proxy_target_port", "9090")
    overridden = [spec for _c, spec in build_nat_rules(override)
                  if "-d" in spec and spec[spec.index("-d") + 1].startswith(
                      "172.16.10.4")]
    check("local port override honoured",
          [spec[-1] for spec in overridden], ["9090", "9090"])
    check("addr:port split", parse_addr_port("172.16.10.40:8080"),
          ("172.16.10.40", "8080"))

    print("transparent HTTP interception")
    transparent = [spec for _c, spec in build_nat_rules(cfg)
                   if "addrtype" in spec]
    check("one rule when enabled", len(transparent), 1)
    check(
        "redirects port 80, excluding local destinations",
        transparent[0],
        ["-i", "ppp+", "-p", "tcp", "--dport", "80",
         "-m", "addrtype", "!", "--dst-type", "LOCAL",
         "-j", "REDIRECT", "--to-ports", "8080"],
    )
    check("local destinations excluded so it stay native",
          "!" in transparent[0] and "LOCAL" in transparent[0], True)

    off = load_config()
    off.set("network", "transparent_http", "no")
    check("no rule when disabled",
          any("addrtype" in spec for _c, spec in build_nat_rules(off)), False)

    moved = load_config()
    moved.set("network", "transparent_http_port", "8090")
    spec = [s for _c, s in build_nat_rules(moved) if "addrtype" in s][0]
    check("target port configurable", spec[-1], "8090")

    blank = load_config()
    blank.set("network", "transparent_http_port", "")
    spec = [s for _c, s in build_nat_rules(blank) if "addrtype" in s][0]
    check("blank port falls back to 8080", spec[-1], "8080")

    check("listening probe finds nothing on a dead port",
          port_is_listening(9, timeout=0.3), False)

    print("address and hostname recognition")
    for good in ("1.2.3.4", "192.168.1.200", "0.0.0.0", "255.255.255.255"):
        check("IPv4 literal: %s" % good, is_ipv4_literal(good), True)
    for bad in ("randnetdd.ch", "1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.04",
                "", "1.2.3.x", "::1"):
        check("not an IPv4 literal: %-14r" % bad, is_ipv4_literal(bad), False)
    for good in ("randnetdd.ch", "server.randnetdd.ch", "a-b.example.co.uk",
                 "x.duckdns.org", "host1.local", "trailing.dot."):
        check("hostname: %s" % good, bool(HOSTNAME_RE.match(good)), True)
    for bad in ("-bad.example", "bad-.example", "has space.com", "a..b",
                "", "x" * 64 + ".com"):
        check("not a hostname: %-16r" % bad, bool(HOSTNAME_RE.match(bad)), False)

    print("resolving the Randnet target")
    import tempfile as _tf3

    probe_dir = _tf3.mkdtemp()
    try:
        drop_in = os.path.join(probe_dir, "redirect.conf")

        def target_cfg(setting, drop_in_body=None):
            probe = load_config()
            probe.set("network", "randnet_redirect", setting)
            probe.set("network", "dnsmasq_redirect_file", drop_in)
            if drop_in_body is None:
                if os.path.exists(drop_in):
                    os.unlink(drop_in)
            else:
                with open(drop_in, "w") as handle:
                    handle.write(drop_in_body)
            return probe

        address, previous, note = resolve_randnet_target(target_cfg("1.2.3.4"))
        check("a literal is used as given", (address, note), ("1.2.3.4",
                                                             "fixed address"))
        address, previous, note = resolve_randnet_target(target_cfg("off"))
        check("off yields no address", (address, note), (None, "disabled"))

        body = "address=/randnet.ne.jp/198.51.100.7\nlocal-ttl=0\n"
        check("previous address read back from the drop-in",
              previous_redirect_target(drop_in, "randnet.ne.jp"), None)
        address, previous, note = resolve_randnet_target(
            target_cfg("no-such-host.invalid", body))
        check("unresolvable name falls back to the last known address",
              (address, previous), ("198.51.100.7", "198.51.100.7"))
        check("and says so", "unresolved" in note, True)

        address, previous, note = resolve_randnet_target(
            target_cfg("no-such-host.invalid"))
        check("unresolvable with no history yields nothing",
              (address, previous), (None, None))

        address, previous, note = resolve_randnet_target(
            target_cfg("not a hostname at all", body))
        check("an unusable setting is refused, not resolved",
              (address, note), (None, "unusable setting"))

        check("a malformed drop-in line is ignored",
              previous_redirect_target(drop_in, "randnet.ne.jp"), "198.51.100.7")
        with open(drop_in, "w") as handle:
            handle.write("address=/randnet.ne.jp/not-an-address\n")
        check("a non-address in the drop-in is not trusted",
              previous_redirect_target(drop_in, "randnet.ne.jp"), None)
        check("a missing drop-in is not an error",
              previous_redirect_target(os.path.join(probe_dir, "nope"),
                                       "randnet.ne.jp"), None)
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)

    print("NAT exclusion follows a resolved address")
    named = load_config()
    named.set("network", "randnet_redirect", "randnetdd.ch")
    spec = [s for _c, s in build_nat_rules(named, "203.0.113.9")
            if "addrtype" in s][0]
    check("excludes the resolved address, not the name",
          "! -d 203.0.113.9" in " ".join(spec), True)
    check("the name never reaches iptables",
          "randnetdd.ch" in " ".join(spec), False)
    spec = [s for _c, s in build_nat_rules(named) if "addrtype" in s][0]
    check("no exclusion when the name is unresolved",
          "!" in spec[:6], False)

    def transparent_purges(*args):
        return [r for r in build_obsolete_nat_rules(*args) if "addrtype" in r[1]]

    print("a moved address has its old rule removed")
    obsolete = [" ".join(s) for _c, s in
                build_obsolete_nat_rules(named, "203.0.113.9", "198.51.100.7")]
    check("the previous address is purged",
          any("! -d 198.51.100.7" in s for s in obsolete), True)
    check("the current address is not purged",
          any("! -d 203.0.113.9" in s for s in obsolete), False)
    check("the un-excluded shape is purged too",
          any("! -d " not in s for s in obsolete), True)
    check("an unchanged address purges only the un-excluded shape",
          len(transparent_purges(named, "203.0.113.9", "203.0.113.9")), 1)

    print("the managed block in /etc/hosts")
    stock = ("127.0.0.1\tlocalhost\n"
             "127.0.1.1\tbridge\n"
             "::1\tip6-localhost ip6-loopback\n")
    names = ["randnet.ne.jp", "www.randnet.ne.jp"]

    block = render_etc_hosts_block(names, "203.0.113.9")
    added, changed = replace_managed_block(stock, block)
    check("adding it reports a change", changed, True)
    check("the address and every name are on one line",
          "203.0.113.9 randnet.ne.jp www.randnet.ne.jp" in added, True)
    check("markers are present", added.count(HOSTS_BEGIN), 1)
    check("closed exactly once", added.count(HOSTS_END), 1)

    check("every stock line survives untouched",
          all(line in added for line in stock.splitlines()), True)
    check("the stock section is byte-identical",
          added.startswith(stock), True)

    again, changed_again = replace_managed_block(added, block)
    check("running twice changes nothing", changed_again, False)
    check("and does not stack up blocks", again.count(HOSTS_BEGIN), 1)

    moved = render_etc_hosts_block(names, "198.51.100.7")
    updated, _ = replace_managed_block(added, moved)
    check("a moved address replaces the old one",
          "198.51.100.7 randnet.ne.jp" in updated, True)
    check("with no trace of the old address",
          "203.0.113.9" in updated, False)
    check("still only one block", updated.count(HOSTS_BEGIN), 1)

    removed, removed_changed = replace_managed_block(added, "")
    check("an empty block removes the section", removed_changed, True)
    check("nothing of ours is left", HOSTS_BEGIN in removed, False)
    check("and the file is back as it was", removed, stock)

    broken = stock + HOSTS_BEGIN + "\n203.0.113.9 randnet.ne.jp\n"
    repaired, _ = replace_managed_block(broken, block)
    check("an unterminated block is repaired, not nested",
          repaired.count(HOSTS_BEGIN), 1)
    check("the stock lines survive the repair", repaired.startswith(stock), True)

    check("no address means no block", render_etc_hosts_block(names, None), "")
    check("no names means no block",
          render_etc_hosts_block([], "203.0.113.9"), "")

    trailing = "127.0.0.1 localhost"          
    fixed, _ = replace_managed_block(trailing, block)
    check("a missing final newline is not glued to our block",
          "localhost\n" + HOSTS_BEGIN in fixed, True)

    print("TLS tunnel for the servlet traffic")
    plain = load_config()
    plain.set("network", "randnet_redirect", "dd.randnetdd.ch")
    before = [" ".join(s) for _c, s in build_nat_rules(plain, "203.0.113.9")]

    tls = load_config()
    tls.set("network", "randnet_redirect", "dd.randnetdd.ch")
    tls.set("network", "randnet_tls", "yes")
    after = [" ".join(s) for _c, s in build_nat_rules(tls, "203.0.113.9")]

    check("off by default", tls_tunnel_wanted(plain), False)
    check("adds exactly two rules", len(after) - len(before), 2)
    tunnel = [r for r in after if "--to-ports 8443" in r]
    check("two tunnel rules", len(tunnel), 2)
    check("both match the server address",
          all("-d 203.0.113.9 --dport 80" in r for r in tunnel), True)

    chains = [c for c, s in build_nat_rules(tls, "203.0.113.9")
              if "8443" in " ".join(s)]
    check("one in PREROUTING, one in OUTPUT",
          sorted(chains), ["OUTPUT", "PREROUTING"])
    prerouting = [r for c, s in build_nat_rules(tls, "203.0.113.9")
                  for r in [" ".join(s)] if c == "PREROUTING" and "8443" in r]
    output = [r for c, s in build_nat_rules(tls, "203.0.113.9")
              for r in [" ".join(s)] if c == "OUTPUT" and "8443" in r]
    check("the console's rule is bound to the ppp interface",
          "-i ppp+" in prerouting[0], True)
    check("the local rule names no interface", "-i" in output[0].split(), False)
    check("the local rule cannot catch stunnel's own connection",
          "--dport 80" in output[0] and "443" not in output[0].split("--to-ports")[0],
          True)
    check("the name never reaches iptables",
          any("randnetdd.ch" in r for r in after), False)

    tls_transparent = [r for r in after if "addrtype" in r]
    check("the transparent rule still excludes the server",
          "! -d 203.0.113.9" in tls_transparent[0], True)
    check("everything else still reaches the browsing proxy",
          "--to-ports 8080" in tls_transparent[0], True)
    check("the browsing proxy's own rules are untouched",
          [r for r in after if "--dport 8080" in r],
          [r for r in before if "--dport 8080" in r])
    check("turning TLS on changes nothing else",
          [r for r in after if "8443" not in r], before)

    moved_port = load_config()
    moved_port.set("network", "randnet_redirect", "dd.randnetdd.ch")
    moved_port.set("network", "randnet_tls", "yes")
    moved_port.set("network", "randnet_tunnel_port", "9443")
    spec = [" ".join(s) for _c, s in build_nat_rules(moved_port, "203.0.113.9")
            if "9443" in " ".join(s)]
    check("the tunnel port is configurable, on both rules", len(spec), 2)

    unresolved = load_config()
    unresolved.set("network", "randnet_redirect", "dd.randnetdd.ch")
    unresolved.set("network", "randnet_tls", "yes")
    check("no tunnel rule without an address to match",
          any("8443" in " ".join(s)
              for _c, s in build_nat_rules(unresolved)), False)

    check("tls host falls back to the redirect",
          tls_tunnel_host(tls), "dd.randnetdd.ch")
    explicit = load_config()
    explicit.set("network", "randnet_redirect", "203.0.113.9")
    explicit.set("network", "randnet_tls_host", "tunnel.example")
    check("an explicit tls host wins",
          tls_tunnel_host(explicit), "tunnel.example")

    print("a tunnel rule is cleaned up when it stops applying")
    gone = [" ".join(s) for _c, s in
            build_obsolete_nat_rules(plain, "203.0.113.9")]
    check("purged when TLS is off",
          any("-d 203.0.113.9 --dport 80 -j REDIRECT --to-ports 8443" in s
              for s in gone), True)
    gone_chains = [c for c, s in build_obsolete_nat_rules(plain, "203.0.113.9")
                   if "8443" in " ".join(s)]
    check("both halves are purged when TLS is off",
          sorted(gone_chains), ["OUTPUT", "PREROUTING"])
    moved_chains = [c for c, s in
                    build_obsolete_nat_rules(tls, "203.0.113.9", "198.51.100.7")
                    if "198.51.100.7" in " ".join(s) and "8443" in " ".join(s)]
    check("both halves of the old address are purged on a move",
          sorted(moved_chains), ["OUTPUT", "PREROUTING"])
    still_on = [" ".join(s) for _c, s in
                build_obsolete_nat_rules(tls, "203.0.113.9")]
    check("not purged while TLS is on",
          any("8443" in s for s in still_on), False)
    moved = [" ".join(s) for _c, s in
             build_obsolete_nat_rules(tls, "203.0.113.9", "198.51.100.7")]
    check("the old address's tunnel rule is purged when the server moves",
          any("-d 198.51.100.7 --dport 80 -j REDIRECT --to-ports 8443" in s
              for s in moved), True)
    check("the current address's tunnel rule survives the move",
          any("-d 203.0.113.9 --dport 80 -j REDIRECT --to-ports 8443" in s
              for s in moved), False)

    print("pointing at a Randnet server on another machine")
    remote = load_config()
    remote.set("network", "randnet_redirect", "192.168.1.200")
    check("recognised as pinned", pinned_randnet_server(remote), "192.168.1.200")
    check("host means not pinned", pinned_randnet_server(cfg), None)
    for value in ("off", "no", "none", "", "127.0.0.1"):
        probe = load_config()
        probe.set("network", "randnet_redirect", value)
        check("not pinned for %r" % value, pinned_randnet_server(probe), None)

    names = parse_host_list(cfg.get("network", "randnet_hostnames"))
    local_form = render_dns_redirect(names, "randnet.ne.jp", "eth0",
                                     "192.168.1.86", dynamic=True)
    remote_form = render_dns_redirect(names, "randnet.ne.jp", "eth0",
                                      "192.168.1.200", dynamic=False)
    check("local: one dynamic entry per hostname",
          len([l for l in local_form.split("\n")
               if l.startswith("interface-name=")]), 6)
    check("remote: no dynamic entries at all",
          any(l.startswith("interface-name=") for l in remote_form.split("\n")),
          False)
    check("remote: wildcard points at the server",
          "address=/randnet.ne.jp/192.168.1.200" in remote_form.split("\n"), True)
    check("remote: says why the dynamic entries are absent",
          "take precedence" in remote_form, True)

    remote_transparent = [spec for _c, spec in build_nat_rules(remote)
                          if "addrtype" in spec][0]
    check("remote: server excluded from the port 80 redirect",
          "! -d 192.168.1.200" in " ".join(remote_transparent), True)
    check("local: no exclusion needed",
          "!" in transparent[0][:6], False)

    check("remote enabled purges the un-excluded shape",
          len(transparent_purges(remote)), 1)
    check("the purged shape is the one without the exclusion",
          "-d" in build_obsolete_nat_rules(remote)[0][1], False)
    remote_off = load_config()
    remote_off.set("network", "randnet_redirect", "192.168.1.200")
    remote_off.set("network", "transparent_http", "no")
    check("remote disabled purges both shapes",
          len(transparent_purges(remote_off)), 2)

    check("nothing to purge while enabled and local",
          build_obsolete_nat_rules(cfg), [])
    obsolete = build_obsolete_nat_rules(off)
    check("disabling schedules the old rule for removal", len(obsolete), 1)
    check("the purged rule is exactly the one we would have added",
          obsolete[0][1], transparent[0])
    off_moved = load_config()
    off_moved.set("network", "transparent_http", "no")
    off_moved.set("network", "transparent_http_port", "8090")
    check("purge follows a changed port",
          build_obsolete_nat_rules(off_moved)[0][1][-1], "8090")
    check("host list split", parse_host_list("1.1.1.1, 2.2.2.2  3.3.3.3"),
          ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    check("empty host list", parse_host_list(""), [])

    print("host address selection (never loopback)")
    lo_only = json.dumps([
        {"ifname": "lo", "flags": ["LOOPBACK", "UP"],
         "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"}]},
    ])
    check("loopback-only host yields nothing", pick_host_address(lo_only), None)
    check("loopback-only, iface named", pick_host_address(lo_only, "lo"), None)

    two_ifaces = json.dumps([
        {"ifname": "lo", "flags": ["LOOPBACK"],
         "addr_info": [{"family": "inet", "local": "127.0.0.1", "scope": "host"}]},
        {"ifname": "eth0", "flags": ["UP"],
         "addr_info": [{"family": "inet", "local": "192.168.1.87",
                        "scope": "global"}]},
        {"ifname": "eth1", "flags": ["UP"],
         "addr_info": [{"family": "inet", "local": "10.0.0.5",
                        "scope": "global"}]},
    ])
    check("prefers the named interface",
          pick_host_address(two_ifaces, "eth1"), "10.0.0.5")
    check("skips lo when no interface is named",
          pick_host_address(two_ifaces), "192.168.1.87")
    check("unknown interface falls back to a real address",
          pick_host_address(two_ifaces, "ppp0"), "192.168.1.87")

    link_local = json.dumps([
        {"ifname": "eth0", "flags": ["UP"], "addr_info": [
            {"family": "inet", "local": "169.254.1.1", "scope": "link"},
            {"family": "inet", "local": "192.168.1.87", "scope": "global"}]},
    ])
    check("ignores link-scope addresses",
          pick_host_address(link_local, "eth0"), "192.168.1.87")
    check("ignores IPv6", pick_host_address(json.dumps([
        {"ifname": "eth0", "flags": ["UP"], "addr_info": [
            {"family": "inet6", "local": "fe80::1", "scope": "link"}]}])), None)
    check("empty input", pick_host_address("[]"), None)
    check("garbage input", pick_host_address("not json"), None)
    check("loopback detector", (is_loopback("127.0.0.1"), is_loopback("127.1.2.3"),
                                is_loopback("192.168.1.1"), is_loopback(None)),
          (True, True, False, False))

    print("resolver failure diagnosis")

    def verdict(dnsmasq_state, resolved_state, port_lines, log=None):
        return " ".join(
            explain_resolver_failure(dnsmasq_state, resolved_state, port_lines,
                                     log)
        )

    held_lines = [
        'UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=1,fd=3))'
    ]
    contradiction = ("aug 28 16:01:00 host dnsmasq[6709]: "
                     "cannot set --bind-interfaces and --bind-dynamic")
    v = verdict("failed", "active", held_lines, contradiction)
    check("log beats port-conflict inference",
          "contradict each other" in v, True)
    check("does not blame the port when the log disagrees",
          "already held by" in v, False)
    check("tells you where to grep", "grep -rn" in v, True)
    check("quotes what dnsmasq said", "dnsmasq said:" in v, True)

    v = verdict("failed", "active", held_lines,
                "dnsmasq[9]: failed to create listening socket for port 53: "
                "Address already in use")
    check("port-conflict message from the log",
          "bind-dynamic" in v and "except-interface=lo" in v, True)

    v = verdict("failed", "inactive", ["nothing is listening on port 53"],
                "dnsmasq[9]: unknown option at line 4 of /etc/dnsmasq.d/x.conf")
    check("unknown option recognised", "rejected an option" in v, True)

    v = verdict("failed", "inactive", ["nothing is listening on port 53"],
                "dnsmasq[9]: no such interface ens33")
    check("missing interface recognised", "does not exist" in v, True)

    check("unrecognised log falls back to inference",
          "on its own account" in verdict(
              "failed", "inactive", ["nothing is listening on port 53"],
              "dnsmasq[9]: started, version 2.91 cachesize 150"), True)
    check("newest error wins over an older one",
          "contradict each other" in verdict(
              "failed", "active", held_lines,
              "dnsmasq[1]: failed to create listening socket for port 53\n"
              "dnsmasq[2]: cannot set --bind-interfaces and --bind-dynamic"),
          True)
    check("no log at all still gives a verdict",
          len(verdict("failed", "active", held_lines, None)) > 0, True)

    held = verdict("failed", "active", [
        'UNCONN 0 0 127.0.0.53:53 0.0.0.0:* users:(("systemd-resolve",pid=1,fd=3))'
    ])
    check("names the port 53 holder", "systemd-resolve" in held, True)
    check("does not claim the port is free", "nothing is bound" in held, False)
    check("gives the bind-dynamic fix", "bind-dynamic" in held, True)
    check("gives the except-interface fix", "except-interface=lo" in held, True)
    check("says resolv.conf stays untouched", "untouched" in held, True)

    free = verdict("failed", "inactive", ["nothing is listening on port 53"])
    check("free port -> blames dnsmasq itself", "on its own account" in free, True)
    check("free port -> does not invent a conflict", "already held" in free, False)

    silent = verdict("active", "inactive", ["nothing is listening on port 53"])
    check("running but silent -> points at CONFIG_DIR",
          "CONFIG_DIR" in silent, True)

    other = verdict("failed", "inactive",
                    ['LISTEN 0 1 127.0.0.53:53 users:(("unbound",pid=9,fd=4))'])
    check("recognises a non-resolved holder", "unbound" in other, True)

    print("dnsmasq bind-mode detection")
    import tempfile as _tf

    probe_dir = _tf.mkdtemp()
    try:
        check("absent when nothing is configured",
              dnsmasq_binds_dynamically((probe_dir,)), False)
        with open(os.path.join(probe_dir, "a.conf"), "w") as handle:
            handle.write("# comment\nno-resolv\nbind-dynamic\n")
        check("detected in a drop-in", dnsmasq_binds_dynamically((probe_dir,)), True)
        with open(os.path.join(probe_dir, "a.conf"), "w") as handle:
            handle.write("#bind-dynamic\n")
        check("commented out does not count",
              dnsmasq_binds_dynamically((probe_dir,)), False)
        with open(os.path.join(probe_dir, "a.conf"), "w") as handle:
            handle.write("bind-interfaces\n")
        check("bind-interfaces also counts",
              dnsmasq_binds_dynamically((probe_dir,)), True)
        check("ignores non-conf files",
              dnsmasq_binds_dynamically((os.path.join(probe_dir, "missing"),)), False)
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)

    print("DNS response parsing")
    import struct as _struct

    def response(name, ip, query_id=0x1234, answers=1, rtype=1):
        header = _struct.pack(">HHHHHH", query_id, 0x8180, 1, answers, 0, 0)
        question = b""
        for label in name.split("."):
            question += bytes([len(label)]) + label.encode()
        question += b"\x00" + _struct.pack(">HH", 1, 1)
        body = b""
        for _ in range(answers):
            body += b"\xc0\x0c"
            octets = bytes(int(p) for p in ip.split("."))
            body += _struct.pack(">HHIH", rtype, 1, 300, len(octets)) + octets
        return header + question + body

    check("single A record",
          parse_dns_response(response("www.randnet.ne.jp", "192.168.1.87"), 0x1234),
          "192.168.1.87")
    check("deep subdomain",
          parse_dns_response(response("a.b.c.randnet.ne.jp", "10.0.0.1"), 0x1234),
          "10.0.0.1")
    check("first of two answers",
          parse_dns_response(response("randnet.ne.jp", "1.2.3.4", answers=2), 0x1234),
          "1.2.3.4")
    check("empty answer section",
          parse_dns_response(response("x.randnet.ne.jp", "1.2.3.4", answers=0),
                             0x1234), None)
    check("mismatched transaction id",
          parse_dns_response(response("x.randnet.ne.jp", "1.2.3.4"), 0x9999), None)
    check("non-A record ignored",
          parse_dns_response(response("x.randnet.ne.jp", "1.2.3.4", rtype=28),
                             0x1234), None)
    check("truncated packet", parse_dns_response(b"\x124", 0x1234), None)
    check("name skip over pointer", _skip_dns_name(b"\xc0\x0c\xff", 0), 2)
    check("name skip over labels", _skip_dns_name(b"\x03abc\x00\xff", 0), 5)

    print("Randnet DNS redirect rendering")
    names = parse_host_list(cfg.get("network", "randnet_hostnames"))
    check("six hostnames from the disk", len(names), 6)
    check("bare domain included", "randnet.ne.jp" in names, True)
    check("pooled host included", "peach.randnet.ne.jp" in names, True)
    check("mail hosts included",
          {"smtp.dd.randnet.ne.jp", "pop.dd.randnet.ne.jp"} <= set(names), True)
    check("infoweb excluded (different ISP profile)",
          any("infoweb" in n for n in names), False)

    rendered = render_dns_redirect(names, "randnet.ne.jp", "eth0", "192.168.1.87")
    body = rendered.split("\n")
    check("dynamic entry per hostname",
          len([l for l in body if l.startswith("interface-name=")]), 6)
    check("dynamic entry format",
          "interface-name=www.randnet.ne.jp,eth0" in body, True)
    check("wildcard catch-all present",
          "address=/randnet.ne.jp/192.168.1.87" in body, True)
    check("ttl pinned to zero", "local-ttl=0" in body, True)

    no_iface = render_dns_redirect(names, "randnet.ne.jp", None, "192.168.1.87")
    check("no interface -> no dynamic entries",
          any(l.startswith("interface-name=") for l in no_iface.split("\n")), False)
    check("no interface -> wildcard still emitted",
          "address=/randnet.ne.jp/192.168.1.87" in no_iface.split("\n"), True)

    no_ip = render_dns_redirect(names, "randnet.ne.jp", "eth0", None)
    check("no address -> dynamic entries kept",
          len([l for l in no_ip.split("\n") if l.startswith("interface-name=")]), 6)
    check("no address -> no half-written wildcard",
          any(l.startswith("address=") for l in no_ip.split("\n")), False)

    print("DTMF decoding")
    check("digit", decode_dtmf(b"5"), "5")
    check("letter", decode_dtmf(b"A"), "A")
    check("hash", decode_dtmf(b"#"), "#")
    check("not a digit", decode_dtmf(b"z"), None)
    check("empty", decode_dtmf(b""), None)
    check("high byte", decode_dtmf(b"\xff"), None)

    print("dial tone pacing")
    now = [0.0]
    pacer = TonePacer(bytes(2500), clock=lambda: now[0])
    pacer.start()
    check("due immediately after start", pacer.due(), True)
    check("first chunk is 1000 bytes", len(pacer.next_chunk()), 1000)
    check("not due again yet", pacer.due(), False)
    now[0] = 0.124
    check("not due at 124ms", pacer.due(), False)
    now[0] = 0.125
    check("due at 125ms", pacer.due(), True)
    pacer.next_chunk()
    now[0] = 0.250
    pacer.next_chunk()
    check("wraps at end of buffer", len(pacer.next_chunk()) > 0, True)
    now[0] = 100.0 
    pacer.next_chunk()
    check("no burst catch-up after a stall", pacer.due(), False)

    print()
    if failures:
        print("%d check(s) FAILED: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("all checks passed")
    return 0


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="randnetpi3.py",
        description="Answer a Randnet dial-up call and hand the line to pppd.",
    )
    parser.add_argument("--config", "-c", help="path to an ini config file")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="print the generated config, pppd command and NAT rules, then exit",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run offline checks of the parsing and rendering logic, then exit",
    )
    parser.add_argument(
        "--check-dns",
        action="store_true",
        help="show which address the Randnet names point at, from the config, "
             "the generated drop-in and the resolver itself, then exit",
    )
    parser.add_argument(
        "--disable-dial-tone",
        action="store_true",
        help="do not generate a dial tone (the line inducer may supply one)",
    )
    parser.add_argument(
        "--pppd-debug", action="store_true", help="add `debug` to the peers file"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="log at DEBUG level"
    )
    parser.add_argument(
        "--no-daemon",
        action="store_true",
        help="accepted and ignored; this version never daemonises",
    )
    parser.add_argument("--version", action="version", version="randnetpi3 " + VERSION)
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    if args.self_test:
        return do_self_test()

    cfg = load_config(args.config)

    if args.check_dns:
        return do_check_dns(cfg)

    if args.dry_run:
        return do_dry_run(cfg, args)

    if os.geteuid() != 0:
        raise SystemExit(
            "randnetpi3 must run as root: it writes /etc/ppp, adds NAT rules "
            "and starts pppd.  Use --dry-run or --self-test to inspect it "
            "without root."
        )

    killer = GracefulKiller()

    logger.info("randnetpi3 %s starting", VERSION)

    while not check_internet_connection():
        logger.info("Waiting for an internet connection")
        time.sleep(3)
        if killer.kill_now:
            return 0

    target = configure_dns_redirect(cfg)

    if cfg.getboolean("network", "restart_dnsmasq"):
        restart_dnsmasq()

    try:
        return serve(cfg, args, killer, target)
    except SystemExit:
        raise
    except Exception:
        logger.exception("Unhandled error")
        return 1
    finally:
        logger.info("randnetpi3 stopped")


if __name__ == "__main__":
    sys.exit(main())
