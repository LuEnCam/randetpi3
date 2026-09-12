#!/usr/bin/env python3
"""install_randnetpi3.py - set up randnetpi3 on a fresh Debian, Ubuntu or
Raspberry Pi OS install.

Installs the dependencies, lays the files down, asks which CHAP key to use,
writes the configuration and enables the service so it starts at boot.

    sudo ./install_randnetpi3.py                            # interactive
    sudo ./install_randnetpi3.py --dry-run                  # show everything, change nothing
    sudo ./install_randnetpi3.py --default-key              # skip the questions & set default CHAP (K1QU0K@N)
    sudo ./install_randnetpi3.py --chap-secret 'K1QU0K@N'   # skip the questions and setting your CHAP

"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))

INSTALL_DIR = "/opt/randnetpi3"
SCRIPT_DEST = os.path.join(INSTALL_DIR, "randnetpi3.py")
WAV_DEST = os.path.join(INSTALL_DIR, "dial-tone.wav")
CONFIG_DEST = "/etc/randnetpi3.conf"
UNIT_DEST = "/etc/systemd/system/randnetpi3.service"
PROXY_SCRIPT = "randnet_proxy.py"
PROXY_UNIT = "randnet-proxy.service"
PROXY_SCRIPT_DEST = os.path.join(INSTALL_DIR, PROXY_SCRIPT)
PROXY_UNIT_DEST = "/etc/systemd/system/" + PROXY_UNIT
PROXY_SERVICE = "randnet-proxy"
PROXY_PORT_DEFAULT = 8080
PROXY_MAX_BYTES_DEFAULT = 32768
STUNNEL_SOURCE = "stunnel-randnet.conf"
STUNNEL_DEST = "/etc/stunnel/randnet.conf"
STUNNEL_SERVICE = "stunnel@randnet"
STUNNEL_PACKAGE = "stunnel4"
TLS_PORT_DEFAULT = 443
TUNNEL_PORT_DEFAULT = 8443
PPP_OPTIONS = "/etc/ppp/options"
DNSMASQ_DROPIN = "/etc/dnsmasq.d/randnetpi3.conf"
UBUNTU_FAN_PACKAGE = "ubuntu-fan"

DOCKER_DAEMON_JSON = "/etc/docker/daemon.json"
WRP_IMAGE = "tenox7/wrp:latest"
WRP_CONTAINER = "wrp"

WRP_GEOMETRY_DEFAULT = "540x384x16"
WRP_MODE_DEFAULT = "html"
WRP_TYPE_DEFAULT = "gif"
WRP_DELAY_DEFAULT = "3s"
WRP_PORT_DEFAULT = 8081

DEFAULT_CHAP_SECRET = "K1QU0K@N"

DIAL_TONE_URL = (
    "https://raw.githubusercontent.com/Kazade/dreampi/master/dial-tone.wav"
)

APT_PACKAGES = [
    "ppp",
    "python3-serial",  
    "iproute2",        
    "iptables",        
    "dnsmasq",         
]


CONFLICTING_SERVICES = ["dreampi", "randnetpi", "xbandpi"]

RANDNET_DOMAINS = ["randnet.ne.jp"]

DNSMASQ_CONF = """\

bind-dynamic
except-interface=lo

# Do not forward queries for unqualified or private-range names upstream.
domain-needed
bogus-priv

# Ignore /etc/resolv.conf and use these upstream resolvers instead, so the
# console's DNS does not depend on whatever DHCP handed this box.
no-resolv
server=1.1.1.1
server=8.8.8.8
"""

_BOLD = "\033[1m" if sys.stdout.isatty() else ""
_RESET = "\033[0m" if sys.stdout.isatty() else ""


def step(message):
    print("\n%s==> %s%s" % (_BOLD, message, _RESET))


def info(message):
    print("    %s" % message)


def warn(message):
    print("    WARNING: %s" % message)


def fail(message):
    sys.stdout.flush()
    print("\nERROR: %s" % message, file=sys.stderr)
    sys.stderr.flush()
    raise SystemExit(1)


class Runner(object):

    def __init__(self, dry_run):
        self.dry_run = dry_run

    def run(self, argv, check=True, env=None):
        if self.dry_run:
            info("would run: %s" % " ".join(argv))
            return 0
        info("running: %s" % " ".join(argv))
        merged = dict(os.environ, **(env or {}))
        result = subprocess.run(argv, env=merged, check=False)
        if check and result.returncode != 0:
            fail("command failed (rc=%d): %s" % (result.returncode, " ".join(argv)))
        return result.returncode

    def write(self, path, content, mode=0o644):
        if self.dry_run:
            info("would write %s (mode %o, %d bytes)" % (path, mode, len(content)))
            return
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.chmod(path, mode)
        info("wrote %s (mode %o)" % (path, mode))

    def copy(self, src, dest, mode=0o644):
        if self.dry_run:
            info("would copy %s -> %s (mode %o)" % (src, dest, mode))
            return
        directory = os.path.dirname(dest)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        shutil.copyfile(src, dest)
        os.chmod(dest, mode)
        info("copied %s -> %s (mode %o)" % (src, dest, mode))

    def backup(self, path):
        if not os.path.exists(path):
            return None
        stamp = time.strftime("%Y%m%d-%H%M%S")
        dest = "%s.pre-randnetpi3.%s" % (path, stamp)
        if self.dry_run:
            info("would back up %s -> %s" % (path, dest))
            return dest
        shutil.copy2(path, dest)
        info("backed up %s -> %s" % (path, dest))
        return dest


def describe_os():
    fields = {}
    try:
        with open("/etc/os-release") as handle:
            for line in handle:
                if "=" in line:
                    key, _, value = line.strip().partition("=")
                    fields[key] = value.strip('"')
    except (IOError, OSError):
        pass
    return fields.get("PRETTY_NAME", "unknown"), fields.get("ID", "")


def preflight(dry_run):
    step("Checking the system")

    if sys.platform != "linux":
        fail("this installer only runs on Linux")

    if os.geteuid() != 0 and not dry_run:
        fail("run this with sudo: sudo ./install_randnetpi3.py")

    pretty, distro_id = describe_os()
    info("OS: %s" % pretty)
    if distro_id not in ("debian", "ubuntu", "raspbian", ""):
        warn(
            "%s is not Debian, Ubuntu or Raspberry Pi OS. The apt step will "
            "probably fail; install ppp, pyserial, iproute2, iptables and "
            "dnsmasq yourself and re-run with --skip-packages." % distro_id
        )

    if sys.version_info < (3, 9):
        fail(
            "randnetpi3 needs Python 3.9 or newer, this is %d.%d"
            % sys.version_info[:2]
        )
    info("Python: %d.%d.%d" % sys.version_info[:3])

    if shutil.which("systemctl") is None:
        fail("systemd not found; this installer sets up a systemd service")

    if shutil.which("apt-get") is None and not dry_run:
        warn("apt-get not found, package installation will be skipped")

    for name in ("randnetpi3.py", "randnetpi3.conf", "randnetpi3.service"):
        path = os.path.join(HERE, name)
        if not os.path.exists(path):
            fail(
                "%s is missing from %s. Run this installer from the directory "
                "that contains randnetpi3.py, randnetpi3.conf and "
                "randnetpi3.service." % (name, HERE)
            )
    info("Found randnetpi3.py, randnetpi3.conf and randnetpi3.service in %s" % HERE)


CHAP_KEY_HELP = """\
    Where to find your key:

      The key is stored in the member record in the disk's rewritable area,
      next to your Randnet account name. With a disk image (.ndd) you can pull
      it out with the analysis tooling in this project:

          python3 extract_member.py [path_to_your_ndd_image]

      and read the value printed on the "CHAP KEY" line.

      If you have a 64DD with a Randnet disk with an existing account, you can
      use the following rom with a flash cart cart to read the CHAP KEY on it:

          randnet_diskread.n64

      Every key seen so far is exactly 8 characters. Type it exactly as it
      appears, including any punctuation and letter case. Do not add quotes and
      do not escape anything: this installer handles that for you.

"""


def ask_yes_no(question, default=False):
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            answer = input("    %s %s " % (question, suffix)).strip().lower()
        except EOFError:
            fail("no input available; use --default-key or --chap-secret for "
                 "an unattended install")
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("    Please answer y or n.")


def describe_secret(secret):

    hexed = " ".join("%02X" % byte for byte in secret.encode("utf-8"))
    print("      characters : %d" % len(secret))
    print("      literal    : [%s]" % secret)
    print("      hex        : %s" % hexed)
    if secret != secret.strip():
        print("      note       : starts or ends with whitespace "
              "(will be stored base64 encoded)")


def prompt_for_chap_secret():
    print(CHAP_KEY_HELP)
    while True:
        try:
            secret = input("    CHAP key: ")
        except EOFError:
            fail("no input available")

        if not secret:
            print("    The key cannot be empty.")
            continue

        control = [ch for ch in secret if ord(ch) < 32 or ord(ch) == 127]
        if control:
            print("    The key contains a control character; that cannot be "
                  "stored in chap-secrets. Please retype it.")
            continue

        print()
        describe_secret(secret)
        if len(secret) != 8:
            print("      note       : every Randnet key seen so far is 8 "
                  "characters, this one is %d" % len(secret))
        if "\\" in secret or '"' in secret:
            print("      note       : contains a backslash or double quote. "
                  "These are escaped for pppd, but verify with a test dial.")
        print()

        if ask_yes_no("Is that exactly right?", default=True):
            return secret
        print("    Let's try again.\n")


def choose_chap_secret(args):
    step("Choosing the CHAP key")

    if args.chap_secret is not None:
        info("Using the key given on the command line")
        describe_secret(args.chap_secret)
        return args.chap_secret

    if args.default_key:
        info("Using the factory key %s" % DEFAULT_CHAP_SECRET)
        return DEFAULT_CHAP_SECRET

    if not sys.stdin.isatty():
        fail(
            "no terminal for the questions. Use --default-key or "
            "--chap-secret KEY for an unattended install."
        )

    print("    The CHAP key is the shared secret the console proves it knows.")
    print("    A disk with no account uses the factory key; a disk with an")
    print("    account has its own.\n")

    has_disk = ask_yes_no(
        "Do you have a 64DD with a Randnet Disk, or an image of the Randnet "
        "Disk?", default=False
    )
    if not has_disk:
        info("No disk: using the factory key %s" % DEFAULT_CHAP_SECRET)
        return DEFAULT_CHAP_SECRET

    has_account = ask_yes_no(
        "Does the disk have an existing account? (When booting the disk, do "
        "you see a screen with 5 IDs?)", default=False
    )
    if not has_account:
        info("No account on the disk: using the factory key %s"
             % DEFAULT_CHAP_SECRET)
        return DEFAULT_CHAP_SECRET

    return prompt_for_chap_secret()


def secret_storage(secret):

    if secret != secret.strip() or "\n" in secret or "\r" in secret:
        return "b64", base64.b64encode(secret.encode("utf-8")).decode("ascii")
    return "plain", secret


def render_config(template, secret, redirect="host", proxy_port=None,
                  tls_host=None, tls_port=None, tunnel_port=None):

    kind, stored = secret_storage(secret)

    plain = stored if kind == "plain" else ""
    encoded = stored if kind == "b64" else ""

    def replace(pattern, value, text):
        new_text, count = re.subn(
            pattern, lambda _m: value, text, count=1, flags=re.MULTILINE
        )
        if count != 1:
            fail("could not find %r in randnetpi3.conf; is it the shipped "
                 "sample file?" % pattern)
        return new_text

    plain_line = ("chap_secret = " + plain) if plain else "chap_secret ="
    b64_line = ("chap_secret_b64 = " + encoded) if encoded else "chap_secret_b64 ="

    text = replace(r"^chap_secret\s*=.*$", plain_line, template)
    text = replace(r"^chap_secret_b64\s*=.*$", b64_line, text)
    text = replace(r"^randnet_redirect\s*=.*$",
                   "randnet_redirect = " + redirect, text)

    if proxy_port is not None and proxy_port != PROXY_PORT_DEFAULT:
        text = replace(r"^proxy_target_port\s*=.*$",
                       "proxy_target_port = %d" % proxy_port, text)
        text = replace(r"^transparent_http_port\s*=.*$",
                       "transparent_http_port = %d" % proxy_port, text)

    if tls_host:
        text = replace(r"^randnet_tls\s*=.*$", "randnet_tls = yes", text)
        text = replace(r"^randnet_tls_host\s*=.*$",
                       "randnet_tls_host = " + tls_host, text)
        text = replace(r"^randnet_tls_port\s*=.*$",
                       "randnet_tls_port = %d" % (tls_port or TLS_PORT_DEFAULT),
                       text)
        text = replace(r"^randnet_tunnel_port\s*=.*$",
                       "randnet_tunnel_port = %d"
                       % (tunnel_port or TUNNEL_PORT_DEFAULT), text)

    return text, kind


def verify_config_round_trip(config_path, expected_secret, dry_run):

    if dry_run:
        info("would verify the key round-trips through %s" % config_path)
        return

    sys.path.insert(0, INSTALL_DIR)
    try:
        import randnetpi3
    except ImportError as exc:
        fail("could not import the installed randnetpi3.py: %s" % exc)
    finally:
        sys.path.pop(0)

    cfg = randnetpi3.load_config(config_path)
    got = randnetpi3.resolve_chap_secret(cfg)
    if got != expected_secret:
        fail(
            "the CHAP key did not survive being written to %s\n"
            "  expected: %r\n  got:      %r" % (config_path, expected_secret, got)
        )
    rendered = randnetpi3.quote_secret(got)
    info("Key verified: reads back identically from %s" % config_path)
    info("chap-secrets will contain: * %s %s *"
         % (cfg.get("ppp", "chap_name"), rendered))



def synthesize_dial_tone(seconds=4.0, rate=8000):

    import math

    frames = int(rate * seconds)
    samples = bytearray(frames)
    for index in range(frames):
        t = float(index) / rate
        mixed = (
            math.sin(2.0 * math.pi * 350.0 * t)
            + math.sin(2.0 * math.pi * 440.0 * t)
        ) / 2.0
        samples[index] = max(0, min(255, int(round(mixed * 110.0)) + 128))

    data = bytes(samples)
    header = b"RIFF"
    header += struct.pack("<I", 36 + len(data))
    header += b"WAVEfmt "
    header += struct.pack("<IHHIIHH", 16, 1, 1, rate, rate, 1, 8)
    header += b"data"
    header += struct.pack("<I", len(data))
    assert len(header) == 44, len(header)
    return header + data


def validate_wav(data, source):

    if len(data) < 45 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        fail("%s is not a RIFF/WAVE file" % source)

    try:
        fmt, channels, rate, _, _, bits = struct.unpack("<HHIIHH", data[20:36])
        payload_at = data.index(b"data") + 8
    except (struct.error, ValueError):
        fail("%s has a WAV header randnetpi3 cannot use" % source)

    info(
        "Format: PCM=%d channels=%d rate=%d bits=%d, payload at byte %d"
        % (fmt, channels, rate, bits, payload_at)
    )

    problems = []
    if payload_at != 44:
        problems.append("samples start at byte %d, not 44" % payload_at)
    if (fmt, channels, rate, bits) != (1, 1, 8000, 8):
        problems.append("not 8 kHz 8 bit unsigned mono PCM")

    if problems:
        warn("%s: %s" % (source, "; ".join(problems)))
        warn("randnetpi3 strips exactly 44 bytes and expects 8 kHz 8 bit mono,")
        warn("so the dial tone will sound wrong. Consider --dial-tone with a")
        warn("correct file, or let the installer generate one.")
    else:
        info("Matches what randnetpi3 expects (%.2f seconds of audio)"
             % ((len(data) - 44) / 8000.0))


def download_dial_tone(url, timeout=20):

    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if response.status != 200:
                return None, "HTTP %s" % response.status
            return response.read(), None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return None, str(exc)


def install_dial_tone(runner, args):
    step("Installing the dial tone")

    local = args.dial_tone or os.path.join(HERE, "dial-tone.wav")
    if os.path.exists(local):
        info("Using local file %s" % local)
        with open(local, "rb") as handle:
            data = handle.read()
        validate_wav(data, local)
        runner.copy(local, WAV_DEST, mode=0o644)
        return
    if args.dial_tone:
        fail("--dial-tone %s does not exist" % args.dial_tone)

    if not args.no_download:
        info("No local dial-tone.wav; fetching the original from dreampi")
        info(DIAL_TONE_URL)
        if runner.dry_run:
            info("would download and install it to %s" % WAV_DEST)
            return
        data, error = download_dial_tone(DIAL_TONE_URL)
        if data:
            info("Downloaded %d bytes (sha256 %s)"
                 % (len(data), hashlib.sha256(data).hexdigest()[:16]))
            validate_wav(data, DIAL_TONE_URL)
            runner.write(WAV_DEST, data, mode=0o644)
            return
        warn("Download failed: %s" % error)
        if "CERTIFICATE_VERIFY_FAILED" in str(error):
            warn("That is a TLS trust problem, not a missing file. A proxy that")
            warn("inspects HTTPS will cause it. Fetch the file by hand and pass")
            warn("it in instead:")
            warn("  curl -LO %s" % DIAL_TONE_URL)
            warn("  sudo ./install_randnetpi3.py --dial-tone ./dial-tone.wav ...")

    info("Generating a dial tone locally instead: 350 Hz + 440 Hz,")
    info("8 kHz 8 bit unsigned PCM, the same format as the original.")
    generated = synthesize_dial_tone()
    validate_wav(generated, "generated dial tone")
    runner.write(WAV_DEST, generated, mode=0o644)
    info("To swap in the original later, drop dial-tone.wav into %s"
         % INSTALL_DIR)
    info("and run: sudo systemctl restart randnetpi3")



def merge_docker_daemon_json(existing_text):

    data = {}
    if existing_text and existing_text.strip():
        data = json.loads(existing_text)
        if not isinstance(data, dict):
            raise ValueError("daemon.json is not a JSON object")

    if data.get("ip-forward-no-drop") is True:
        return json.dumps(data, indent=2) + "\n", "already set"

    data["ip-forward-no-drop"] = True
    return json.dumps(data, indent=2) + "\n", "added"


def apply_docker_forward_fix(runner):

    step("Letting Docker coexist with routing")
    info("Docker sets the iptables FORWARD policy to DROP, which stops this")
    info("machine forwarding between ppp0 and the LAN. That breaks the")
    info("console's direct internet access (pings, raw TCP).")

    existing = ""
    if os.path.exists(DOCKER_DAEMON_JSON):
        try:
            with open(DOCKER_DAEMON_JSON) as handle:
                existing = handle.read()
        except (IOError, OSError) as exc:
            warn("could not read %s: %s" % (DOCKER_DAEMON_JSON, exc))
            return False

    try:
        content, note = merge_docker_daemon_json(existing)
    except ValueError as exc:
        warn("%s is not valid JSON (%s)." % (DOCKER_DAEMON_JSON, exc))
        warn("Leaving it alone rather than overwriting your configuration.")
        warn('Add  "ip-forward-no-drop": true  to it by hand.')
        return False

    if existing.strip():
        runner.backup(DOCKER_DAEMON_JSON)
    runner.write(DOCKER_DAEMON_JSON, content, mode=0o644)
    info("ip-forward-no-drop %s (other settings preserved)" % note)

    runner.run(["systemctl", "restart", "docker"], check=False)
    runner.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)
    info("FORWARD policy set to ACCEPT for this boot")
    return True


def normalise_wrp_delay(value):

    value = (value or "").strip()
    if re.match(r"\A\d+\Z", value):
        return value + "s", True
    return value, False


def validate_wrp_geometry(value):
    if not re.match(r"\A\d+x\d+x\d+\Z", (value or "").strip()):
        fail("--wrp-geometry must look like WxHxC, for example %s"
             % WRP_GEOMETRY_DEFAULT)
    return value.strip()


def wrp_run_argv(port, mode, img_type, geometry, delay):
    return [
        "docker", "run", "-d", "--restart", "unless-stopped",
        "--name", WRP_CONTAINER,
        "-p", "%d:8080" % port,
        WRP_IMAGE,
        "-l", ":8080",
        "-m", mode,
        "-t", img_type,
        "-g", geometry,
        "-s", delay,
    ]


def install_wrp(runner, args):

    step("Installing WRP (Web Rendering Proxy)")

    port = args.wrp_port
    taken = {80: "the Randnet server"}
    if not args.no_proxy:
        taken[args.proxy_port] = "the browsing proxy"
    if port in taken:
        fail("--wrp-port %d is already %s. Use something else, such as %d."
             % (port, taken[port], WRP_PORT_DEFAULT))

    geometry = validate_wrp_geometry(args.wrp_geometry)
    delay, added_unit = normalise_wrp_delay(args.wrp_delay)
    if added_unit:
        info("--wrp-delay %s is a Go duration; using %s"
             % (args.wrp_delay, delay))

    if shutil.which("docker") is None:
        info("Installing Docker (WRP needs Chrome, and the image bundles it)")
        if shutil.which("apt-get") is None:
            fail("apt-get not found; install Docker yourself then re-run")
        env = {"DEBIAN_FRONTEND": "noninteractive"}
        runner.run(["apt-get", "install", "-y", "docker.io"], env=env)
        runner.run(["systemctl", "enable", "--now", "docker"], check=False)
    else:
        info("Docker already installed")

    apply_docker_forward_fix(runner)

    step("Starting WRP")
    info("Pulling %s (about 530 MB, this takes a while)" % WRP_IMAGE)
    if runner.run(["docker", "pull", WRP_IMAGE], check=False) != 0:
        warn("docker pull failed. WRP is not running; everything else is fine.")
        warn("Retry later with:  sudo docker pull %s" % WRP_IMAGE)
        return False

    runner.run(["docker", "rm", "-f", WRP_CONTAINER], check=False)

    argv = wrp_run_argv(port, args.wrp_mode, args.wrp_image_type, geometry, delay)
    if runner.run(argv, check=False) != 0:
        warn("could not start the WRP container")
        return False

    info("WRP listening on port %d, mode=%s type=%s geometry=%s"
         % (port, args.wrp_mode, args.wrp_image_type, geometry))
    info("From the console's address bar:  http://<this machine>:%d/" % port)
    info("Type the full https:// URL into WRP's own form, not the console's")
    info("address bar: the browser has no TLS, WRP's Chrome does it instead.")
    return True


def port_answers(port, host="127.0.0.1", attempts=6, delay=0.5, timeout=2.0):

    for attempt in range(attempts):
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except (OSError, ValueError):
            pass
        if attempt + 1 < attempts:
            time.sleep(delay)
    return False


def proxy_responds(port, attempts=6, delay=0.5, timeout=5.0):

    import urllib.error
    import urllib.request

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for attempt in range(attempts):
        try:
            with opener.open("http://127.0.0.1:%d/hello" % port,
                             timeout=timeout) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        if attempt + 1 < attempts:
            time.sleep(delay)
    return False


def wrp_responds(port, timeout=5.0):

    import urllib.error
    import urllib.request

    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/" % port,
                                    timeout=timeout) as response:
            return response.status == 200
    except (urllib.error.URLError, OSError, ValueError):
        return False


def install_packages(runner, args):
    step("Installing packages")
    if args.skip_packages:
        info("Skipped (--skip-packages)")
        return
    if shutil.which("apt-get") is None:
        warn("apt-get not available, skipping")
        return

    packages = list(APT_PACKAGES)
    if args.with_tls:
        packages.append(STUNNEL_PACKAGE)
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    runner.run(["apt-get", "update"], env=env)
    runner.run(["apt-get", "install", "-y"] + packages, env=env)


def stop_conflicting_services(runner):
    step("Disabling anything else that wants the modem")
    found = False
    for name in CONFLICTING_SERVICES:
        probe = subprocess.run(
            ["systemctl", "list-unit-files", "--no-legend", name + ".service"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
        if probe.returncode != 0:
            continue
        lines = probe.stdout.decode("utf-8", "replace").splitlines()
        if not any(line.strip().startswith(name + ".service") for line in lines):
            continue
        found = True
        info("Found %s.service" % name)
        runner.run(["systemctl", "disable", "--now", name], check=False)
    if not found:
        info("Nothing to disable")


NOTABLE_STOCK_OPTIONS = {
    "crtscts": "hardware (RTS/CTS) flow control",
    "modem": "watch the DCD line to detect carrier loss",
    "lock": "create a UUCP lock file on the serial device",
    "asyncmap": "async control character map request",
    "lcp-echo-interval": "LCP keepalive probes",
    "lcp-echo-failure": "LCP keepalive failure threshold",
}


def clear_ppp_options(runner):
    step("Clearing /etc/ppp/options")
    info("pppd reads this file in addition to the peers file, so anything in")
    info("here silently applies on top of our configuration. randnetpi3 keeps")
    info("every option in /etc/ppp/peers/randnet so it cannot leak.")

    try:
        with open(PPP_OPTIONS) as handle:
            existing = [
                line.strip() for line in handle
                if line.strip() and not line.strip().startswith("#")
            ]
    except (IOError, OSError):
        existing = []

    if not existing:
        info("Already empty or absent, nothing to do")
        return

    info("Found %d active directive(s): %s" % (len(existing), ", ".join(existing)))

    if any(line.startswith("record ") for line in existing):
        info("One of them is a `record` capture. If its directory is missing,")
        info("pppd refuses to start at all, which is why this file is cleared.")

    notable = []
    for line in existing:
        keyword = line.split()[0]
        if keyword in NOTABLE_STOCK_OPTIONS:
            notable.append((line, NOTABLE_STOCK_OPTIONS[keyword]))

    if notable:
        print()
        info("Some of these look like Debian's stock defaults:")
        for line, why in notable:
            info("    %-24s %s" % (line, why))
        info("The Randnet setup that is known to work runs without them, so")
        info("they are being removed rather than kept on faith. They are")
        info("preserved in the backup below, and any of them can be put back")
        info("by adding it to extra_options in %s." % CONFIG_DEST)
        print()

    runner.backup(PPP_OPTIONS)
    runner.write(
        PPP_OPTIONS,
        "# Emptied by install_randnetpi3.py\n"
        "# randnetpi3 puts every option in /etc/ppp/peers/randnet instead, so\n"
        "# that it cannot leak into other pppd invocations on this machine.\n"
        "# The previous contents are in the .pre-randnetpi3.* backup alongside.\n",
        mode=0o644,
    )


def import_randnetpi3():

    for directory in (INSTALL_DIR, HERE):
        if not os.path.exists(os.path.join(directory, "randnetpi3.py")):
            continue
        sys.path.insert(0, directory)
        try:
            import randnetpi3
            return randnetpi3
        except ImportError:
            continue
        finally:
            sys.path.pop(0)
    fail("could not import randnetpi3.py")


def parse_server_target(value):

    import ipaddress

    value = (value or "").strip()
    if not value:
        return None, None, "no address given"

    try:
        parsed = ipaddress.IPv4Address(value)
    except ValueError:
        pass
    else:
        if parsed.is_loopback:
            return None, None, ("a loopback address; the console cannot reach "
                                "127.0.0.0/8 on this machine")
        return str(parsed), "address", None

    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        pass
    else:
        return None, None, ("an IPv6 address; the console's stack is IPv4 only")

    labels = value.rstrip(".").split(".")

    if labels and labels[-1].isdigit():
        return None, None, "not a valid IPv4 address"

    if len(labels) < 2:
        return None, None, ("not a valid IPv4 address, and not a qualified "
                            "hostname either (it needs a dot, as in "
                            "randnetdd.ch)")

    randnetpi3 = import_randnetpi3()
    if randnetpi3.HOSTNAME_RE.match(value):
        return value, "hostname", None

    return None, None, "neither an IPv4 address nor a valid hostname"


def validate_server_target(value, source):
    target, _kind, error = parse_server_target(value)
    if error:
        fail("%s is %s: %r" % (source, error, value))
    return target


RANDNET_SERVER_HELP = """\
    The Randnet server answers the console: the service calls and the Randnet
    pages. It runs on a separate machine that every bridge shares, so this asks
    where to find it.

    A hostname such as randnetdd.ch is better than an address. It is resolved
    every time the service starts, so if the server ever moves, only its own DNS
    record changes and this machine picks it up on the next restart.

    Only the service traffic crosses to it. Web browsing is handled by the proxy
    on this machine, so pages you visit never go through the server.
"""


def prompt_for_randnet_server():

    print(RANDNET_SERVER_HELP)

    while True:
        try:
            answer = input("    Hostname or address of the Randnet server: ")
        except EOFError:
            fail("no input available; use --randnet-server HOST")

        if not answer.strip():
            print("    A hostname or address is needed, for example")
            print("    randnetdd.ch or 192.168.1.200.")
            print("    (To serve them from this machine instead, which is only")
            print("     useful for development, re-run with")
            print("     --randnet-server host.)")
            continue

        target, kind, error = parse_server_target(answer)
        if error:
            print("    That is %s. Try again, for example randnetdd.ch." % error)
            continue

        print()
        if kind == "hostname":
            randnetpi3 = import_randnetpi3()
            resolved = randnetpi3.resolve_hostname_a(target)
            if resolved:
                print("      %s currently resolves to %s" % (target, resolved))
                print("      It is re-resolved at every service start, so the")
                print("      server can move without changing this.")
            else:
                print("      %s does not resolve yet." % target)
                print("      That is fine if the DNS record is not set up, but")
                print("      the redirect will not work until it is.")
        else:
            print("      Randnet names will resolve to %s" % target)
            print("      A hostname would let the server move later without")
            print("      reconfiguring this machine.")
        print()
        if ask_yes_no("Is that right?", default=True):
            return target
        print("    Let's try again.\n")


def resolve_redirect_setting(args):

    if args.no_randnet_redirect:
        return "off"

    if args.randnet_server:
        value = args.randnet_server.strip()
        if value.lower() in ("host", "off"):
            return value.lower()
        return validate_server_target(value, "--randnet-server")

    step("The Randnet server")
    if sys.stdin.isatty():
        return prompt_for_randnet_server()

    fail(
        "no terminal to ask which Randnet server to use.\n"
        "  Give it explicitly:   --randnet-server 192.168.1.200\n"
        "  Or, for a development box that runs its own copy:\n"
        "                        --randnet-server host"
    )


def configure_dnsmasq(runner, args, redirect):

    step("Configuring dnsmasq")
    if args.skip_dnsmasq:
        info("Skipped (--skip-dnsmasq)")
        warn("dnsmasq answers the DNS randnetpi3 advertises over IPCP, so the")
        warn("console will have no working resolver unless you configure one.")
        return

    if os.path.exists(DNSMASQ_DROPIN) and not args.force:
        info("%s already exists, leaving it alone (use --force to rewrite)"
             % DNSMASQ_DROPIN)
    else:
        runner.write(DNSMASQ_DROPIN, DNSMASQ_CONF, mode=0o644)
        info("dnsmasq will answer the address randnetpi3 advertises as ms-dns.")
        info("bind-dynamic + except-interface=lo keeps it off loopback, so it")
        info("coexists with systemd-resolved instead of losing port 53 to it.")

    if redirect == "off":
        warn("Randnet hostnames will not be redirected. They resolve upstream,")
        warn("where the domain now belongs to someone else, so console traffic")
        warn("would leave your network.")
    elif redirect == "host":
        info("Randnet hostnames -> this machine, re-detected on every service")
        info("start, so a DHCP lease change cannot leave a stale address.")
    else:
        info("Randnet hostnames -> %s (fixed)" % redirect)

    check_no_hosts_setting()
    resolve_bind_conflicts(runner, find_bind_interfaces_conflicts(),
                           args.fix_dnsmasq_conflicts)

    runner.run(["systemctl", "enable", "dnsmasq"], check=False)
    restarted = runner.run(["systemctl", "restart", "dnsmasq"], check=False) == 0

    if not runner.dry_run and not restarted:
        state = service_state("dnsmasq")
        print()
        for line in dnsmasq_failure_advice():
            warn(line)
        fail("dnsmasq is %s, so the console would have no DNS at all. "
             "Fix that and run this again." % state)


def find_bind_interfaces_conflicts(conf="/etc/dnsmasq.conf",
                                   conf_dir="/etc/dnsmasq.d"):

    ours = os.path.basename(DNSMASQ_DROPIN)
    candidates = []
    if os.path.isfile(conf):
        candidates.append(conf)
    if os.path.isdir(conf_dir):
        for name in sorted(os.listdir(conf_dir)):
            if name.endswith((".dpkg-dist", ".dpkg-old", ".dpkg-new")):
                continue
            if name == ours:
                continue
            candidates.append(os.path.join(conf_dir, name))

    hits = []
    for path in candidates:
        try:
            with open(path) as handle:
                for number, line in enumerate(handle, 1):
                    if line.strip() == "bind-interfaces":
                        hits.append((path, number))
        except (IOError, OSError, UnicodeDecodeError):
            continue
    return hits


def dnsmasq_failure_advice():

    lines = ["dnsmasq did not start. The console gets its resolver from this "
             "machine, so"]
    lines.append("nothing will work until it does.")

    result = subprocess.run(
        ["journalctl", "-u", "dnsmasq", "-n", "40", "--no-pager"],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    log = result.stdout.decode("utf-8", "replace") if result.returncode == 0 else ""

    if "cannot set --bind-interfaces and --bind-dynamic" in log:
        lines.append("")
        lines.append("dnsmasq said: cannot set --bind-interfaces and "
                     "--bind-dynamic")
        lines.append("Another drop-in still sets bind-interfaces. Find it with:")
        lines.append("    grep -rn '^bind-interfaces' /etc/dnsmasq.conf "
                     "/etc/dnsmasq.d/")
    elif "Address already in use" in log:
        lines.append("")
        lines.append("Something already holds port 53. Find it with:")
        lines.append("    sudo ss -lunp | grep :53")
    else:
        lines.append("")
        lines.append("See what it said:")
        lines.append("    journalctl -u dnsmasq -n 30 --no-pager")
    return lines


def package_owning(path):

    if shutil.which("dpkg") is None:
        return None
    result = subprocess.run(["dpkg", "-S", path], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, check=False)
    if result.returncode != 0:
        return None
    first = result.stdout.decode("utf-8", "replace").strip().splitlines()
    if not first:
        return None
    return first[0].split(":", 1)[0].strip() or None


def parse_apt_removals(output):

    return [line.split()[1] for line in output.splitlines()
            if line.startswith("Remv ") and len(line.split()) > 1]


def removal_takes_only(package):

    if shutil.which("apt-get") is None:
        return False
    result = subprocess.run(["apt-get", "-s", "remove", package],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            check=False)
    if result.returncode != 0:
        return False
    removals = parse_apt_removals(result.stdout.decode("utf-8", "replace"))
    return removals == [package]


def resolve_bind_conflicts(runner, hits, fix):

    if not hits:
        return

    warn("bind-interfaces is set in another dnsmasq config file:")
    for path, number in hits:
        warn("    %s line %d" % (path, number))
    warn("dnsmasq refuses to start with both bind-interfaces and bind-dynamic,")
    warn("and only bind-dynamic can pick up ppp0, so that line has to go.")

    if any("ubuntu-fan" in path for path, _ in hits):
        warn("That file belongs to Ubuntu Fan networking, a container overlay")
        warn("feature you are almost certainly not using. Purging it is the")
        warn("durable fix - and it must be purge, not remove, because remove")
        warn("leaves the drop-in behind and dnsmasq still will not start:")
        warn("    sudo apt purge ubuntu-fan")

    if not fix:
        if not runner.dry_run and sys.stdin.isatty():
            print()
            fix = ask_yes_no(
                "Comment out bind-interfaces now? Without it dnsmasq will not "
                "start and the console will have no DNS.", default=True)
            print()
        if not fix:
            warn("Left in place. dnsmasq will fail to start until it is dealt")
            warn("with. To do it by hand:")
            for path, _ in hits:
                warn("    sudo cp %s %s.dpkg-old" % (path, path))
                warn("    sudo sed -i 's/^bind-interfaces/#bind-interfaces/' %s"
                     % path)
            return

    for path, _ in hits:

        owner = package_owning(path)
        if owner == UBUNTU_FAN_PACKAGE and removal_takes_only(owner):

            if runner.run(["apt-get", "purge", "-y", owner],
                          env={"DEBIAN_FRONTEND": "noninteractive"},
                          check=False) == 0:
                info("Purged the %s package, which owned %s" % (owner, path))
                info("Nothing else depended on it. Reinstall with: sudo apt "
                     "install %s" % owner)
                if not os.path.exists(path):
                    continue

                warn("%s outlived the purge; commenting the line as well" % path)
            else:
                warn("Could not purge %s; commenting the line instead" % owner)

        runner.run(["cp", path, path + ".dpkg-old"], check=False)
        runner.run(
            ["sed", "-i",
             "s/^bind-interfaces/#bind-interfaces  # disabled by randnetpi3/",
             path],
            check=False,
        )
        info("Commented bind-interfaces in %s (backup at %s.dpkg-old)"
             % (path, path))
        if owner:
            warn("%s belongs to the %s package. An upgrade may restore it and "
                 "break DNS again." % (path, owner))


def check_no_hosts_setting():

    for path in ("/etc/dnsmasq.conf",):
        try:
            with open(path) as handle:
                active = [
                    line.strip() for line in handle
                    if line.strip() == "no-hosts"
                ]
        except (IOError, OSError):
            continue
        if active:
            info("Note: %s has `no-hosts`, so dnsmasq ignores /etc/hosts." % path)
            info("The address= rules above work regardless. Only remove it if")
            info("you would rather manage names in /etc/hosts.")


def expected_redirect_answer(randnetpi3, cfg, redirect):

    if redirect == "host":
        address = randnetpi3.local_host_address()
        if not address:
            return (None, "this machine",
                    "this machine's address could not be detected")
        return address, "this machine", None

    if randnetpi3.is_ipv4_literal(redirect):
        return redirect, "the Randnet server", None


    if cfg is not None:
        resolved = randnetpi3.resolve_randnet_target(cfg)[0]
    else:
        resolved = randnetpi3.resolve_hostname_a(redirect)

    label = "the Randnet server (%s)" % redirect
    if not resolved:
        return None, label, "%s does not resolve yet" % redirect
    return resolved, label, None


def verify_dns_redirect(redirect="host"):

    step("Verifying the Randnet name redirect")
    name = "www." + RANDNET_DOMAINS[0]

    got = None
    for _ in range(5):
        time.sleep(1.0)
        got = dns_query_a(name)
        if got:
            break

    if not got:
        warn("%s did not resolve through the local dnsmasq." % name)
        warn("Check both services:")
        warn("  systemctl status dnsmasq randnetpi3")
        warn("  journalctl -u randnetpi3 | grep -i randnet")
        return

    info("%s resolves to %s" % (name, got))

    try:
        randnetpi3 = import_randnetpi3()
    except SystemExit:
        return

    cfg = None
    try:
        cfg = randnetpi3.load_config(CONFIG_DEST)
    except SystemExit:
        pass

    expected, label, problem = expected_redirect_answer(randnetpi3, cfg, redirect)
    if problem:
        warn("%s, so this cannot be checked yet." % problem)
        if redirect != "host":
            warn("Publish its DNS record, then restart the service:")
            warn("  sudo systemctl restart randnetpi3")
        return

    if got == expected:
        info("That is %s, as intended." % label)
    else:
        warn("Expected %s (%s). Something else answered:" % (expected, label))
        warn("  sudo %s --config %s --check-dns" % (SCRIPT_DEST, CONFIG_DEST))


def _skip_dns_name(data, off):
    while off < len(data):
        length = data[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += length + 1
    return off


def dns_query_a(name, server="127.0.0.1", port=53, timeout=3.0):

    import random
    import socket
    import struct

    query_id = random.randint(0, 0xFFFF)
    packet = struct.pack(">HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        encoded = label.encode("idna" if not label.isascii() else "ascii")
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


def normalise_line_endings(text):

    return text.replace("\r\n", "\n").replace("\r", "\n")


def install_script(runner):

    source = os.path.join(HERE, "randnetpi3.py")
    with open(source, "r", newline="") as handle:
        original = handle.read()

    content = normalise_line_endings(original)
    if content != original:
        warn("source had CRLF line endings; converted to LF")

    if not content.startswith("#!"):
        warn("randnetpi3.py has no shebang line")

    runner.write(SCRIPT_DEST, content, mode=0o755)


def find_python3():

    for candidate in (shutil.which("python3"), sys.executable, "/usr/bin/python3"):
        if candidate and os.path.isfile(candidate):
            return candidate
    fail("could not find a python3 interpreter to run the service with")


def install_unit(runner):

    source = os.path.join(HERE, "randnetpi3.service")
    with open(source, "r", newline="") as handle:
        content = normalise_line_endings(handle.read())

    python = find_python3()
    if "/usr/bin/python3" not in content:
        warn("the shipped unit does not name an interpreter; leaving it as is")
    elif python != "/usr/bin/python3":
        content = content.replace("/usr/bin/python3", python)
        info("unit will use %s" % python)

    runner.write(UNIT_DEST, content, mode=0o644)


def missing_proxy_sources():
    return [name for name in (PROXY_SCRIPT, PROXY_UNIT)
            if not os.path.exists(os.path.join(HERE, name))]


def validate_proxy_port(args):
    port = args.proxy_port
    if not 1 <= port <= 65535:
        fail("--proxy-port %d is not a TCP port" % port)
    if port == 53:
        fail("--proxy-port 53 is the DNS port, which dnsmasq needs")
    if args.with_wrp and port == args.wrp_port:
        fail("--proxy-port %d is also --wrp-port. They are two different "
             "servers and cannot share a port." % port)
    if port < 1024:
        warn("port %d is privileged. It will work, but ports above 1024 are "
             "the safer habit." % port)
    return port


def render_proxy_unit(template, port, max_bytes, python="/usr/bin/python3"):


    preserve = " ".join("--preserve-agent-for %s" % domain
                        for domain in RANDNET_DOMAINS)
    exec_line = ("ExecStart=%s %s --port %d --max-bytes %d %s"
                 % (python, PROXY_SCRIPT_DEST, port, max_bytes, preserve))
    text, count = re.subn(r"^ExecStart=.*$", lambda _m: exec_line, template,
                          count=1, flags=re.MULTILINE)
    if count != 1:
        fail("could not find the ExecStart line in %s; is it the shipped unit "
             "file?" % PROXY_UNIT)
    return text


def install_proxy(runner, args, port):
    step("Installing the browsing proxy service")

    source = os.path.join(HERE, PROXY_SCRIPT)
    with open(source, "r", newline="") as handle:
        original = handle.read()
    content = normalise_line_endings(original)
    if content != original:
        warn("%s had CRLF line endings; converted to LF" % PROXY_SCRIPT)
    runner.write(PROXY_SCRIPT_DEST, content, mode=0o755)

    with open(os.path.join(HERE, PROXY_UNIT), "r", newline="") as handle:
        template = normalise_line_endings(handle.read())
    runner.write(PROXY_UNIT_DEST,
                 render_proxy_unit(template, port, args.proxy_max_bytes,
                                   find_python3()),
                 mode=0o644)

    info("Listens on port %d, pages capped at %d bytes"
         % (port, args.proxy_max_bytes))
    if port != PROXY_PORT_DEFAULT:
        info("NAT rules follow it: proxy_target_port and transparent_http_port")
        info("in %s are set to %d" % (CONFIG_DEST, port))

    warn("The proxy has no password and listens on every interface, so")
    warn("anything that can reach port %d here can browse through it. That is" % port)
    warn("fine behind a home router. Do not port-forward it from the internet.")


def validate_tls_settings(args, redirect):

    if not args.with_tls:
        return None, None

    if os.path.exists(os.path.join(HERE, STUNNEL_SOURCE)) is False:
        fail("%s is missing from %s, and it is the tunnel's configuration."
             % (STUNNEL_SOURCE, HERE))

    if redirect == "host":
        fail("--with-tls needs a remote server. 'host' means this machine "
             "serves the Randnet names itself, so there is no internet hop to "
             "encrypt.")
    if redirect == "off":
        fail("--with-tls needs a Randnet server to point at, but the redirect "
             "is off.")
    kind = parse_server_target(redirect)[1]
    if kind != "hostname":
        fail("--with-tls needs --randnet-server to be a hostname, not an "
             "address. The tunnel verifies the server's certificate against "
             "the name it connected to, and no certificate authority issues "
             "for a bare address, so %s could never be checked. Use the name "
             "the server's certificate covers." % redirect)

    port = args.tunnel_port
    if not 1 <= port <= 65535:
        fail("--tunnel-port %d is not a TCP port" % port)
    if not 1 <= args.tls_port <= 65535:
        fail("--tls-port %d is not a TCP port" % args.tls_port)

    taken = {53: "DNS", 80: "the console's own HTTP"}
    if not args.no_proxy:
        taken[args.proxy_port] = "the browsing proxy"
    if args.with_wrp:
        taken[args.wrp_port] = "WRP"
    if port in taken:
        fail("--tunnel-port %d is already %s. They cannot share a port."
             % (port, taken[port]))

    return redirect, port


def render_stunnel_config(template, tls_host, tls_port, tunnel_port):

    replacements = (
        (r"^accept\s*=.*$", "accept = 0.0.0.0:%d" % tunnel_port),
        (r"^connect\s*=.*$", "connect = %s:%d" % (tls_host, tls_port)),
        (r"^checkHost\s*=.*$", "checkHost = %s" % tls_host),
    )
    text = template
    for pattern, line in replacements:
        text, count = re.subn(pattern, lambda _m, l=line: l, text, count=1,
                              flags=re.MULTILINE)
        if count != 1:
            fail("could not find %r in %s; is it the shipped file?"
                 % (pattern, STUNNEL_SOURCE))
    return text


def install_tls_tunnel(runner, args, tls_host, tunnel_port):
    step("Installing the TLS tunnel to the Randnet server")

    if (shutil.which("stunnel4") is None and shutil.which("stunnel") is None
            and not runner.dry_run):
        warn("stunnel is not installed, so the tunnel cannot start. Install %s "
             "and rerun, or drop --skip-packages." % STUNNEL_PACKAGE)

    with open(os.path.join(HERE, STUNNEL_SOURCE), "r", newline="") as handle:
        template = normalise_line_endings(handle.read())
    content = render_stunnel_config(template, tls_host, args.tls_port,
                                   tunnel_port)

    if not runner.dry_run:
        os.makedirs(os.path.dirname(STUNNEL_DEST), exist_ok=True)
    runner.backup(STUNNEL_DEST)
    runner.write(STUNNEL_DEST, content, mode=0o644)

    info("Tunnel: console -> this machine (plain) -> %s:%d (TLS)"
         % (tls_host, args.tls_port))
    info("Listening on port %d, where the NAT rule sends servlet traffic"
         % tunnel_port)
    info("The server's certificate is verified against %s; a wrong or "
         "untrusted one is refused" % tls_host)


def enable_tls_tunnel(runner):
    step("Enabling the TLS tunnel at boot")
    runner.run(["systemctl", "daemon-reload"])
    runner.run(["systemctl", "enable", STUNNEL_SERVICE])
    runner.run(["systemctl", "restart", STUNNEL_SERVICE])


def tls_handshake_works(host, port, timeout=10.0):
    import ssl
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                return True, "%s, cert valid for %s" % (tls.version(), host)
    except ssl.SSLCertVerificationError as exc:
        return False, "certificate rejected: %s" % exc.verify_message
    except ssl.SSLError as exc:
        return False, "TLS error: %s" % exc
    except (socket.timeout, socket.gaierror, OSError) as exc:
        return False, "%s: %s" % (type(exc).__name__, exc)


def install_files(runner, secret, redirect, proxy_port=None, tls_host=None,
                  tls_port=None, tunnel_port=None):
    step("Installing files")

    if not runner.dry_run:
        os.makedirs(INSTALL_DIR, exist_ok=True)
        os.chmod(INSTALL_DIR, 0o755)
    info("Install directory: %s" % INSTALL_DIR)

    install_script(runner)

    helper = os.path.join(HERE, "set_chap_key.py")
    if os.path.exists(helper):
        with open(helper, "r", newline="") as handle:
            runner.write(
                os.path.join(INSTALL_DIR, "set_chap_key.py"),
                normalise_line_endings(handle.read()),
                mode=0o755,
            )
    else:
        warn("set_chap_key.py not found; the key can still be changed by hand")

    with open(os.path.join(HERE, "randnetpi3.conf")) as handle:
        template = handle.read()
    content, kind = render_config(template, secret, redirect, proxy_port,
                                  tls_host, tls_port, tunnel_port)
    if kind == "b64":
        info("Key stored base64 encoded (it has whitespace at an edge)")
    else:
        info("Key stored verbatim in chap_secret")

    runner.backup(CONFIG_DEST)
    runner.write(CONFIG_DEST, content, mode=0o640)

    install_unit(runner)


def enable_service(runner):
    step("Enabling the service at boot")
    runner.run(["systemctl", "daemon-reload"])
    runner.run(["systemctl", "enable", "randnetpi3"])
    runner.run(["systemctl", "restart", "randnetpi3"])


def enable_proxy_service(runner):
    step("Enabling the browsing proxy at boot")
    runner.run(["systemctl", "daemon-reload"])
    runner.run(["systemctl", "enable", PROXY_SERVICE])
    runner.run(["systemctl", "restart", PROXY_SERVICE])


def smoke_test(runner):
    step("Smoke testing the installed script")
    if runner.dry_run:
        info("would run: %s --self-test" % SCRIPT_DEST)
        info("would run: %s --config %s --dry-run" % (SCRIPT_DEST, CONFIG_DEST))
        return

    result = subprocess.run(
        [sys.executable, SCRIPT_DEST, "--self-test"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    output = result.stdout.decode("utf-8", "replace")
    if result.returncode != 0:
        print(output)
        fail("randnetpi3 --self-test failed")
    passed = output.count("\n  ok ")
    info("--self-test passed (%d checks)" % passed)

    result = subprocess.run(
        [sys.executable, SCRIPT_DEST, "--config", CONFIG_DEST, "--dry-run"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    if result.returncode != 0:
        print(result.stdout.decode("utf-8", "replace"))
        fail("randnetpi3 --dry-run failed")
    info("--dry-run rendered the PPP configuration without error")


def service_state(name):
    out = subprocess.run(["systemctl", "is-active", name],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                         check=False)
    return out.stdout.decode("utf-8", "replace").strip() or "unknown"


def final_health_check(args, redirect, proxy_port=None, tls_host=None,
                       tunnel_port=None):

    step("Checking the result")
    problems = []

    def report(ok, label, detail=""):
        print("  [%s] %s%s" % ("ok" if ok else "FAIL", label,
                               "  %s" % detail if detail else ""))
        if not ok:
            problems.append(label)

    randnetpi3 = import_randnetpi3()

    state = service_state("randnetpi3")
    report(state == "active", "randnetpi3 service running", state)

    if not args.skip_dnsmasq:
        state = service_state("dnsmasq")
        report(state == "active", "dnsmasq running", state)
    else:
        print("  [--] dnsmasq skipped")

    if proxy_port:
        state = service_state(PROXY_SERVICE)
        report(state == "active", "browsing proxy running", state)
        report(proxy_responds(proxy_port), "browsing proxy answering",
               "http://127.0.0.1:%d/hello" % proxy_port)
    else:
        print("  [--] browsing proxy not installed")

    if tls_host:
        state = service_state(STUNNEL_SERVICE)
        report(state == "active", "TLS tunnel running", state)
        report(port_answers(tunnel_port), "TLS tunnel listening",
               "port %d" % tunnel_port)
        ok, detail = tls_handshake_works(tls_host, args.tls_port)
        report(ok, "server's certificate verifies", detail)
    else:
        print("  [--] TLS tunnel not installed; servlet traffic is plain HTTP")

    try:
        cfg = randnetpi3.load_config(CONFIG_DEST)
        secret = randnetpi3.resolve_chap_secret(cfg)
        report(bool(secret), "CHAP key readable from config",
               "%d characters" % len(secret))
    except SystemExit:
        report(False, "CHAP key readable from config")
        cfg = None

    for path, label in ((SCRIPT_DEST, "randnetpi3.py installed"),
                        (WAV_DEST, "dial tone installed"),
                        (UNIT_DEST, "systemd unit installed")):
        report(os.path.exists(path), label, path)

    if not args.skip_dnsmasq and redirect != "off":
        host = randnetpi3.local_host_address()
        answer = None
        for server in [s for s in ("127.0.0.1", host) if s]:
            answer = randnetpi3.dns_query_a("www.randnet.ne.jp", server=server)
            if answer:
                break

        expected, label, problem = expected_redirect_answer(
            randnetpi3, cfg, redirect)
        if problem:
            warn("%s, so the redirect cannot be verified." % problem)
            if redirect != "host":
                warn("Publish its DNS record, then restart the service:")
                warn("  sudo systemctl restart randnetpi3")

        name = "www." + RANDNET_DOMAINS[0]
        try:
            local = socket.gethostbyname(name)
        except OSError:
            local = None
        report(bool(local), "%s resolves for this machine too" % name,
               local or "no answer; a disk using a proxy cannot load pages")

        if not answer:
            report(False, "Randnet names resolve",
                   "no answer on 127.0.0.1 or %s" % (host or "?"))
        elif expected and answer != expected:
            report(False, "Randnet names resolve to %s" % label,
                   "got %s, expected %s" % (answer, expected))
        else:
            report(True, "Randnet names resolve to %s" % label, answer)

    if args.with_wrp:
        report(wrp_responds(args.wrp_port), "WRP answering",
               "http://127.0.0.1:%d/" % args.wrp_port)
        forward = subprocess.run(["iptables", "-L", "FORWARD", "-n"],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, check=False)
        head = forward.stdout.decode("utf-8", "replace").splitlines()[:1]
        policy_ok = bool(head) and "policy ACCEPT" in head[0]
        report(policy_ok, "iptables FORWARD policy is ACCEPT",
               head[0].strip() if head else "could not read")

    device = randnetpi3.detect_device(cfg) if cfg else None
    if device and os.path.exists(device):
        print("  [ok] modem present  %s" % device)
    else:
        print("  [--] no modem detected yet; randnetpi3 waits for one, so plug")
        print("       it in and it will pick it up with no restart needed")

    return problems


def report_status(runner):
    step("Result")
    if runner.dry_run:
        info("Dry run finished. Nothing was changed.")
        return

    subprocess.run(
        ["systemctl", "--no-pager", "--lines=15", "status", "randnetpi3"],
        check=False,
    )


def randnet_server_next_step(redirect):

    if redirect == "off":
        return ("  * Randnet hostnames are not redirected. They resolve "
                "upstream, off\n    your network.\n")

    if redirect == "host":
        return (
            "  * Randnet hostnames resolve to this machine.\n"
        )

    return (
        "  * Randnet hostnames resolve to %s, so that machine\n"
        "    serves them.\n"
        % redirect
    )


def proxy_next_step(proxy_port):
    if not proxy_port:
        return ("  * No browsing proxy is installed, so the console can reach "
                "the Randnet\n    service but not the web. Port %d is where "
                "its web traffic is sent, so\n    something has to listen "
                "there." % PROXY_PORT_DEFAULT)
    return ("  * The browsing proxy starts at boot as well, on port %d.\n"
            "    Watch it:    journalctl -fu %s\n"
            "    Restart it:  sudo systemctl restart %s\n"
            "    Test it:     curl -s http://127.0.0.1:%d/hello"
            % (proxy_port, PROXY_SERVICE, PROXY_SERVICE, proxy_port))


def tls_next_step(tls_host, tunnel_port):
    if not tls_host:
        return ("  * Servlet traffic to the Randnet server is plain HTTP, so "
                "anyone on\n    the path can read it - including the CHAP key "
                "the server sends back.\n    Reinstall with --with-tls once the "
                "server is set up for it.")
    return ("  * Servlet traffic goes through the TLS tunnel on port %d.\n"
            "    Watch it:    journalctl -fu %s\n"
            "    Restart it:  sudo systemctl restart %s\n"
            "    Check the certificate:\n"
            "      openssl s_client -connect %s:443 -servername %s </dev/null"
            % (tunnel_port, STUNNEL_SERVICE, STUNNEL_SERVICE, tls_host,
               tls_host))


def print_next_steps(runner, secret, redirect="host", problems=None,
                     proxy_port=None, tls_host=None, tunnel_port=None):
    if runner.dry_run or problems:
        return

    kind, _ = secret_storage(secret)
    print("""
%sInstalled.%s randnetpi3 is enabled and will start at boot.

  Watch it:      journalctl -fu randnetpi3
  Restart it:    sudo systemctl restart randnetpi3
  Stop it:       sudo systemctl stop randnetpi3
  Config:        %s
  Preview:       sudo %s --config %s --dry-run
  Change the key: sudo /opt/randnetpi3/set_chap_key.py
  Check DNS:      sudo /opt/randnetpi3/randnetpi3.py --check-dns \\
                       --config /etc/randnetpi3.conf
  WRP (if used):  sudo docker logs wrp / sudo docker restart wrp

Wait for "Listening for a call" in the journal, then cold boot the console and
dial. On the first successful call, confirm the secrets file looks right:

  sudo cat -A /etc/ppp/chap-secrets

Tabs show as ^I and the line ends with $. There must be four columns.

Worth doing next:

  * Pin the addresses. Set local_ip and peer_ip in %s to fixed
    values outside your DHCP pool, otherwise the console's IP moves between
    sessions as the ARP cache changes.
%s
%s
%s
""" % (_BOLD, _RESET, CONFIG_DEST, SCRIPT_DEST, CONFIG_DEST, CONFIG_DEST,
       randnet_server_next_step(redirect), proxy_next_step(proxy_port),
       tls_next_step(tls_host, tunnel_port)))

    if kind == "b64":
        print("  * Your key is stored base64 encoded in chap_secret_b64 because "
              "it has\n    whitespace at an edge. Leave chap_secret empty.\n")


def do_self_test():

    failures = []

    def check(name, got, want):
        if got == want:
            print("  ok   %s" % name)
        else:
            print("  FAIL %s\n         got:  %r\n         want: %r"
                  % (name, got, want))
            failures.append(name)

    sys.path.insert(0, HERE)
    try:
        import randnetpi3
    except ImportError as exc:
        fail("cannot import randnetpi3.py from %s: %s" % (HERE, exc))
    finally:
        sys.path.pop(0)

    with open(os.path.join(HERE, "randnetpi3.conf")) as handle:
        template = handle.read()

    hard_keys = [
        DEFAULT_CHAP_SECRET,       
        "PC#4x!9q",                
        "50%pow3r",               
        "a;b<c>d",                
        'qu"te?!',                
        "back\\sla",              
        "it's-a-k",               
        "pa$$w0rd",
        "sp ace!!",               
        "equal=s?",
        "brack[e]",
        "colon:x1",
        "~^&*()_+",
        "\u00e9\u00e0\u00fc key",  
        " leading",               
        "trailing ",
        "\tboth\t",
    ]

    print("key survives keyboard -> ini -> loader -> chap-secrets")
    for key in hard_keys:
        content, kind = render_config(template, key)

        import tempfile

        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".conf", delete=False, encoding="utf-8"
        )
        try:
            handle.write(content)
            handle.close()
            cfg = randnetpi3.load_config(handle.name)
            got = randnetpi3.resolve_chap_secret(cfg)
        finally:
            os.unlink(handle.name)

        check("round-trip %-14r (%s)" % (key, kind), got, key)

        line = randnetpi3.merge_chap_secrets("", "*", "Randnet", got).splitlines()[-1]
        fields = split_pppd_words(line)
        check("chap-secrets fields %-14r" % key, len(fields), 4)
        check("chap-secrets secret %-14r" % key, fields[2] if len(fields) > 2 else None, key)

    print("storage decisions")
    check("plain for a simple key", secret_storage("K1QU0K@N")[0], "plain")
    check("plain for a key with #", secret_storage("PC#4x!9q")[0], "plain")
    check("plain for a key with a space inside", secret_storage("a b")[0], "plain")
    check("base64 for a leading space", secret_storage(" ab")[0], "b64")
    check("base64 for a trailing tab", secret_storage("ab\t")[0], "b64")
    check(
        "base64 payload decodes",
        base64.b64decode(secret_storage(" ab ")[1]).decode(),
        " ab ",
    )

    print("factory key stays byte-identical in chap-secrets")
    line = randnetpi3.merge_chap_secrets(
        "", "*", "Randnet", DEFAULT_CHAP_SECRET
    ).splitlines()[-1]
    check("no quoting added", line, "*\tRandnet\tK1QU0K@N\t*")

    print("generated dial tone")
    wav = synthesize_dial_tone(seconds=0.5)
    check("RIFF magic", wav[:4], b"RIFF")
    check("WAVE magic", wav[8:12], b"WAVE")
    check("header is exactly 44 bytes", wav.index(b"data") + 8, 44)
    check("sample count matches", len(wav) - 44, 4000)
    check("8 bit unsigned centred", 100 < wav[44] < 160, True)
    check("declared size matches payload",
          int.from_bytes(wav[40:44], "little"), len(wav) - 44)

    print("docker daemon.json merging")
    text, note = merge_docker_daemon_json("")
    check("empty file gets the key", json.loads(text), {"ip-forward-no-drop": True})
    check("reported as added", note, "added")
    text, note = merge_docker_daemon_json(
        '{"log-driver": "journald", "dns": ["1.1.1.1"]}')
    merged = json.loads(text)
    check("existing settings preserved", merged["log-driver"], "journald")
    check("existing lists preserved", merged["dns"], ["1.1.1.1"])
    check("key added alongside", merged["ip-forward-no-drop"], True)
    text, note = merge_docker_daemon_json('{"ip-forward-no-drop": true}')
    check("idempotent", note, "already set")
    check("output is valid JSON", json.loads(text)["ip-forward-no-drop"], True)
    for bad in ("{not json", "[1,2,3]", '"a string"'):
        try:
            merge_docker_daemon_json(bad)
            check("rejects %r" % bad, "accepted", "ValueError")
        except ValueError:
            print("  ok   refuses to clobber %-12r" % bad)

    print("WRP argument handling")
    check("bare number gets a unit", normalise_wrp_delay("3"), ("3s", True))
    check("already a duration is untouched",
          normalise_wrp_delay("2500ms"), ("2500ms", False))
    check("seconds untouched", normalise_wrp_delay("3s"), ("3s", False))
    check("whitespace trimmed", normalise_wrp_delay("  4 "), ("4s", True))
    argv = wrp_run_argv(8081, "html", "gif", "540x384x16", "3s")
    check("publishes to the container's 8080", "8081:8080" in argv, True)
    check("restart policy set", "unless-stopped" in argv, True)
    check("delay carries a unit", argv[argv.index("-s") + 1], "3s")
    check("geometry passed through", argv[argv.index("-g") + 1], "540x384x16")
    check("mode passed through", argv[argv.index("-m") + 1], "html")
    check("image name present", WRP_IMAGE in argv, True)
    check("valid geometry accepted",
          validate_wrp_geometry("540x384x16"), "540x384x16")
    for bad in ("540x384", "540*384*16", "", "axbxc"):
        try:
            validate_wrp_geometry(bad)
            check("rejects geometry %r" % bad, "accepted", "SystemExit")
        except SystemExit:
            print("  ok   rejects geometry %-12r" % bad)

    print("bind-interfaces conflict detection")
    import tempfile as _tf

    probe = _tf.mkdtemp()
    try:
        conf = os.path.join(probe, "dnsmasq.conf")
        with open(conf, "w") as handle:
            handle.write("#bind-interfaces\n#except-interface=\n")
        d = os.path.join(probe, "dnsmasq.d")
        os.makedirs(d)
        check("clean system: nothing found",
              find_bind_interfaces_conflicts(conf, d), [])

        fan = os.path.join(d, "ubuntu-fan")
        with open(fan, "w") as handle:
            handle.write("# fan networking\nbind-interfaces\n"
                         "except-interface=fan-*\n")
        hits = find_bind_interfaces_conflicts(conf, d)
        check("ubuntu-fan detected", [(p, n) for p, n in hits], [(fan, 2)])

        with open(os.path.join(d, os.path.basename(DNSMASQ_DROPIN)), "w") as h:
            h.write("bind-dynamic\nexcept-interface=lo\n")
        check("our own drop-in is not a conflict",
              find_bind_interfaces_conflicts(conf, d), [(fan, 2)])

        with open(fan, "w") as handle:
            handle.write("#bind-interfaces\nexcept-interface=fan-*\n")
        check("commented out is not a conflict",
              find_bind_interfaces_conflicts(conf, d), [])

        with open(os.path.join(d, "ubuntu-fan.dpkg-old"), "w") as handle:
            handle.write("bind-interfaces\n")
        check("dpkg-old backups ignored",
              find_bind_interfaces_conflicts(conf, d), [])
        for suffix in (".bak", ".disabled"):
            with open(os.path.join(d, "other" + suffix), "w") as handle:
                handle.write("bind-interfaces\n")
        found = [os.path.basename(p) for p, _ in
                 find_bind_interfaces_conflicts(conf, d)]
        check("other extensions ARE read by dnsmasq, so flagged",
              sorted(found), ["other.bak", "other.disabled"])

        with open(conf, "w") as handle:
            handle.write("bind-interfaces\n")
        check("dnsmasq.conf itself counts",
              (conf, 1) in find_bind_interfaces_conflicts(conf, d), True)
    finally:
        shutil.rmtree(probe, ignore_errors=True)

    print("dnsmasq base drop-in")
    check("binds dynamically, not 0.0.0.0",
          "bind-dynamic" in DNSMASQ_CONF.split("\n"), True)
    check("never binds loopback (systemd-resolved owns it)",
          "except-interface=lo" in DNSMASQ_CONF.split("\n"), True)
    check("does not forward to itself", "no-resolv" in DNSMASQ_CONF.split("\n"), True)
    check("no redirect baked in (the service owns that)",
          "address=" in DNSMASQ_CONF or "interface-name=" in DNSMASQ_CONF, False)

    print("redirect setting resolution")
    import io as _io
    import types as _types

    def resolve(randnet_server=None, no_redirect=False, typed=None):
        args = _types.SimpleNamespace(randnet_server=randnet_server,
                                      no_randnet_redirect=no_redirect)
        if typed is None:
            return resolve_redirect_setting(args)

        class FakeTTY(_io.StringIO):
            def isatty(self):
                return True

        saved_in, saved_out = sys.stdin, sys.stdout
        sys.stdin = FakeTTY("".join(line + "\n" for line in typed))
        sys.stdout = _io.StringIO()
        try:
            return resolve_redirect_setting(args)
        finally:
            sys.stdin, sys.stdout = saved_in, saved_out

    check("explicit address passes through", resolve("192.168.1.87"), "192.168.1.87")
    check("host keyword", resolve("host"), "host")
    check("off keyword", resolve("off"), "off")
    check("--no-randnet-redirect wins", resolve("192.168.1.87", True), "off")

    print("the interactive question")
    check("asks straight for an address",
          resolve(typed=["192.168.1.200", "y"]), "192.168.1.200")
    check("confirming with bare enter",
          resolve(typed=["10.0.0.5", ""]), "10.0.0.5")
    check("rejecting the address re-asks",
          resolve(typed=["10.0.0.5", "n", "10.0.0.6", "y"]), "10.0.0.6")
    check("a bad address re-asks rather than aborting",
          resolve(typed=["not-an-ip", "192.168.1.999", "192.168.1.200", "y"]),
          "192.168.1.200")
    check("loopback re-asks rather than aborting",
          resolve(typed=["127.0.0.1", "192.168.1.200", "y"]), "192.168.1.200")
    check("an empty answer re-asks, it does not fall back to local",
          resolve(typed=["", "", "192.168.1.200", "y"]), "192.168.1.200")
    check("never returns host from the prompt",
          resolve(typed=["", "192.168.1.200", "y"]) == "host", False)
    check("the flag skips the question entirely",
          resolve("192.168.1.87", typed=["10.0.0.1", "y"]), "192.168.1.87")
    check("host is still reachable by flag", resolve("host"), "host")

    print("no terminal, no flag")
    saved = sys.stdin
    sys.stdin = _io.StringIO("")          
    try:
        resolve_redirect_setting(
            _types.SimpleNamespace(randnet_server=None,
                                   no_randnet_redirect=False))
        check("refuses to guess a server", "returned", "SystemExit")
    except SystemExit:
        print("  ok   refuses to guess a server without a terminal")
    finally:
        sys.stdin = saved

    print("non-fatal target parsing: addresses and hostnames")
    check("address", parse_server_target("192.168.1.200"),
          ("192.168.1.200", "address", None))
    check("whitespace trimmed", parse_server_target(" 10.0.0.5 "),
          ("10.0.0.5", "address", None))
    check("dynamic dns name", parse_server_target("me.duckdns.org"),
          ("me.duckdns.org", "hostname", None))

    for bad in ("192.168.1.999", "192.168.1", "has space.com", "-bad.example",
                "", "a..b"):
        target, kind, error = parse_server_target(bad)
        check("rejects %-16r without exiting" % bad,
              (target, bool(error)), (None, True))

    target, kind, error = parse_server_target("127.0.0.1")
    check("loopback rejected with a reason",
          (target, "loopback" in (error or "")), (None, True))
    target, kind, error = parse_server_target("::1")
    check("IPv6 rejected, and says why",
          (target, "IPv4 only" in (error or "")), (None, True))

    print("redirect setting lands in the config")
    for value in ("host", "off", "192.168.1.87"):
        rendered, _ = render_config(template, "K1QU0K@N", value)
        check("config says randnet_redirect = %s" % value,
              ("randnet_redirect = " + value) in rendered.split("\n"), True)
    rendered, _ = render_config(template, "K1QU0K@N", "host")
    check("exactly one randnet_redirect line",
          len([l for l in rendered.split("\n")
               if l.startswith("randnet_redirect =")]), 1)

    print("a mistyped address must not be taken for a hostname")
    for bad in ("192.168.1.999", "192.168.1", "192.168.1.1.1", "10.0.0.256"):
        target, kind, error = parse_server_target(bad)
        check("%-16r is a bad address, not a name" % bad,
              (target, kind, "IPv4" in (error or "")), (None, None, True))
    for bad in ("not-an-ip", "randnet", "localhostx"):
        target, kind, error = parse_server_target(bad)
        check("%-16r needs a dot" % bad,
              (target, "needs a dot" in (error or "")), (None, True))

    print("--randnet-server validation")
    for bad, why in (
        ("192.168.1.999", "octet out of range"),
        ("not-an-ip", "not numeric"),
        ("192.168.1", "three octets"),
        ("127.0.0.1", "loopback"),
        ("::1", "IPv6"),
    ):
        try:
            resolve(bad)
            check("rejects %s (%s)" % (bad, why), "accepted", "SystemExit")
        except SystemExit:
            print("  ok   rejects %-14s (%s)" % (bad, why))

    print("DNS response parsing")
    import struct as _struct

    def build_response(name, ip, query_id=0x1234, answers=1, rtype=1):
        header = _struct.pack(">HHHHHH", query_id, 0x8180, 1, answers, 0, 0)
        question = b""
        for label in name.split("."):
            question += bytes([len(label)]) + label.encode()
        question += b"\x00" + _struct.pack(">HH", 1, 1)
        body = b""
        for _ in range(answers):
            body += b"\xc0\x0c"  
            octets = bytes(int(part) for part in ip.split("."))
            body += _struct.pack(">HHIH", rtype, 1, 300, len(octets)) + octets
        return header + question + body

    def parse(packet, query_id=0x1234):
        if len(packet) < 12 or _struct.unpack(">H", packet[:2])[0] != query_id:
            return None
        count = _struct.unpack(">H", packet[6:8])[0]
        if not count:
            return None
        off = _skip_dns_name(packet, 12) + 4
        for _ in range(count):
            off = _skip_dns_name(packet, off)
            if off + 10 > len(packet):
                return None
            rtype, _c, _t, rdlength = _struct.unpack(">HHIH", packet[off:off + 10])
            off += 10
            rdata = packet[off:off + rdlength]
            off += rdlength
            if rtype == 1 and rdlength == 4:
                return ".".join(str(byte) for byte in rdata)
        return None

    check("single A record",
          parse(build_response("www.randnet.ne.jp", "192.168.1.99")),
          "192.168.1.99")
    check("deep subdomain",
          parse(build_response("a.b.c.randnet.ne.jp", "10.0.0.1")), "10.0.0.1")
    check("two answers, first wins",
          parse(build_response("randnet.ne.jp", "1.2.3.4", answers=2)), "1.2.3.4")
    check("no answers", parse(build_response("x.randnet.ne.jp", "1.2.3.4",
                                             answers=0)), None)
    check("wrong transaction id ignored",
          parse(build_response("x.randnet.ne.jp", "1.2.3.4", query_id=0x9999)),
          None)
    check("non-A record skipped",
          parse(build_response("x.randnet.ne.jp", "1.2.3.4", rtype=28)), None)
    check("truncated packet", parse(b"\x12\x34"), None)
    check("skip name over a pointer", _skip_dns_name(b"\xc0\x0c\xff", 0), 2)
    check("skip name over labels", _skip_dns_name(b"\x03abc\x00\xff", 0), 5)

    print("config template rewriting")
    content, _ = render_config(template, "PC#4x!9q")
    check("exactly one chap_secret line",
          len([l for l in content.splitlines() if l.startswith("chap_secret =")]), 1)
    check("exactly one chap_secret_b64 line",
          len([l for l in content.splitlines()
               if l.startswith("chap_secret_b64 =")]), 1)
    check("comments preserved", "# Written by" in content or "# randnetpi3" in content,
          True)
    check("other settings untouched", "peers_name = randnet" in content, True)

    print("redirect answer expectations")

    class FakeUltra(object):

        def __init__(self, local=None, resolved=None, target=None):
            self._local = local
            self._resolved = resolved
            self._target = target

        def local_host_address(self):
            return self._local

        def is_ipv4_literal(self, value):
            return bool(re.match(r"^\d+\.\d+\.\d+\.\d+$", value))

        def resolve_hostname_a(self, name):
            return self._resolved

        def resolve_randnet_target(self, cfg):
            return self._target, None, "stub"

    ultra = FakeUltra(target="203.0.113.9")
    expected, label, problem = expected_redirect_answer(
        ultra, {"stub": True}, "dd.randnetdd.ch")
    check("hostname expects an address", expected, "203.0.113.9")
    check("hostname is not compared as a name",
          expected == "dd.randnetdd.ch", False)
    check("a resolving hostname is not a problem", problem, None)
    check("hostname label says which name", "dd.randnetdd.ch" in label, True)
    check("address answer matches a hostname setting",
          "203.0.113.9" == expected, True)

    ultra = FakeUltra(target=None)
    expected, _label, problem = expected_redirect_answer(
        ultra, {"stub": True}, "dd.randnetdd.ch")
    check("unresolved hostname has no expectation", expected, None)
    check("unresolved hostname reports a problem", bool(problem), True)

    ultra = FakeUltra(resolved="198.51.100.7")
    check("without config it falls back to a lookup",
          expected_redirect_answer(ultra, None, "dd.randnetdd.ch")[0],
          "198.51.100.7")

    ultra = FakeUltra()
    check("literal address expects itself",
          expected_redirect_answer(ultra, None, "192.168.1.200")[0],
          "192.168.1.200")

    ultra = FakeUltra(local="192.168.1.50")
    expected, label, problem = expected_redirect_answer(ultra, None, "host")
    check("host expects this machine", expected, "192.168.1.50")
    check("host labels this machine", label, "this machine")
    check("host with an address is not a problem", problem, None)

    ultra = FakeUltra(local=None)
    check("undetectable host address reports a problem",
          bool(expected_redirect_answer(ultra, None, "host")[2]), True)

    print("browsing proxy service")

    unit_template = (
        "[Unit]\nDescription=x\n\n[Service]\n"
        "ExecStart=/usr/bin/python3 /opt/randnetpi3/randnet_proxy.py --port 8080\n"
        "DynamicUser=yes\n\n[Install]\nWantedBy=multi-user.target\n"
    )
    unit = render_proxy_unit(unit_template, 8080, 32768)
    exec_lines = [l for l in unit.splitlines() if l.startswith("ExecStart=")]
    check("exactly one ExecStart line", len(exec_lines), 1)
    check("ExecStart names the installed script",
          PROXY_SCRIPT_DEST in exec_lines[0], True)
    check("ExecStart carries the port", "--port 8080" in exec_lines[0], True)
    check("ExecStart carries the body cap",
          "--max-bytes 32768" in exec_lines[0], True)
    check("ExecStart preserves the console's User-Agent for the Randnet domain",
          "--preserve-agent-for %s" % RANDNET_DOMAINS[0] in exec_lines[0], True)
    check("hardening is preserved", "DynamicUser=yes" in unit, True)
    check("install section is preserved",
          "WantedBy=multi-user.target" in unit, True)

    moved = render_proxy_unit(unit_template, 8090, 65536, "/usr/local/bin/python3")
    moved_exec = [l for l in moved.splitlines() if l.startswith("ExecStart=")][0]
    check("a moved port reaches ExecStart", "--port 8090" in moved_exec, True)
    check("no stale port is left behind", "8080" in moved_exec, False)
    check("a different interpreter is honoured",
          moved_exec.startswith("ExecStart=/usr/local/bin/python3 "), True)

    ports, _ = render_config(template, "PC#4x!9q", "host", 8090)
    check("moved port sets proxy_target_port",
          "proxy_target_port = 8090" in ports, True)
    check("moved port sets transparent_http_port",
          "transparent_http_port = 8090" in ports, True)
    def setting_of(text, key):
        found = re.search(r"^%s\s*=(.*)$" % key, text, re.MULTILINE)
        return found.group(1).strip() if found else None

    default_ports, _ = render_config(template, "PC#4x!9q", "host", 8080)
    check("the default port leaves the config alone",
          setting_of(default_ports, "proxy_target_port"),
          setting_of(template, "proxy_target_port"))
    check("and leaves the transparent port alone too",
          setting_of(default_ports, "transparent_http_port"),
          setting_of(template, "transparent_http_port"))
    untouched, _ = render_config(template, "PC#4x!9q", "host", None)
    check("no proxy leaves the ports alone",
          "transparent_http_port = 8080" in untouched, True)

    def port_args(**kwargs):
        base = dict(proxy_port=8080, wrp_port=WRP_PORT_DEFAULT, with_wrp=False)
        base.update(kwargs)
        return argparse.Namespace(**base)

    def rejects(name, **kwargs):
        try:
            validate_proxy_port(port_args(**kwargs))
            check(name, "accepted", "SystemExit")
        except SystemExit:
            check(name, "SystemExit", "SystemExit")

    check("the default port validates", validate_proxy_port(port_args()), 8080)
    rejects("rejects port 0", proxy_port=0)
    rejects("rejects a port above range", proxy_port=70000)
    rejects("rejects the DNS port", proxy_port=53)
    rejects("rejects sharing WRP's port", proxy_port=8081, with_wrp=True)
    check("allows WRP's port when WRP is not installed",
          validate_proxy_port(port_args(proxy_port=8081)), 8081)

    print("reading what apt would remove")
    isolated = ("Reading package lists...\n"
                "The following packages will be REMOVED:\n"
                "  ubuntu-fan\n"
                "Remv ubuntu-fan [0.12.16+24.04.1]\n")
    check("a lone removal is read as one package",
          parse_apt_removals(isolated), ["ubuntu-fan"])

    dragging = (isolated + "Remv ubuntu-server [1.539]\n"
                           "Remv something-else [2.0]\n")
    check("extra removals are all seen",
          parse_apt_removals(dragging),
          ["ubuntu-fan", "ubuntu-server", "something-else"])
    check("nothing to remove reads as empty",
          parse_apt_removals("Reading package lists...\n"), [])
    check("a bare Remv with no package is ignored",
          parse_apt_removals("Remv\n"), [])
    check("Remv inside other text is not matched",
          parse_apt_removals("  Remv ubuntu-fan\n"), [])

    print("TLS tunnel rendering")

    stunnel_template = (
        "; comment\n"
        "setuid = stunnel4\n"
        "foreground = yes\n"
        "\n[randnet]\n"
        "client = yes\n"
        "accept = 0.0.0.0:8443\n"
        "connect = dd.randnetdd.ch:443\n"
        "delay = yes\n"
        "verifyChain = yes\n"
        "CAfile = /etc/ssl/certs/ca-certificates.crt\n"
        "checkHost = dd.randnetdd.ch\n"
        "sslVersionMin = TLSv1.2\n"
    )
    rendered = render_stunnel_config(stunnel_template, "sv.example.ch", 8443,
                                     9443)
    lines = rendered.splitlines()
    check("one accept line", len([l for l in lines if l.startswith("accept")]), 1)
    check("accept carries the tunnel port",
          "accept = 0.0.0.0:9443" in lines, True)
    check("accept binds all interfaces, not loopback",
          any(l.startswith("accept = 127.0.0.1") for l in lines), False)
    check("connect carries host and port",
          "connect = sv.example.ch:8443" in lines, True)
    check("checkHost follows the host",
          "checkHost = sv.example.ch" in lines, True)
    check("no stale hostname anywhere",
          "randnetdd.ch" in rendered, False)
    check("verification survives rendering",
          "verifyChain = yes" in lines, True)
    check("the CA bundle survives", any("CAfile" in l for l in lines), True)
    check("the minimum version survives",
          "sslVersionMin = TLSv1.2" in lines, True)
    check("foreground survives, so systemd sees it alive",
          "foreground = yes" in lines, True)

    def tls_args(**kwargs):
        base = dict(with_tls=True, tls_port=443, tunnel_port=8443,
                    proxy_port=8080, no_proxy=False, wrp_port=WRP_PORT_DEFAULT,
                    with_wrp=False)
        base.update(kwargs)
        return argparse.Namespace(**base)

    def tls_rejects(name, redirect="dd.randnetdd.ch", **kwargs):
        try:
            validate_tls_settings(tls_args(**kwargs), redirect)
            check(name, "accepted", "SystemExit")
        except SystemExit:
            check(name, "SystemExit", "SystemExit")

    check("a hostname is accepted",
          validate_tls_settings(tls_args(), "dd.randnetdd.ch"),
          ("dd.randnetdd.ch", 8443))
    check("off unless asked for",
          validate_tls_settings(tls_args(with_tls=False), "dd.randnetdd.ch"),
          (None, None))
    tls_rejects("rejects an IPv4 address", redirect="203.0.113.9")
    tls_rejects("rejects 'host'", redirect="host")
    tls_rejects("rejects 'off'", redirect="off")
    tls_rejects("rejects a tunnel port of 0", tunnel_port=0)
    tls_rejects("rejects an out-of-range tunnel port", tunnel_port=70000)
    tls_rejects("rejects an out-of-range tls port", tls_port=0)
    tls_rejects("rejects sharing the browsing proxy's port", tunnel_port=8080)
    tls_rejects("rejects sharing WRP's port", tunnel_port=8081, with_wrp=True)
    tls_rejects("rejects port 80", tunnel_port=80)
    tls_rejects("rejects the DNS port", tunnel_port=53)
    check("WRP's port is free when WRP is absent",
          validate_tls_settings(tls_args(tunnel_port=8081),
                                "dd.randnetdd.ch")[1], 8081)

    print("TLS settings reach the config")
    tls_conf, _ = render_config(template, "PC#4x!9q", "dd.randnetdd.ch", None,
                                "dd.randnetdd.ch", 443, 9443)
    check("randnet_tls turned on", "randnet_tls = yes" in tls_conf, True)
    check("tls host written",
          "randnet_tls_host = dd.randnetdd.ch" in tls_conf, True)
    check("tls port written", "randnet_tls_port = 443" in tls_conf, True)
    check("tunnel port written",
          "randnet_tunnel_port = 9443" in tls_conf, True)
    plain_conf, _ = render_config(template, "PC#4x!9q", "dd.randnetdd.ch")
    check("left alone when the tunnel is not used",
          "randnet_tls = no" in plain_conf, True)

    print()
    if failures:
        print("%d check(s) FAILED" % len(failures))
        return 1
    print("all checks passed")
    return 0


def split_pppd_words(line):

    words = []
    current = ""
    started = False
    quote = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote:
            if char == "\\" and index + 1 < len(line):
                index += 1
                current += line[index]
            elif char == quote:
                quote = None
            else:
                current += char
        elif char == "\\" and index + 1 < len(line):
            index += 1
            current += line[index]
            started = True
        elif char in ("'", '"'):
            quote = char
            started = True
        elif char == "#":
            break
        elif char.isspace():
            if started:
                words.append(current)
            current = ""
            started = False
        else:
            current += char
            started = True
        index += 1
    if started:
        words.append(current)
    return words


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="install_randnetpi3.py",
        description="Install randnetpi3 and enable it at boot.",
    )
    parser.add_argument(
        "--self-test", action="store_true",
        help="verify the CHAP key escaping offline, then exit (no root needed)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="print every action without changing anything",
    )
    parser.add_argument(
        "--chap-secret", metavar="KEY",
        help="use this CHAP key and skip the questions (quote it in the shell)",
    )
    parser.add_argument(
        "--default-key", action="store_true",
        help="use the factory key %s and skip the questions" % DEFAULT_CHAP_SECRET,
    )
    parser.add_argument(
        "--dial-tone", metavar="WAV",
        help="use this dial-tone.wav instead of looking next to the installer "
             "or downloading it",
    )
    parser.add_argument(
        "--no-download", action="store_true",
        help="never fetch dial-tone.wav from the network; generate one instead",
    )
    parser.add_argument(
        "--skip-packages", action="store_true", help="do not run apt-get"
    )
    parser.add_argument(
        "--randnet-server", metavar="ADDR",
        help="address of the shared Randnet server, where %s and all its "
             "subdomains will point. Omit it and the installer asks. Use "
             "'host' to serve them from this machine instead, which is only "
             "useful on a development box." % RANDNET_DOMAINS[0],
    )
    parser.add_argument(
        "--no-randnet-redirect", action="store_true",
        help="do not redirect Randnet hostnames at all (they will resolve "
             "upstream, off your network)",
    )
    parser.add_argument(
        "--skip-dnsmasq", action="store_true", help="do not touch dnsmasq"
    )
    parser.add_argument(
        "--force", action="store_true",
        help="overwrite the dnsmasq drop-in if it already exists",
    )
    parser.add_argument(
        "--no-proxy", action="store_true",
        help="do not install the browsing proxy (%s) as a service. Web "
             "browsing then needs a proxy on port %d from somewhere else, "
             "because the NAT rules send the console's traffic there."
             % (PROXY_SCRIPT, PROXY_PORT_DEFAULT),
    )
    parser.add_argument(
        "--proxy-port", type=int, default=PROXY_PORT_DEFAULT, metavar="PORT",
        help="port the browsing proxy listens on (default %d). The NAT rules "
             "are pointed at whatever is chosen here, so the two cannot drift "
             "apart." % PROXY_PORT_DEFAULT,
    )
    parser.add_argument(
        "--proxy-max-bytes", type=int, default=PROXY_MAX_BYTES_DEFAULT,
        metavar="N",
        help="cap on the page size handed to the console (default %d). The "
             "console has 1.5 MB for a page and a ~2.3 KB/s line, so a large "
             "page is a long wait rather than a better result."
             % PROXY_MAX_BYTES_DEFAULT,
    )
    parser.add_argument(
        "--with-tls", action="store_true",
        help="send the servlet traffic to the Randnet server through a TLS "
             "tunnel instead of plain HTTP. The console still speaks plain "
             "HTTP to this machine, which is unavoidable and harmless: that "
             "link never leaves the box. What gets encrypted is the part that "
             "crosses the internet, which carries the CHAP key. Requires "
             "--randnet-server to be a hostname, and the server to be set up "
             "for TLS already.",
    )
    parser.add_argument(
        "--tls-port", type=int, default=TLS_PORT_DEFAULT, metavar="PORT",
        help="port the Randnet server terminates TLS on (default %d)"
             % TLS_PORT_DEFAULT,
    )
    parser.add_argument(
        "--tunnel-port", type=int, default=TUNNEL_PORT_DEFAULT, metavar="PORT",
        help="local port stunnel listens on (default %d). The NAT rule is "
             "pointed at whatever is chosen here." % TUNNEL_PORT_DEFAULT,
    )
    parser.add_argument(
        "--with-wrp", action="store_true",
        help="also install Docker and run WRP, so the disk's browser can reach "
             "HTTPS sites. Applies the Docker FORWARD fix as part of this.",
    )
    parser.add_argument(
        "--fix-docker-forward", action="store_true",
        help="only apply the Docker FORWARD fix (use when Docker is already "
             "installed and you do not want WRP)",
    )
    parser.add_argument(
        "--wrp-port", type=int, default=WRP_PORT_DEFAULT, metavar="PORT",
        help="port WRP listens on (default %d; 80 and 8080 are taken)"
             % WRP_PORT_DEFAULT,
    )
    parser.add_argument(
        "--wrp-mode", choices=("html", "ismap"), default=WRP_MODE_DEFAULT,
        help="html is simplified markup (~4 KB/page, ~2s); ismap renders the "
             "page as a clickable image (~20 KB, ~9s). Default %s."
             % WRP_MODE_DEFAULT,
    )
    parser.add_argument(
        "--wrp-image-type", choices=("gif", "png", "jpg", "gip"),
        default=WRP_TYPE_DEFAULT,
        help="image format for ismap mode; gif is smallest for text "
             "(default %s)" % WRP_TYPE_DEFAULT,
    )
    parser.add_argument(
        "--wrp-geometry", default=WRP_GEOMETRY_DEFAULT, metavar="WxHxC",
        help="viewport and colours; the disk reports 540x384x64K, and fewer "
             "colours means fewer bytes (default %s)" % WRP_GEOMETRY_DEFAULT,
    )
    parser.add_argument(
        "--wrp-delay", default=WRP_DELAY_DEFAULT, metavar="DURATION",
        help="settle time before the screenshot, a Go duration such as 3s "
             "(default %s)" % WRP_DELAY_DEFAULT,
    )
    parser.add_argument(
        "--fix-dnsmasq-conflicts", action="store_true",
        help="comment out bind-interfaces in other dnsmasq config files "
             "(Ubuntu's ubuntu-fan sets it, and it stops dnsmasq starting). "
             "Backs each file up first. Without this, the conflict is only "
             "reported.",
    )
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    if args.self_test:
        return do_self_test()

    if args.chap_secret is not None and args.default_key:
        fail("--chap-secret and --default-key are mutually exclusive")
    if args.chap_secret is not None and not args.chap_secret:
        fail("--chap-secret cannot be empty")

    print("%srandnetpi3 installer%s" % (_BOLD, _RESET))
    if args.dry_run:
        print("(dry run: nothing will be changed)")

    preflight(args.dry_run)

    secret = choose_chap_secret(args)
    redirect = resolve_redirect_setting(args)

    proxy_port = None
    if not args.no_proxy:
        missing = missing_proxy_sources()
        if missing:
            warn("%s not found in %s, so the browsing proxy will not be "
                 "installed as a service." % (" and ".join(missing), HERE))
            warn("Everything else still works; only web browsing needs it.")
        else:
            proxy_port = validate_proxy_port(args)

    tls_host, tunnel_port = validate_tls_settings(args, redirect)

    runner = Runner(args.dry_run)

    install_packages(runner, args)
    stop_conflicting_services(runner)
    install_files(runner, secret, redirect, proxy_port, tls_host,
                  args.tls_port, tunnel_port)
    if proxy_port:
        install_proxy(runner, args, proxy_port)
    if tls_host:
        install_tls_tunnel(runner, args, tls_host, tunnel_port)
    install_dial_tone(runner, args)
    clear_ppp_options(runner)
    configure_dnsmasq(runner, args, redirect)
    verify_config_round_trip(CONFIG_DEST, secret, args.dry_run)
    smoke_test(runner)
    enable_service(runner)
    if proxy_port:
        enable_proxy_service(runner)
    if tls_host:
        enable_tls_tunnel(runner)

    if redirect != "off" and not args.dry_run and not args.skip_dnsmasq:
        verify_dns_redirect(redirect)

    
    if args.with_wrp:
        install_wrp(runner, args)
    elif args.fix_docker_forward:
        apply_docker_forward_fix(runner)

    problems = ([] if args.dry_run
                else final_health_check(args, redirect, proxy_port, tls_host,
                                        tunnel_port))

    report_status(runner)
    print_next_steps(runner, secret, redirect, problems, proxy_port, tls_host,
                     tunnel_port)

    if problems:
        print("\n%sInstalled, but %d check(s) failed:%s"
              % (_BOLD, len(problems), _RESET))
        for problem in problems:
            print("  - %s" % problem)
        print("\nDiagnose with:")
        print("  sudo %s --config %s --check-dns" % (SCRIPT_DEST, CONFIG_DEST))
        print("  journalctl -u randnetpi3 -n 40 --no-pager")
        if proxy_port:
            print("  journalctl -u %s -n 40 --no-pager" % PROXY_SERVICE)
        if tls_host:
            print("  journalctl -u %s -n 40 --no-pager" % STUNNEL_SERVICE)
        return 1

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        sys.exit(130)
