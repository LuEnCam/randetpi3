#!/usr/bin/env python3
"""set_chap_key.py - change the Randnet CHAP key after installation.

Reads the key currently in use, asks for a new one, writes it, verifies it
survived, and restarts randnetpi3 so /etc/ppp/chap-secrets is regenerated.

    sudo /opt/randnetpi3/set_chap_key.py                 # interactive
    sudo /opt/randnetpi3/set_chap_key.py --show          # just print the current key
    sudo /opt/randnetpi3/set_chap_key.py --key 'PC#4x!9q'
    sudo /opt/randnetpi3/set_chap_key.py --factory       # back to K1QU0K@N
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(os.path.realpath(__file__)))

CONFIG_DEFAULT = "/etc/randnetpi3.conf"
CHAP_SECRETS = "/etc/ppp/chap-secrets"
SERVICE = "randnetpi3"
INSTALL_DIR = "/opt/randnetpi3"

FACTORY_KEY = "K1QU0K@N"

EXPECTED_LENGTH = 8

KEY_HELP ="""\
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

_BOLD = "\033[1m" if sys.stdout.isatty() else ""
_RESET = "\033[0m" if sys.stdout.isatty() else ""


def fail(message):
    sys.stdout.flush()
    print("\nERROR: %s" % message, file=sys.stderr)
    sys.stderr.flush()
    raise SystemExit(1)


def info(message=""):
    print(message)


def import_randnetpi3():

    for directory in (INSTALL_DIR, HERE):
        if os.path.exists(os.path.join(directory, "randnetpi3.py")):
            sys.path.insert(0, directory)
            try:
                import randnetpi3
                return randnetpi3
            except ImportError:
                pass
            finally:
                sys.path.pop(0)
    fail("could not find randnetpi3.py in %s or %s" % (INSTALL_DIR, HERE))


def secret_storage(secret):

    if secret != secret.strip() or "\n" in secret or "\r" in secret:
        return "b64", base64.b64encode(secret.encode("utf-8")).decode("ascii")
    return "plain", secret


def rewrite_config(text, secret):

    kind, stored = secret_storage(secret)
    plain = stored if kind == "plain" else ""
    encoded = stored if kind == "b64" else ""

    plain_line = ("chap_secret = " + plain) if plain else "chap_secret ="
    b64_line = ("chap_secret_b64 = " + encoded) if encoded else "chap_secret_b64 ="

    text, count = re.subn(r"^chap_secret\s*=.*$", lambda _m: plain_line,
                          text, count=1, flags=re.MULTILINE)
    if count != 1:
        fail("no 'chap_secret =' line found; is this a randnetpi3 config file?")

    text, count = re.subn(r"^chap_secret_b64\s*=.*$", lambda _m: b64_line,
                          text, count=1, flags=re.MULTILINE)
    if count != 1:
        text = re.sub(r"^(chap_secret\s*=.*)$",
                      lambda m: m.group(1) + "\n" + b64_line,
                      text, count=1, flags=re.MULTILINE)

    return text, kind



def describe(secret, randnetpi3, label="  "):
    hexed = " ".join("%02X" % byte for byte in secret.encode("utf-8"))
    print("%scharacters %d" % (label, len(secret)))
    print("%sliteral    [%s]" % (label, secret))
    print("%shex        %s" % (label, hexed))
    print("%sin chap-secrets: *\tRandnet\t%s\t*"
          % (label, randnetpi3.quote_secret(secret)))
    if secret != secret.strip():
        print("%snote       edge whitespace, will be stored base64 encoded" % label)
    if len(secret) != EXPECTED_LENGTH:
        print("%snote       every Randnet key seen so far is %d characters"
              % (label, EXPECTED_LENGTH))


def ask_yes_no(question, default=True):
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        try:
            answer = input("  %s %s " % (question, suffix)).strip().lower()
        except EOFError:
            fail("no input available; use --key KEY or --factory")
        if not answer:
            return default
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("  Please answer y or n.")


def prompt_for_key(current, randnetpi3):
    print(KEY_HELP)
    while True:
        try:
            secret = input("  New CHAP key (Enter to keep the current one): ")
        except EOFError:
            fail("no input available; use --key KEY or --factory")

        if not secret:
            return None  # keep current

        control = [ch for ch in secret if ord(ch) < 32 or ord(ch) == 127]
        if control:
            print("  That contains a control character, which cannot be stored.")
            continue

        if secret == current:
            print("  That is the key already in use.")
            return None

        print()
        describe(secret, randnetpi3, label="    ")
        print()
        if ask_yes_no("Is that exactly right?", default=True):
            return secret
        print("  Let's try again.\n")



def unique_backup_path(config, now=None):

    stamp = time.strftime("%Y%m%d-%H%M%S", now or time.localtime())
    candidate = "%s.chapkey.%s" % (config, stamp)
    if not os.path.exists(candidate):
        return candidate
    for suffix in range(2, 100):
        candidate = "%s.chapkey.%s-%d" % (config, stamp, suffix)
        if not os.path.exists(candidate):
            return candidate
    fail("too many backups for %s in the same second" % config)


def restart_service():
    if shutil.which("systemctl") is None:
        print("  systemctl not found; restart randnetpi3 yourself.")
        return False

    subprocess.run(["systemctl", "reset-failed", SERVICE],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   check=False)

    result = subprocess.run(["systemctl", "restart", SERVICE],
                            stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        print("  FAILED to restart %s: %s" % (
            SERVICE, result.stderr.decode("utf-8", "replace").strip()))
        print("  Check: systemctl status %s" % SERVICE)
        return False

    print("  Restarted %s" % SERVICE)
    return True


def show_installed_secret(expected, randnetpi3):

    for _ in range(5):
        time.sleep(1.0)
        try:
            with open(CHAP_SECRETS) as handle:
                lines = [l.strip() for l in handle if l.strip()
                         and not l.strip().startswith("#")]
        except (IOError, OSError):
            continue
        for line in lines:
            fields = line.split()
            if len(fields) >= 3 and fields[0] == "*":
                rendered = randnetpi3.quote_secret(expected)
                got = fields[2]
                print("  %s contains: %s" % (CHAP_SECRETS, line))
                if got == rendered:
                    print("  Verified: the new key is live.")
                    return True
                print("  Mismatch: expected the secret column to be %s" % rendered)
                return False
    print("  Could not read %s yet. Check: journalctl -u %s -n 20"
          % (CHAP_SECRETS, SERVICE))
    return False



def do_self_test():

    failures = []

    def check(name, got, want):
        if got == want:
            print("  ok   %s" % name)
        else:
            print("  FAIL %s\n         got:  %r\n         want: %r"
                  % (name, got, want))
            failures.append(name)

    randnetpi3 = import_randnetpi3()

    template_path = os.path.join(HERE, "randnetpi3.conf")
    if not os.path.exists(template_path):
        fail("randnetpi3.conf not found next to this script; needed for tests")
    with open(template_path) as handle:
        template = handle.read()

    hard_keys = [
        FACTORY_KEY, "PC#4x!9q", "50%pow3r", "a;b<c>d", 'qu"te?!', "back\\sla",
        "it's-a-k", "pa$$w0rd", "sp ace!!", "equal=s?", "brack[e]", "~^&*()_+",
        " leading", "trailing ", "\tboth\t",
    ]

    print("key survives rewrite -> loader -> chap-secrets")
    import tempfile

    for key in hard_keys:
        content, kind = rewrite_config(template, key)
        handle = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False,
                                             encoding="utf-8")
        try:
            handle.write(content)
            handle.close()
            cfg = randnetpi3.load_config(handle.name)
            got = randnetpi3.resolve_chap_secret(cfg)
        finally:
            os.unlink(handle.name)
        check("round-trip %-13r (%s)" % (key, kind), got, key)

    print("storage decisions")
    check("plain for a simple key", secret_storage(FACTORY_KEY)[0], "plain")
    check("plain for # inside", secret_storage("PC#4x!9q")[0], "plain")
    check("plain for a space inside", secret_storage("a b c")[0], "plain")
    check("base64 for a leading space", secret_storage(" ab")[0], "b64")
    check("base64 for a trailing tab", secret_storage("ab\t")[0], "b64")

    print("config rewriting")
    content, _ = rewrite_config(template, "PC#4x!9q")
    lines = content.split("\n")
    check("one chap_secret line",
          len([l for l in lines if l.startswith("chap_secret =")]), 1)
    check("one chap_secret_b64 line",
          len([l for l in lines if l.startswith("chap_secret_b64 =")]), 1)
    check("comments preserved", "# CHAP credentials" in content, True)
    check("other settings untouched", "peers_name = randnet" in content, True)
    check("idempotent", rewrite_config(content, "PC#4x!9q")[0], content)

    print("older config without a b64 line")
    legacy = "[ppp]\nchap_name = Randnet\nchap_secret = OLDKEY12\npeers_name = x\n"
    upgraded, _ = rewrite_config(legacy, " padded ")
    check("b64 line inserted",
          any(l.startswith("chap_secret_b64 = ") for l in upgraded.split("\n")),
          True)
    check("plain emptied when b64 is used",
          "chap_secret =" in upgraded.split("\n"), True)
    check("inserted directly after chap_secret",
          upgraded.split("\n").index("chap_secret =") + 1,
          next(i for i, l in enumerate(upgraded.split("\n"))
               if l.startswith("chap_secret_b64 = ")))
    check("unrelated keys survive", "peers_name = x" in upgraded.split("\n"), True)

    print("backup naming never overwrites")
    probe_dir = tempfile.mkdtemp()
    try:
        target = os.path.join(probe_dir, "randnetpi3.conf")
        open(target, "w").close()
        fixed = time.localtime(0)
        first = unique_backup_path(target, fixed)
        check("first backup has no suffix", first.endswith("-2"), False)
        open(first, "w").close()
        second = unique_backup_path(target, fixed)
        check("second in the same second is distinct", second != first, True)
        check("second is suffixed", second.endswith("-2"), True)
        open(second, "w").close()
        third = unique_backup_path(target, fixed)
        check("third is distinct again", third not in (first, second), True)
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)

    print("a config that is not ours")
    try:
        rewrite_config("[ppp]\nnothing = here\n", "KEY")
        check("refuses an unrecognised file", "accepted", "SystemExit")
    except SystemExit:
        print("  ok   refuses an unrecognised file")

    print()
    if failures:
        print("%d check(s) FAILED" % len(failures))
        return 1
    print("all checks passed")
    return 0


def build_arg_parser():
    parser = argparse.ArgumentParser(
        prog="set_chap_key.py",
        description="Change the Randnet CHAP key and restart randnetpi3.",
    )
    parser.add_argument("--config", default=CONFIG_DEFAULT,
                        help="config file to edit (default %s)" % CONFIG_DEFAULT)
    parser.add_argument("--key", metavar="KEY",
                        help="set this key without asking (quote it in the shell)")
    parser.add_argument("--factory", action="store_true",
                        help="set the factory key %s, for a disk with no account"
                             % FACTORY_KEY)
    parser.add_argument("--show", action="store_true",
                        help="print the key currently in use and exit")
    parser.add_argument("--no-restart", action="store_true",
                        help="write the config but do not restart the service")
    parser.add_argument("--self-test", action="store_true",
                        help="run offline checks of the escaping, then exit")
    return parser


def main(argv=None):
    args = build_arg_parser().parse_args(argv)

    if args.self_test:
        return do_self_test()

    if args.key is not None and args.factory:
        fail("--key and --factory contradict each other")
    if args.key is not None and not args.key:
        fail("--key cannot be empty")

    randnetpi3 = import_randnetpi3()

    if not os.path.exists(args.config):
        fail("config not found: %s\nIs randnetpi3 installed?" % args.config)

    cfg = randnetpi3.load_config(args.config)
    current = randnetpi3.resolve_chap_secret(cfg)
    stored_as = "chap_secret_b64 (base64)" if \
        cfg.get("ppp", "chap_secret_b64", fallback="").strip() else "chap_secret"

    print("%srandnetpi3 CHAP key%s" % (_BOLD, _RESET))
    print("\nCurrent key")
    print("  source     %s in %s" % (stored_as, args.config))
    describe(current, randnetpi3)

    if args.show:
        return 0

    if os.geteuid() != 0:
        fail("run this with sudo: it edits %s and restarts the service"
             % args.config)

    print()
    if args.factory:
        new_key = FACTORY_KEY if FACTORY_KEY != current else None
        if new_key:
            print("Setting the factory key")
            describe(new_key, randnetpi3)
    elif args.key is not None:
        new_key = args.key if args.key != current else None
        if new_key:
            print("Setting the key given on the command line")
            describe(new_key, randnetpi3)
    else:
        if not sys.stdin.isatty():
            fail("no terminal for the prompt; use --key KEY or --factory")
        new_key = prompt_for_key(current, randnetpi3)

    if new_key is None:
        print("\nKey unchanged. Nothing to do.")
        return 0

    backup = unique_backup_path(args.config)
    shutil.copy2(args.config, backup)
    print("\n  Backed up %s -> %s" % (args.config, backup))

    with open(args.config) as handle:
        original = handle.read()
    content, kind = rewrite_config(original, new_key)

    mode = os.stat(args.config).st_mode & 0o777
    fd = os.open(args.config, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, content.encode("utf-8"))
    finally:
        os.close(fd)
    print("  Wrote %s (mode %o, stored %s)" % (args.config, mode, kind))

    check_cfg = randnetpi3.load_config(args.config)
    written = randnetpi3.resolve_chap_secret(check_cfg)
    if written != new_key:
        shutil.copy2(backup, args.config)
        fail("the key did not survive being written; config restored from backup\n"
             "  expected: %r\n  got:      %r" % (new_key, written))
    print("  Verified: reads back identically")

    if args.no_restart:
        print("\n  --no-restart given. The new key takes effect when you run:")
        print("    sudo systemctl restart %s" % SERVICE)
        return 0

    print("\n  Restarting %s. Any call in progress will be dropped." % SERVICE)
    if not restart_service():
        return 1

    show_installed_secret(new_key, randnetpi3)

    print("\nDone. Cold boot the console and dial to test the new key.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted. Nothing was changed.", file=sys.stderr)
        sys.exit(130)
