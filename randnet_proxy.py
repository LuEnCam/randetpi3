#!/usr/bin/env python3
"""
randnet_proxy.py - plain HTTP in, HTTPS out, for the Randnet disk's browser.

Runs on the dial-up bridge next to randnetpi3.py. The console asks for a page
over ordinary HTTP; this fetches it over TLS and hands back the result. That is
the whole job.
"""

import argparse
import logging
import re
import socket
import socketserver
import ssl
import sys
import urllib.error
import urllib.request

LOG = logging.getLogger("randnet-proxy")

HOST_RE = re.compile(r"\A[A-Za-z0-9._-]+(:[0-9]{1,5})?\Z")

MAX_REQUEST_BYTES = 8192
MAX_HEADER_LINES = 64

LOOP_HEADER = "X-Randnet-Proxy"

REWRITABLE_TYPES = ("text/html", "application/xhtml+xml", "text/plain")

_HTTPS_URL = re.compile(rb"(?i)\bhttps://")

HELLO_BODY = (
    b"Hello from the Randnet proxy.\n"
    b"If the console can read this, TCP and HTTP both work.\n"
)

METHODS = ("GET", "HEAD", "POST")


def downgrade_https(data, ctype, content_encoding=None):

    if content_encoding and content_encoding.strip().lower() != "identity":
        return data, 0

    base = (ctype or "").split(";")[0].strip().lower()
    if base not in REWRITABLE_TYPES:
        return data, 0

    return _HTTPS_URL.subn(b"http://", data)


def split_request_target(target, host_header):

    lowered = (target or "").lower()
    if lowered.startswith("http://") or lowered.startswith("https://"):
        without_scheme = target.split("//", 1)[1]
        host, _, rest = without_scheme.partition("/")
        return host, "/" + rest

    if target and target.startswith("/"):
        return host_header, target

    return None, None


def host_in_suffixes(host, suffixes):
    if not suffixes:
        return False

    name = (host or "").strip().lower()
    if name.startswith("["):
        name = name[1:].split("]", 1)[0]
    elif name.count(":") == 1:
        name = name.split(":", 1)[0]
    name = name.strip(".")
    if not name:
        return False

    for suffix in suffixes:
        wanted = (suffix or "").strip().lower().strip(".")
        if wanted and (name == wanted or name.endswith("." + wanted)):
            return True
    return False


def upstream_candidates(host, path, https_first=True):

    secure = "https://%s%s" % (host, path)
    plain = "http://%s%s" % (host, path)
    return [secure, plain] if https_first else [plain, secure]


class ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    max_bytes = 32768
    upstream_timeout = 20.0
    user_agent = ("Mozilla/5.0 (compatible; RandnetProxy) "
                  "AppleWebKit/537.36 Chrome/120.0 Safari/537.36")
    ssl_context = None
    rewrite_https = True
    https_first = True
    listen_port = 8080
    local_names = frozenset()
    preserve_agent_for = ()


class ProxyHandler(socketserver.StreamRequestHandler):
    timeout = 60

    def handle(self):
        try:
            request = self._read_request()
        except (socket.timeout, OSError) as exc:
            LOG.warning("%s: could not read request: %s", self._peer(), exc)
            return
        if request is None:
            return

        method, target, headers, body = request
        host, path = split_request_target(target, headers.get("host", ""))

        LOG.info("%s: %s %s (Host: %s)", self._peer(), method, target,
                 headers.get("host") or "-")

        if method not in METHODS:
            self._respond(405, "Method Not Allowed",
                          b"Only GET, HEAD and POST are supported.\n")
            return

        if path == "/hello":
            self._respond(200, "OK", HELLO_BODY, "text/plain")
            return

        if not host or not HOST_RE.match(host):
            self._respond(400, "Bad Request",
                          b"A valid Host header or absolute URL is required.\n")
            return

        if headers.get(LOOP_HEADER.lower()):
            LOG.warning("%s: forwarding loop for %s", self._peer(), host)
            self._respond(508, "Loop Detected", b"Forwarding loop detected.\n")
            return

        if self._is_self(host):
            LOG.warning("%s: refusing self-reference to %s", self._peer(), host)
            self._respond(508, "Loop Detected",
                          b"That address is this proxy.\n")
            return

        self._proxy(method, host, path, headers, body)


    def _peer(self):
        try:
            return "%s:%d" % self.client_address
        except Exception:                       
            return "?"

    def _is_self(self, host):

        name, _, port = host.partition(":")
        try:
            port = int(port) if port else 80
        except ValueError:
            return False
        if port != self.server.listen_port:
            return False
        return name.lower() in self.server.local_names

    def _read_request(self):

        total = 0
        line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
        total += len(line)
        if not line:
            return None
        if len(line) > MAX_REQUEST_BYTES:
            self._respond(414, "URI Too Long", b"Request line too long.\n")
            return None

        parts = line.decode("latin-1").rstrip("\r\n").split()
        if len(parts) < 2:
            self._respond(400, "Bad Request", b"Malformed request line.\n")
            return None
        method, target = parts[0].upper(), parts[1]

        headers = {}
        for _ in range(MAX_HEADER_LINES):
            line = self.rfile.readline(MAX_REQUEST_BYTES + 1)
            total += len(line)
            if not line or line in (b"\r\n", b"\n"):
                break
            if total > MAX_REQUEST_BYTES:
                self._respond(431, "Request Header Fields Too Large",
                              b"Too many header bytes.\n")
                return None
            text = line.decode("latin-1").rstrip("\r\n")
            if ":" not in text:
                continue
            name, value = text.split(":", 1)
            headers[name.strip().lower()] = value.strip()

        body = b""
        declared = headers.get("content-length")
        if declared and method == "POST":
            try:
                length = int(declared)
            except ValueError:
                self._respond(400, "Bad Request", b"Bad Content-Length.\n")
                return None
            if length < 0 or length > MAX_REQUEST_BYTES:
                self._respond(413, "Payload Too Large",
                              b"Request body too large.\n")
                return None
            body = self.rfile.read(length)

        return method, target, headers, body

    def _proxy(self, method, host, path, headers, body):
        server = self.server
        attempts = upstream_candidates(host, path, server.https_first)

        result = None
        last_error = None
        for index, url in enumerate(attempts):
            if index:
                LOG.info("%s: retrying %s", self._peer(), url)
            request = urllib.request.Request(
                url, data=body or None, method=method)

            agent = server.user_agent
            if host_in_suffixes(host, server.preserve_agent_for):
                original = headers.get("user-agent")
                if original:
                    agent = original
                    LOG.debug("%s: passing the client's User-Agent to %s",
                              self._peer(), host)
            request.add_header("User-Agent", agent)
            request.add_header("Accept", headers.get("accept", "*/*"))
            request.add_header("Accept-Encoding", "identity")
            request.add_header(LOOP_HEADER, "1")
            for name in ("accept-language", "content-type"):
                if headers.get(name):
                    request.add_header(name, headers[name])

            try:
                with urllib.request.urlopen(
                        request, timeout=server.upstream_timeout,
                        context=server.ssl_context) as response:
                    result = (
                        response.read(server.max_bytes + 1),
                        response.status,
                        response.reason or "OK",
                        response.headers.get("Content-Type", "text/html"),
                        response.headers.get("Content-Encoding"),
                        response.geturl(),
                    )
                break
            except urllib.error.HTTPError as exc:
                result = (
                    exc.read(server.max_bytes + 1) if exc.fp else b"",
                    exc.code,
                    exc.reason or "Error",
                    (exc.headers.get("Content-Type", "text/html")
                     if exc.headers else "text/plain"),
                    exc.headers.get("Content-Encoding") if exc.headers else None,
                    url,
                )
                break
            except (urllib.error.URLError, ssl.SSLError, OSError,
                    ValueError) as exc:
                last_error = exc
                LOG.warning("%s: upstream %s failed: %s", self._peer(), url, exc)

        if result is None:
            self._respond(502, "Bad Gateway",
                          ("Upstream fetch failed: %s\n" % last_error).encode(
                              "utf-8", "replace"))
            return

        body, status, reason, ctype, encoding, final = result

        rewritten = 0
        if server.rewrite_https:
            body, rewritten = downgrade_https(body, ctype, encoding)

        truncated = len(body) > server.max_bytes
        if truncated:
            body = body[:server.max_bytes]

        LOG.info("%s: %s -> %d, %d bytes%s%s%s", self._peer(), final, status,
                 len(body),
                 " (truncated)" if truncated else "",
                 "  %d https link(s) downgraded" % rewritten if rewritten else "",
                 "" if final in attempts else "  via %s" % final)

        if method == "HEAD":
            body = b""
        self._respond(status, reason, body, ctype)

    def _respond(self, status, reason, body, ctype="text/plain"):

        head = (
            "HTTP/1.0 %d %s\r\n"
            "Content-Type: %s\r\n"
            "Content-Length: %d\r\n"
            "Connection: close\r\n"
            "\r\n" % (status, reason, ctype, len(body))
        ).encode("latin-1")
        try:
            self.wfile.write(head)
            if body:
                self.wfile.write(body)
            self.wfile.flush()
        except OSError as exc:
            LOG.warning("%s: client went away: %s", self._peer(), exc)


def local_names():

    names = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]"}
    try:
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.connect(("192.0.2.1", 1))     
            names.add(probe.getsockname()[0].lower())
        finally:
            probe.close()
    except OSError:
        pass
    return frozenset(names)


def do_self_test():

    failures = []

    def check(name, got, want):
        if got == want:
            print("  ok   %s" % name)
        else:
            print("  FAIL %s\n         got:  %r\n         want: %r"
                  % (name, got, want))
            failures.append(name)

    print("which hosts keep the client's User-Agent")
    keep = ("randnetdd.ch",)
    check("the domain itself", host_in_suffixes("randnetdd.ch", keep), True)
    check("a name beneath it",
          host_in_suffixes("dd.randnetdd.ch", keep), True)
    check("deeper still",
          host_in_suffixes("a.b.randnetdd.ch", keep), True)
    check("port ignored",
          host_in_suffixes("dd.randnetdd.ch:8080", keep), True)
    check("case ignored",
          host_in_suffixes("DD.RandnetDD.CH", keep), True)
    check("trailing dot ignored",
          host_in_suffixes("dd.randnetdd.ch.", keep), True)

    check("a different domain that merely ends the same",
          host_in_suffixes("notrandnetdd.ch", keep), False)
    check("our name used as a prefix of someone else's",
          host_in_suffixes("randnetdd.ch.attacker.test", keep), False)
    check("our name in the middle",
          host_in_suffixes("x.randnetdd.ch.evil.test", keep), False)
    check("an unrelated host", host_in_suffixes("example.com", keep), False)

    check("nothing configured means never",
          host_in_suffixes("randnetdd.ch", ()), False)
    check("empty entries are ignored",
          host_in_suffixes("randnetdd.ch", ("", "  ", ".")), False)
    check("no host", host_in_suffixes("", keep), False)
    check("None host", host_in_suffixes(None, keep), False)
    check("several suffixes, second matches",
          host_in_suffixes("dd.randnetdd.ch", ("example.com", "randnetdd.ch")),
          True)
    check("bracketed IPv6 does not match a domain",
          host_in_suffixes("[2001:db8::1]:8080", keep), False)
    check("off by default on the server class",
          ProxyServer.preserve_agent_for, ())

    print("https downgrade")
    cases = [
        (b'<a href="https://n64brew.dev/wiki">w</a>', "text/html", 1),
        (b'<a href="HTTPS://EXAMPLE.COM/x">x</a>', "text/html", 1),
        (b'<base href="https://a.b/"><img src="https://a.b/i.png">',
         "text/html", 2),
        (b'<a href="/rel">r</a><a href="//proto.rel/x">p</a>', "text/html", 0),
        (b'plain https://a and https://b', "text/plain", 2),
        (b'\x89PNG\r\n\x1a\nhttps://x', "image/png", 0),
        (b'{"u":"https://api/x"}', "application/json", 0),
        (b'<a href="https://x/">y</a>', "text/html; charset=Shift_JIS", 1),
    ]
    for body, ctype, want in cases:
        out, count = downgrade_https(body, ctype)
        check("%-30s n=%d" % (ctype, want), count, want)
        if want:
            check("  no https left in %s" % ctype,
                  b"https://" in out.lower(), False)

    check("compressed body untouched",
          downgrade_https(b'<a href="https://x/">', "text/html", "gzip")[1], 0)
    check("identity is not compression",
          downgrade_https(b'<a href="https://x/">', "text/html", "identity")[1],
          1)
    original = b'<a href="https://a/">x</a>' * 3
    shrunk, count = downgrade_https(original, "text/html")
    check("shrinks one byte per rewrite, so Content-Length stays right",
          len(shrunk), len(original) - count)

    print("request target parsing")
    check("origin-form uses the Host header",
          split_request_target("/page", "example.com"),
          ("example.com", "/page"))
    check("absolute-form http",
          split_request_target("http://example.com/page", ""),
          ("example.com", "/page"))
    check("absolute-form https",
          split_request_target("https://example.com/page", ""),
          ("example.com", "/page"))
    check("absolute-form wins over the header",
          split_request_target("http://real.host/p", "ignored.host"),
          ("real.host", "/p"))
    check("absolute-form with no path",
          split_request_target("http://example.com", ""),
          ("example.com", "/"))
    check("absolute-form keeps a port",
          split_request_target("http://example.com:8080/p", ""),
          ("example.com:8080", "/p"))
    check("origin-form keeps the query",
          split_request_target("/p?a=1&b=2", "h"), ("h", "/p?a=1&b=2"))
    check("neither shape", split_request_target("nonsense", ""), (None, None))
    check("empty target", split_request_target("", "h"), (None, None))

    print("host validation")
    for good in ("example.com", "a.b.c.d", "host:8080", "n64brew.dev",
                 "192.168.1.86:80"):
        check("accepts %s" % good, bool(HOST_RE.match(good)), True)
    for bad in ("exa mple.com", "host:99999999", "a/b", "", "host:port",
                "e@vil.com", "host:80/x"):
        check("refuses %r" % bad, bool(HOST_RE.match(bad)), False)

    print("upstream attempt order")
    check("TLS first by default",
          upstream_candidates("h", "/p"),
          ["https://h/p", "http://h/p"])
    check("plain first when asked",
          upstream_candidates("h", "/p", https_first=False),
          ["http://h/p", "https://h/p"])

    print("no reverse-engineered protocol knowledge anywhere in this file")
    forbidden = [
        "serv" "let", "net" "workid", "net" "workpw", "mem" "berid",
        "mem" "berpw", "dis" "kid", "ap" "tel", "mult" "cast", "tic" "ket",
        "mem" "bers.json", "prox" "y01", "disk" "_field", "check" "member",
        "getcommunication" "config", "0x5" "be",
    ]
    with open(__file__, encoding="utf-8") as handle:
        source = handle.read().lower()
    for term in forbidden:
        check("absent: %s" % term, term in source, False)

    print()
    if failures:
        print("%d check(s) FAILED" % len(failures))
        return 1
    print("all checks passed")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description="Plain HTTP in, HTTPS out, for the Randnet disk's browser.")
    ap.add_argument("--port", type=int, default=8080,
                    help="TCP port to listen on (default 8080)")
    ap.add_argument("--bind", default="0.0.0.0",
                    help="address to bind (default all interfaces, so ppp0 is "
                         "covered whenever it comes up)")
    ap.add_argument("--max-bytes", type=int, default=32768,
                    help="cap on the body returned to the console "
                         "(default 32768)")
    ap.add_argument("--timeout", type=float, default=20.0,
                    help="upstream fetch timeout in seconds (default 20)")
    ap.add_argument("--user-agent", default=ProxyServer.user_agent,
                    help="User-Agent sent upstream. Sites that sniff for a "
                         "modern browser serve their normal HTML to this; "
                         "announcing a 1999 browser gets unpredictable results")
    ap.add_argument("--preserve-agent-for", action="append", metavar="HOST",
                    help="send the client's own User-Agent to this host and "
                         "anything beneath it, instead of the one above. ")
    ap.add_argument("--no-rewrite-https", action="store_true",
                    help="do not rewrite https:// to http:// in HTML bodies. "
                         "Rewriting is on by default: the browser has no TLS, "
                         "so an absolute https link is a dead end, and without "
                         "it only the first page of a site is reachable")
    ap.add_argument("--http-first", action="store_true",
                    help="try plain HTTP before TLS. The default is TLS first, "
                         "which is right for almost every site today")
    ap.add_argument("--insecure", action="store_true",
                    help="skip TLS certificate verification. Only for a box "
                         "whose CA bundle is too old for modern sites; it "
                         "makes the upstream fetch spoofable, so fix the CA "
                         "store instead if you can")
    ap.add_argument("--quiet", action="store_true", help="warnings only")
    ap.add_argument("--self-test", action="store_true",
                    help="run offline checks and exit")
    args = ap.parse_args()

    if args.self_test:
        return do_self_test()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    context = ssl.create_default_context()
    if args.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        LOG.warning("TLS certificate verification is DISABLED")

    ProxyServer.max_bytes = args.max_bytes
    ProxyServer.upstream_timeout = args.timeout
    ProxyServer.ssl_context = context
    ProxyServer.user_agent = args.user_agent
    ProxyServer.rewrite_https = not args.no_rewrite_https
    ProxyServer.https_first = not args.http_first
    ProxyServer.listen_port = args.port
    ProxyServer.local_names = local_names()
    ProxyServer.preserve_agent_for = tuple(args.preserve_agent_for or ())
    if ProxyServer.preserve_agent_for:
        LOG.info("passing the client's User-Agent through to: %s",
                 ", ".join(ProxyServer.preserve_agent_for))

    server = ProxyServer((args.bind, args.port), ProxyHandler)
    LOG.info("listening on %s:%d, max body %d bytes, https rewrite %s",
             args.bind, args.port, args.max_bytes,
             "on" if ProxyServer.rewrite_https else "off")
    LOG.warning("open forwarding proxy: it will fetch any URL for anyone who "
                "can reach this port. Keep it off the internet.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        LOG.info("stopping")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
