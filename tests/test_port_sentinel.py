import http.server
import importlib.machinery
import importlib.util
import io
import ipaddress
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr, redirect_stdout

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "port-sentinel")
loader = importlib.machinery.SourceFileLoader("port_sentinel", SCRIPT)
spec = importlib.util.spec_from_loader("port_sentinel", loader)
ps = importlib.util.module_from_spec(spec)
loader.exec_module(ps)

LINUX = sys.platform.startswith("linux")
HEAD = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"


def encode(ip, port):
    """Inverse of decode_address, the way the kernel prints it."""
    packed = ipaddress.ip_address(ip).packed
    words = [struct.unpack("=I", packed[i:i + 4])[0] for i in range(0, len(packed), 4)]
    return "".join("%08X" % w for w in words) + ":%04X" % port


def row(n, ip, port, st, inode, rip=None):
    rip = rip or ("::" if ":" in ip else "0.0.0.0")
    return "%4d: %s %s %s 00000000:00000000 00:00000000 00000000     0        0 %d 1 0000000000000000 100 0 0 10 0\n" % (
        n, encode(ip, port), encode(rip, 0), st, inode)


def fake_proc(tcp=(), tcp6=(), udp=(), udp6=()):
    root = tempfile.mkdtemp(prefix="ps-proc-")
    os.makedirs(os.path.join(root, "net"))
    for name, rows in (("tcp", tcp), ("tcp6", tcp6), ("udp", udp), ("udp6", udp6)):
        with open(os.path.join(root, "net", name), "w") as f:
            f.write(HEAD + "".join(row(i, *r) for i, r in enumerate(rows)))
    return root


def proc(name, pid=100, cmd=None, exe=None):
    return {"pid": pid, "name": name, "comm": name, "exe": exe or name, "cmd": cmd or name}


def listener(port, address="0.0.0.0", proto="tcp", procs=(("sshd",),)):
    return {"proto": proto, "address": address, "port": port, "exposure": ps.exposure(address),
            "processes": [proc(*p) for p in procs]}


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = ps.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class KernelTables(unittest.TestCase):
    def test_decode_real_lines(self):
        self.assertEqual(ps.decode_address("0100007F:1F90"), ("127.0.0.1", 8080))
        self.assertEqual(ps.decode_address("00000000:0016"), ("0.0.0.0", 22))
        self.assertEqual(ps.decode_address("00000000000000000000000001000000:0016"), ("::1", 22))
        self.assertEqual(ps.decode_address("00000000000000000000000000000000:01BB"), ("::", 443))
        self.assertEqual(ps.decode_address("0000000000000000FFFF00000100007F:1F90"), ("127.0.0.1", 8080))

    def test_encode_roundtrip(self):
        for ip in ("10.1.2.3", "8.8.8.8", "2001:db8::42", "fe80::1"):
            self.assertEqual(ps.decode_address(encode(ip, 5353)), (ip, 5353))

    def test_parse_keeps_listen_and_unconnected_udp_only(self):
        text = HEAD + row(0, "0.0.0.0", 22, "0A", 11) + row(1, "10.0.0.5", 22, "01", 12, "10.0.0.9")
        self.assertEqual(ps.parse_table(text, "tcp"), [("tcp", "0.0.0.0", 22, 11)])
        text = HEAD + row(0, "127.0.0.53", 53, "07", 21) + row(1, "10.0.0.5", 40000, "01", 22, "1.1.1.1")
        self.assertEqual(ps.parse_table(text, "udp"), [("udp", "127.0.0.53", 53, 21)])

    def test_exposure(self):
        self.assertEqual(ps.exposure("0.0.0.0"), "public")
        self.assertEqual(ps.exposure("::"), "public")
        self.assertEqual(ps.exposure("127.0.0.1"), "loopback")
        self.assertEqual(ps.exposure("::1"), "loopback")
        self.assertEqual(ps.exposure("192.168.1.10"), "private")
        self.assertEqual(ps.exposure("100.101.1.2"), "private")  # CGNAT / tailscale
        self.assertEqual(ps.exposure("fe80::1"), "private")
        self.assertEqual(ps.exposure("8.8.8.8"), "public")

    def test_collect_groups_and_sorts(self):
        root = fake_proc(tcp=[("0.0.0.0", 443, "0A", 1), ("127.0.0.1", 5432, "0A", 2), ("0.0.0.0", 22, "0A", 3)],
                         tcp6=[("::", 22, "0A", 4)], udp=[("127.0.0.53", 53, "07", 5)])
        got = [(l["proto"], l["address"], l["port"], l["exposure"]) for l in ps.collect(root)]
        self.assertEqual(got, [("tcp", "0.0.0.0", 22, "public"), ("tcp", "::", 22, "public"),
                               ("tcp", "0.0.0.0", 443, "public"), ("tcp", "127.0.0.1", 5432, "loopback"),
                               ("udp", "127.0.0.53", 53, "loopback")])

    def test_collect_without_proc(self):
        with self.assertRaises(ps.Error):
            ps.collect(tempfile.mkdtemp())

    @unittest.skipUnless(LINUX, "needs Linux /proc")
    def test_real_owner_is_this_process(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen()
        try:
            port = s.getsockname()[1]
            mine = [l for l in ps.collect() if l["port"] == port and l["proto"] == "tcp"]
            self.assertEqual(len(mine), 1)
            self.assertEqual(mine[0]["exposure"], "loopback")
            self.assertIn(os.getpid(), [p["pid"] for p in mine[0]["processes"]])
            self.assertTrue(mine[0]["processes"][0]["name"].startswith("python"))
        finally:
            s.close()


class Allowlist(unittest.TestCase):
    def test_parse(self):
        rules = ps.parse_allowlist("""
            # comment
            tcp 22 sshd required        # inline comment
            tcp 80,443,8000-8010 nginx
            tcp 6379 redis* loopback
            any 3000 node cmd=*api* private
            udp * chronyd loopback
        """)
        self.assertEqual(len(rules), 5)
        r = rules[0]
        self.assertEqual((r.proto, r.ports, r.process, r.scope, r.required), ("tcp", ((22, 22),), "sshd", "public", True))
        self.assertEqual(rules[1].ports, ((80, 80), (443, 443), (8000, 8010)))
        self.assertTrue(rules[1].covers("tcp", 8005) and not rules[1].covers("udp", 80))
        self.assertEqual((rules[3].proto, rules[3].cmd, rules[3].scope), ("any", "*api*", "private"))
        self.assertIsNone(rules[4].ports)
        self.assertEqual(rules[1].line, 4)

    def test_errors_name_the_line(self):
        for bad in ("tcp", "sctp 22", "tcp 0", "tcp 22-21", "tcp 70000", "tcp abc", "tcp 22 sshd nginx"):
            with self.assertRaises(ps.Error) as cm:
                ps.parse_allowlist("\n" + bad, "allow.conf")
            self.assertIn("allow.conf:2", str(cm.exception))

    def test_compress_and_format(self):
        self.assertEqual(ps.format_ranges(ps.compress([443, 80, 19133, 19132, 19134])), "80,443,19132-19134")
        self.assertEqual(ps.format_ranges(None), "*")


class Evaluate(unittest.TestCase):
    RULES = ps.parse_allowlist("""
        tcp 22 sshd required
        tcp 80,443 nginx
        tcp 6379 redis-server loopback
        tcp 3000 node cmd=*shop*
        tcp 9000-9100 *
        udp 123 chronyd required
    """)

    def kinds(self, listeners):
        return sorted((p["kind"], p["port"]) for p in ps.evaluate(listeners, self.RULES))

    def base(self):
        return [listener(22), listener(443, procs=[("nginx", 1), ("nginx", 2)]),
                listener(123, "127.0.0.1", "udp", [("chronyd",)])]

    def test_clean(self):
        self.assertEqual(self.kinds(self.base()), [])

    def test_unexpected(self):
        self.assertEqual(self.kinds(self.base() + [listener(2323, procs=[("server",)])]), [("unexpected", 2323)])

    def test_exposure_wider_than_allowed(self):
        probs = ps.evaluate(self.base() + [listener(6379, procs=[("redis-server",)])], self.RULES)
        self.assertEqual([(p["kind"], p["port"]) for p in probs], [("exposure", 6379)])
        self.assertIn("allowed: loopback", probs[0]["message"])
        self.assertEqual(self.kinds(self.base() + [listener(6379, "::1", procs=[("redis-server",)])]), [])

    def test_wrong_program(self):
        probs = ps.evaluate(self.base() + [listener(80, procs=[("python3",)])], self.RULES)
        self.assertEqual(probs[0]["kind"], "process")
        self.assertIn("allowed for nginx, not python3", probs[0]["message"])

    def test_every_program_on_a_socket_must_fit(self):
        self.assertEqual(self.kinds(self.base() + [listener(80, procs=[("nginx",), ("nc",)])]), [("process", 80)])

    def test_unknown_owner(self):
        probs = ps.evaluate(self.base() + [listener(80, procs=[])], self.RULES)
        self.assertIn("run as root", probs[0]["message"])
        self.assertEqual(self.kinds(self.base() + [listener(9050, procs=[])]), [])  # '*' vouches for it

    def test_cmd_glob(self):
        ok = listener(3000, procs=[("node", 5, "node /srv/shop/server.js")])
        bad = listener(3000, procs=[("node", 6, "node /tmp/x.js")])
        self.assertEqual(self.kinds(self.base() + [ok]), [])
        self.assertEqual(self.kinds(self.base() + [bad]), [("process", 3000)])

    def test_exe_name_also_matches(self):
        l = listener(22)
        l["processes"][0]["name"] = l["processes"][0]["comm"] = "sshd: /usr/sbin"
        self.assertEqual(self.kinds([l, self.base()[1], self.base()[2]]), [])

    def test_missing_required(self):
        probs = ps.evaluate(self.base()[1:], self.RULES)
        self.assertEqual([p["kind"] for p in probs], ["missing"])
        self.assertIn("tcp 22 sshd", probs[0]["message"])

    def test_diff(self):
        a = ps.evaluate(self.base() + [listener(2323, procs=[("server",)])], self.RULES)
        b = ps.evaluate(self.base() + [listener(6703, procs=[("server",)])], self.RULES)
        new, resolved = ps.diff({p["key"]: p for p in a}, b)
        self.assertEqual([p["port"] for p in new], [6703])
        self.assertEqual([p["port"] for p in resolved], [2323])
        self.assertEqual(ps.diff({p["key"]: p for p in b}, b), ([], []))


class InitRoundTrip(unittest.TestCase):
    def test_init_output_allows_everything_it_saw(self):
        seen = [listener(22), listener(22, "::"), listener(80, procs=[("nginx",)]), listener(443, procs=[("nginx",)]),
                listener(5432, "127.0.0.1", procs=[("postgres",)]), listener(10101, "0.0.0.0", "udp", [("node",)]),
                listener(10102, "0.0.0.0", "udp", [("node",)]), listener(45123, "0.0.0.0", "udp", [("node",)]),
                listener(8080, procs=[]), listener(7000, procs=[("a",), ("b",)])]
        text = ps.build_allowlist(seen, "web1", (32768, 60999))
        lines = [" ".join(l.split()) for l in text.splitlines() if not l.startswith("#")]
        self.assertIn("tcp 80,443 nginx", lines)
        self.assertIn("tcp 5432 postgres loopback", lines)
        self.assertIn("udp 10101-10102 node", lines)
        self.assertIn("udp 32768-60999 node # ephemeral ports: client sockets", lines)
        rules = ps.parse_allowlist(text)
        self.assertEqual(ps.evaluate(seen, rules), [])
        # and it is tight: redis appearing later is not covered, postgres going public is caught
        later = seen + [listener(6379, procs=[("redis-server",)]), listener(5432, "0.0.0.0", procs=[("postgres",)])]
        self.assertEqual(sorted(p["kind"] for p in ps.evaluate(later, rules)), ["exposure", "unexpected"])


class Programs(unittest.TestCase):
    def test_script_of(self):
        cases = {
            "node /opt/app/src/index.js": "/opt/app/src/index.js",
            "/usr/bin/node --max-old-space-size=512 /srv/api/server.js --port 3000": "/srv/api/server.js",
            "node /root/MY BOTS/MUSIC SERVER/index.js": "/root/MY BOTS/MUSIC SERVER/index.js",
            "python3 -u manage.py runserver": "manage.py",
            "node": None,
        }
        for cmd, want in cases.items():
            name = "python3" if cmd.startswith("python") else "node"
            self.assertEqual(ps.script_of(proc(name, cmd=cmd)), want, cmd)
        self.assertIsNone(ps.script_of(proc("nginx", cmd="nginx: worker process")))

    def test_cmd_glob_survives_spaces(self):
        p = proc("node", cmd="node /root/MY BOTS/MUSIC SERVER/index.js")
        glob = ps.cmd_glob(ps.script_of(p))
        self.assertNotIn(" ", glob)
        rule = ps.parse_allowlist("tcp 8090 node cmd=%s" % glob)[0]
        self.assertTrue(rule.owns([p]))
        self.assertFalse(rule.owns([proc("node", cmd="node /root/other/index.js")]))

    def test_init_separates_node_apps(self):
        a = listener(8084, procs=[("node", 1, "node /opt/game/tcp.js")])
        b = listener(10200, procs=[("node", 2, "node /opt/game/chat server.js")])
        rules = ps.parse_allowlist(ps.build_allowlist([a, b], "h"))
        self.assertEqual([r.cmd for r in rules], ["*/opt/game/tcp.js*", "*/opt/game/chat?server.js*"])
        swapped = listener(8084, procs=[("node", 3, "node /tmp/evil.js")])
        self.assertEqual([p["kind"] for p in ps.evaluate([swapped, b], rules)], ["process"])


class Notify(unittest.TestCase):
    EVENT = {"text": "x" * 3000, "host": "web1"}

    def test_payload_shapes(self):
        url, body, ctype = ps.payload("https://discord.com/api/webhooks/1/abc", self.EVENT)
        body = json.loads(body)
        self.assertLessEqual(len(body["content"]), ps.DISCORD_LIMIT)
        self.assertEqual(body["allowed_mentions"], {"parse": []})
        url, body, _ = ps.payload("https://hooks.slack.com/services/T/B/x", self.EVENT)
        self.assertIn("text", json.loads(body))
        url, body, _ = ps.payload("https://api.telegram.org/bot1:AA/sendMessage?chat_id=-100", self.EVENT)
        self.assertEqual(url, "https://api.telegram.org/bot1:AA/sendMessage")
        self.assertEqual(json.loads(body)["chat_id"], "-100")
        with self.assertRaises(ps.Error):
            ps.payload("https://api.telegram.org/bot1:AA/sendMessage", self.EVENT)
        url, body, ctype = ps.payload("https://ntfy.sh/my-topic", self.EVENT)
        self.assertTrue(ctype.startswith("text/plain"))
        url, body, ctype = ps.payload("https://example.org/hook", self.EVENT)
        self.assertEqual(json.loads(body), self.EVENT)

    def test_redact_hides_tokens(self):
        self.assertEqual(ps.redact("https://discord.com/api/webhooks/1/SECRET"), "https://discord.com/...")
        self.assertEqual(ps.redact("exec:/usr/bin/mail -s x root"), "exec:/usr/bin/mail")

    def test_http_and_exec_delivery(self):
        got = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(204)
                self.end_headers()

            def log_message(self, *a):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        out = os.path.join(tempfile.mkdtemp(), "event.json")
        copy = "import sys; open(sys.argv[1], 'wb').write(sys.stdin.buffer.read())"
        exec_target = 'exec:"%s" -c "%s" "%s"' % (sys.executable, copy, out)
        try:
            new = [ps.problem("unexpected", "tcp", "0.0.0.0", 2323, "server", "no rule allows tcp/2323")]
            ok = ps.notify(["http://127.0.0.1:%d/hook" % srv.server_port, exec_target], "web1", new, [], new)
        finally:
            srv.shutdown()
            srv.server_close()
        self.assertTrue(ok)
        self.assertEqual(got[0]["host"], "web1")
        self.assertIn("2323", got[0]["text"])
        with open(out) as f:
            self.assertEqual(json.load(f)["new"][0]["port"], 2323)

    def test_failure_is_reported_not_raised(self):
        err = io.StringIO()
        with redirect_stderr(err):
            ok = ps.notify(["http://127.0.0.1:1/SECRET", "exec:exit 3"], "h", [], [], [])
        self.assertFalse(ok)
        self.assertNotIn("SECRET", err.getvalue())
        self.assertEqual(err.getvalue().count("failed"), 2)


class Probe(unittest.TestCase):
    def test_reachable_and_unreachable(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        s.listen()
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()
        try:
            port = s.getsockname()[1]
            found = ps.scan_ports(socket.AF_INET, "127.0.0.1", [port, closed_port], 1.0, 4)
            self.assertEqual(found, [port])
            rules = ps.parse_allowlist("tcp %d * required\ntcp %d * loopback" % (closed_port, port))
            probs = ps.probe_problems("127.0.0.1", [port, closed_port], found, rules)
            self.assertEqual(sorted(p["kind"] for p in probs), ["reachable", "unreachable"])
            self.assertIn("allowed only as loopback", [p for p in probs if p["kind"] == "reachable"][0]["message"])
        finally:
            s.close()

    def test_lan_counts_private_rules(self):
        rules = ps.parse_allowlist("tcp 8080 * private")
        self.assertEqual(len(ps.probe_problems("10.0.0.2", [8080], [8080], rules)), 1)
        self.assertEqual(ps.probe_problems("10.0.0.2", [8080], [8080], rules, lan=True), [])


class Cli(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="ps-cli-")
        self.allow = os.path.join(self.tmp, "allow.conf")
        self.state = os.path.join(self.tmp, "state.json")
        self.proc = fake_proc(tcp=[("0.0.0.0", 22, "0A", 1), ("127.0.0.1", 5432, "0A", 2)],
                              udp=[("127.0.0.53", 53, "07", 3)])

    def test_init_check_state_cycle(self):
        code, out, _ = run("init", "--proc", self.proc, "--allow", self.allow)
        self.assertEqual(code, 0)
        self.assertIn("wrote", out)
        self.assertEqual(run("init", "--proc", self.proc, "--allow", self.allow)[0], 2)  # no silent overwrite
        code, out, _ = run("check", "--proc", self.proc, "--allow", self.allow, "--state", self.state)
        self.assertEqual((code, out.strip()), (0, "ok: 3 listening sockets, all allowed"))

        # a port comes back: check fails, the state remembers it
        grown = fake_proc(tcp=[("0.0.0.0", 22, "0A", 1), ("127.0.0.1", 5432, "0A", 2), ("0.0.0.0", 2323, "0A", 4)],
                          udp=[("127.0.0.53", 53, "07", 3)])
        code, out, _ = run("check", "--proc", grown, "--allow", self.allow, "--state", self.state, "--json")
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out)["problems"][0]["port"], 2323)
        with open(self.state) as f:
            self.assertEqual(len(json.load(f)["problems"]), 1)

        # alerts only on change: a notify target that always fails is not even tried the second time
        code, _, err = run("check", "--proc", grown, "--allow", self.allow, "--state", self.state,
                           "--notify", "exec:exit 1")
        self.assertEqual((code, err), (1, ""))
        code, _, err = run("check", "--proc", self.proc, "--allow", self.allow, "--state", self.state,
                           "--notify", "exec:exit 1", "-q")
        self.assertEqual(code, 0)
        self.assertIn("failed", err)  # the "resolved" alert was tried, failed, so the state stays
        with open(self.state) as f:
            self.assertEqual(len(json.load(f)["problems"]), 1)

    def test_scan_with_status(self):
        with open(self.allow, "w") as f:
            f.write("tcp 22 *\nudp 53 * loopback\ntcp 443 * required\n")
        code, out, _ = run("scan", "--proc", self.proc, "--allow", self.allow)
        self.assertEqual(code, 0)
        self.assertIn("UNEXPECTED: no rule allows tcp/5432", out)
        self.assertIn("MISSING", out)
        code, out, _ = run("scan", "--proc", self.proc, "--allow", self.allow, "--json")
        data = json.loads(out)
        self.assertEqual([l["status"] for l in data["listeners"]], ["ok", "unexpected", "ok"])
        self.assertEqual(len(data["missing"]), 1)

    def test_watch_once(self):
        with open(self.allow, "w") as f:
            f.write("tcp 22 *\n")
        code, out, _ = run("watch", "--proc", self.proc, "--allow", self.allow, "--once")
        self.assertEqual(code, 1)
        self.assertIn("+ UNEXPECTED", out)

    def test_errors_exit_2(self):
        self.assertEqual(run("check", "--proc", self.proc, "--allow", os.path.join(self.tmp, "nope"))[0], 2)
        self.assertEqual(run("probe", "127.0.0.1", "--ports", "0")[0], 2)
        self.assertEqual(run()[0], 2)


if __name__ == "__main__":
    unittest.main()
