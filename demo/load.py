#!/usr/bin/env python3
"""Load generator for the strait demos.

Runs concurrent clients against a target for a fixed duration and reports which
backend answered each request, errors, latency percentiles, a per-second
timeline and, with --sources, whether each client IP stayed on one backend.
"""

import argparse
import os
import re
import socket
import threading
import time
from collections import Counter, defaultdict
from dataclasses import dataclass


@dataclass
class Result:
    at: float
    source: str
    backend: str | None
    latency: float


def request(
    target: tuple[str, int], source: str | None, timeout: float, pattern: re.Pattern | None
) -> str:
    """Sends one HTTP/1.0 GET and returns the backend name from the response body.

    Without `pattern` the whole body is the name; with it, the first capture group.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        if source:
            sock.bind((source, 0))
        sock.connect(target)
        sock.sendall(b"GET / HTTP/1.0\r\nHost: strait-demo\r\n\r\n")
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
            # Stop once the body is complete instead of waiting for the server to
            # close, which some proxies (kubectl port-forward) take a second to relay.
            head, sep, body = data.partition(b"\r\n\r\n")
            length = re.search(rb"(?im)^content-length:\s*(\d+)", head)
            if sep and length and len(body) >= int(length.group(1)):
                break

    head, _, body = data.partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.0 200") and not head.startswith(b"HTTP/1.1 200"):
        raise ConnectionError(head.split(b"\r\n", 1)[0].decode(errors="replace") or "empty response")
    text = body.decode()
    if pattern:
        match = pattern.search(text)
        if not match:
            raise ConnectionError("backend name not found in response")
        return match.group(1)
    return text.strip()


def client(target, source, deadline, timeout, pattern, results, lock) -> None:
    while time.monotonic() < deadline:
        start = time.monotonic()
        try:
            backend = request(target, source, timeout, pattern)
        except OSError:
            backend = None
        result = Result(start, source or "127.0.0.1", backend, time.monotonic() - start)
        with lock:
            results.append(result)


def percentile(values: list[float], p: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, round(p / 100 * (len(ordered) - 1)))
    return ordered[index]


def report(results: list[Result], started: float, duration: float, sources: int) -> None:
    ok = [r for r in results if r.backend]
    errors = len(results) - len(ok)
    backends = sorted({r.backend for r in ok})

    # Pod names share a long prefix (web-5fdc855b45-); show only what differs.
    prefix = os.path.commonprefix(backends) if len(backends) > 1 else ""
    label = {b: b[len(prefix):] or b for b in backends}
    width = max([8] + [len(name) + 2 for name in label.values()])

    print(f"\nrequests  {len(results)}  ({len(results) / duration:.0f}/s)")
    print(f"errors    {errors}")
    if ok:
        latencies = [r.latency * 1000 for r in ok]
        print(
            "latency   "
            f"p50 {percentile(latencies, 50):.1f}ms  "
            f"p95 {percentile(latencies, 95):.1f}ms  "
            f"p99 {percentile(latencies, 99):.1f}ms"
        )

    print("\nbackend   requests   share")
    counts = Counter(r.backend for r in ok)
    for backend in backends:
        print(f"{backend:<9} {counts[backend]:>8}   {counts[backend] / len(results):>5.1%}")

    if prefix:
        print(f"\ntimeline columns drop the shared prefix {prefix!r}")
    print("\nsecond  " + "".join(f"{label[b]:>{width}}" for b in backends) + "  errors")
    timeline: dict[int, Counter] = defaultdict(Counter)
    for r in results:
        timeline[int(r.at - started)][r.backend or "error"] += 1
    for second in range(int(duration)):
        row = timeline[second]
        print(f"{second:>6}  " + "".join(f"{row[b]:>{width}}" for b in backends) + f"  {row['error']:>6}")

    if sources:
        # Distinct backends per client IP, in the order they were first used.
        path: dict[str, list[str]] = defaultdict(list)
        for r in sorted(ok, key=lambda r: r.at):
            if r.backend not in path[r.source]:
                path[r.source].append(r.backend)
        moved = {s: p for s, p in path.items() if len(p) > 1}
        origins = Counter(p[0] for p in moved.values())
        summary = ", ".join(f"{n} from {b}" for b, n in sorted(origins.items()))
        print(f"\naffinity  {len(path)} client IPs, {len(moved)} switched backend" + (f" ({summary})" if moved else ""))
        for source in sorted(moved, key=socket.inet_aton):
            print(f"          {source}: {' -> '.join(moved[source])}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="127.0.0.1:18080", help="host:port of strait")
    parser.add_argument("--clients", type=int, default=20, help="concurrent clients")
    parser.add_argument("--duration", type=float, default=5, help="seconds to run")
    parser.add_argument("--timeout", type=float, default=5, help="per-request timeout in seconds")
    parser.add_argument(
        "--sources",
        type=int,
        default=0,
        help="spread clients over this many source IPs (127.0.0.2, 127.0.0.3, ...)",
    )
    parser.add_argument(
        "--backend-pattern",
        help="regex whose first group is the backend name, e.g. 'Hostname: (\\S+)'",
    )
    args = parser.parse_args()
    pattern = re.compile(args.backend_pattern) if args.backend_pattern else None

    host, port = args.target.rsplit(":", 1)
    target = (host, int(port))
    results: list[Result] = []
    lock = threading.Lock()
    started = time.monotonic()
    deadline = started + args.duration

    threads = []
    for i in range(args.clients):
        source = f"127.0.0.{2 + i % args.sources}" if args.sources else None
        thread = threading.Thread(
            target=client,
            args=(target, source, deadline, args.timeout, pattern, results, lock),
            daemon=True,
        )
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()

    report(results, started, args.duration, args.sources)


if __name__ == "__main__":
    main()
