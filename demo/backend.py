#!/usr/bin/env python3
"""HTTP backend for the strait demos.

Answers every request with its own name, so the load generator can tell which
replica served it. `--delay` makes it slow, to simulate an overloaded replica.
"""

import argparse
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="replica name returned in every response")
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--delay", type=float, default=0.0, help="seconds to wait before answering")
    args = parser.parse_args()

    body = f"{args.name}\n".encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if args.delay:
                time.sleep(args.delay)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Backend", args.name)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_: object) -> None:
            pass

    ThreadingHTTPServer.daemon_threads = True
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"backend {args.name} listening on {args.host}:{args.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
