# strait demos

Scenarios that run strait in front of three local HTTP backends and drive traffic through it, to show how it behaves under load and when things fail.

Everything runs on localhost and needs only Rust and Python 3 (standard library only).

```bash
demo/run.sh            # all scenarios
demo/run.sh balance    # or just one: balance, least-conn, failover, affinity
```

The script builds strait in release mode, starts backends `a`, `b` and `c` on ports 9101 to 9103, puts strait in front of them on `127.0.0.1:18080`, and runs [`load.py`](load.py) against it. Logs from every process go to `demo/.logs/`.

## Scenarios

| Scenario | What happens | What to look for |
|---|---|---|
| `balance` | Round-robin across three healthy backends. | About a third of the requests on each backend, no errors. |
| `least-conn` | Backend `c` answers 50ms slower. Runs once with round-robin and once with least-conn. | With least-conn, `c` gets a small share and total requests per second go up. |
| `failover` | Backend `b` is stopped at second 2 and started again at second 5. | `b` drops to zero in the timeline and then comes back. Only requests already in flight on `b` when it stopped fail. |
| `affinity` | 40 client IPs with `ip-hash`. Backend `c` is stopped at second 3. | Every IP stays on one backend. When `c` stops, only the clients of `c` move. |

### Sample output

From the `failover` scenario on a laptop:

```
requests  15473  (1934/s)
errors    2

second         a       b       c  errors
     0       640     639     640       0
     1       622     591     613       2
     2       923       0     790       0
     3      1063       0    1063       0
     4       982       0     983       0
     5      1024     232    1024       0
     6       596     595     596       0
     7       618     619     618       0
```

The 2 errors are the requests that were in flight on `b` when it was stopped. An L4 load balancer cannot replay a connection that already exchanged bytes. Every new connection that was routed to `b` after that was retried on `a` or `c` until the health check took `b` out of rotation.

## Tools

These work on their own too, for example against a strait you started by hand.

**[`backend.py`](backend.py)** is an HTTP server that answers every request with its name.

```bash
python3 demo/backend.py --name a --port 9101 [--delay 0.05]
```

**[`load.py`](load.py)** runs concurrent clients for a fixed time and reports requests per backend, errors, latency percentiles and a per-second timeline.

```bash
python3 demo/load.py --target 127.0.0.1:18080 --clients 20 --duration 5 [--sources 40]
```

`--sources` spreads the clients over several source IPs (`127.0.0.2`, `127.0.0.3`, ...) and reports whether each one stayed on the same backend. On Linux the whole `127.0.0.0/8` range is loopback, so this works without extra setup. On macOS only `127.0.0.1` exists by default.
