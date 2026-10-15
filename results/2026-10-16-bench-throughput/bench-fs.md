# Bicameral bench - kind=fs

- run: 2026-10-15T09:15:22Z (runid 20261015-171522)
- base: http://127.0.0.1:18000 (build_sha 7cafc8cfac6f65f5) / agent: http://127.0.0.1:18001 / strata_state: ok
- window: 15.0 s per level; client: 1 process, keep-alive HTTP, 16 worker threads per level
- corpus: 32 file(s) x 4096 B pre-written via agent-rw fs.write; every read is fs.read through /agent/invoke
- errors = non-2xx responses + transport failures; req/s = requests started within the window / window length

| concurrency | req/s | p50 ms | p95 ms | p99 ms | mean ms | errors | non2xx | conn | tokens |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1433.7 | 0.68 | 0.72 | 0.84 | 0.69 | 0 | 0 | 0 | 64 |
| 4 | 1378.6 | 2.84 | 4.02 | 4.83 | 2.90 | 0 | 0 | 0 | 168 |
| 16 | 958.9 | 16.43 | 23.23 | 30.43 | 16.67 | 0 | 0 | 0 | 128 |

