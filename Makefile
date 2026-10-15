PY ?= python3

.PHONY: run example check bench

run:       ## start the layer (control :18000, agent :18001)
	$(PY) bicameral/server.py

example:   ## 30-second end-to-end verification demo
	$(PY) examples/quickstart.py

bench:     ## throughput/latency bench against a running instance
	$(PY) scripts/bench.py --base http://127.0.0.1:18000 --agent http://127.0.0.1:18001 \
		--admin-token "$${BICAMERAL_ADMIN_TOKEN:?set BICAMERAL_ADMIN_TOKEN}" \
		--concurrency 1,4,16 --duration 15 --kind fs --out results/bench-local

check: example
