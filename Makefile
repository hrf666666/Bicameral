PY ?= python3

.PHONY: run example check

run:       ## start the layer (control :18000, agent :18001)
	$(PY) bicameral/server.py

example:   ## 30-second end-to-end verification demo
	$(PY) examples/quickstart.py

check: example
