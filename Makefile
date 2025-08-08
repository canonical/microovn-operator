VENV := .venv
PARALLEL ?= 1
TESTSUITEFLAGS ?= ""
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
CHARMS := token-distributor microovn tests/interface-consumer

build:
	for charm in $(CHARMS); do \
		$(MAKE) -C $$charm; \
	done

$(VENV):
	python3 -m venv $(VENV) --upgrade-deps
	$(PIP) install -r tests/requirements.txt

get-consumer-libs:
	$(MAKE) -C tests/interface-consumer charm-libs

check-lint: get-consumer-libs
	tox -e lint

check-static: get-consumer-libs
	tox -e static

check-code: check-lint check-static

check-unit: $(VENV)
	tox -e unit

check-integration: $(VENV)
	./$(VENV)/bin/pytest -v -n $(PARALLEL) tests/integration $(TESTSUITEFLAGS)

check-system: check-integration check-unit

check: check-code check-system

test: $(VENV) check-system
.PHONY: test

clean:
	$(MAKE) -C token-distributor clean
	$(MAKE) -C microovn clean
