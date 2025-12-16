VENV := .venv
PARALLEL ?= 1
TESTSUITEFLAGS ?= ""
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
CHARMS := microovn tests/interface-consumer

build:
	for charm in $(CHARMS); do \
		$(MAKE) -C $$charm; \
	done

$(VENV):
	python3 -m venv $(VENV) --upgrade-deps
	$(PIP) install -r tests/requirements.txt

get-microovn-libs:
	$(MAKE) -C microovn charm-libs

get-consumer-libs:
	$(MAKE) -C tests/interface-consumer charm-libs

get-libs: get-microovn-libs get-consumer-libs

check-lint: get-libs 
	tox -e lint

check-code: check-lint

check-unit: get-libs
	tox -e unit

check-integration: $(VENV)
	./$(VENV)/bin/pytest -v -n $(PARALLEL) --ignore=tests/unit $(TESTSUITEFLAGS)

check-system: check-integration check-unit

check: check-code check-system

test: $(VENV) check-system
.PHONY: test

clean:
	for charm in $(CHARMS); do \
		$(MAKE) -C $$charm clean; \
	done
