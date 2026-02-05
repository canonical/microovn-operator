# Copyright 2025 Ubuntu
# See LICENSE file for licensing details.

VENV := .venv
PARALLEL ?= 1
TESTSUITEFLAGS ?= ""
CHARMFILE := microovn_ubuntu@24.04-amd64.charm
OVSDBLIB := lib/charms/microovn/v0/ovsdb.py
TOKENDISTLIB := lib/charms/microcluster_token_distributor/v0/token_distributor.py

# Virtual environment
$(VENV): poetry.lock pyproject.toml
	poetry install --extras dev

# Build targets
build: $(CHARMFILE)

$(CHARMFILE): src/charm.py charmcraft.yaml charm-libs
	charmcraft pack -v

build-consumer:
	$(MAKE) -C tests/interface-consumer

build-all: build build-consumer

# Charm libs targets
$(TOKENDISTLIB):
	charmcraft fetch-lib microcluster_token_distributor.token_distributor

charm-libs: $(TOKENDISTLIB) $(OVSDBLIB)

get-consumer-libs:
	$(MAKE) -C tests/interface-consumer charm-libs

get-libs: charm-libs get-consumer-libs

# Check targets
check-lint: get-libs
	tox -e lint

check-code: check-lint

check-unit: get-libs
	tox -e unit

check-integration:
	tox -e integration -- -n $(PARALLEL) $(TESTSUITEFLAGS)

check-system: check-integration check-unit

check: check-code check-system

test: check-system
.PHONY: test

# Clean targets
clean:
	charmcraft clean
	rm -f $(CHARMFILE)
	$(MAKE) -C tests/interface-consumer clean
