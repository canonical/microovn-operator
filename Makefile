# Copyright 2026 Ubuntu
# See LICENSE file for licensing details.

PARALLEL ?= 0
TESTSUITEFLAGS ?= ""
CHARMFILE := microovn_ubuntu@24.04-amd64.charm
OVSDBLIB := lib/charms/microovn/v0/ovsdb.py
TOKENDISTLIB := lib/charms/microcluster_token_distributor/v0/token_distributor.py
SRC_FILES := src/charm.py src/constants.py src/snap_manager.py src/utils.py

# Build targets
build: $(CHARMFILE)

$(CHARMFILE): charmcraft.yaml charm-libs $(SRC_FILES)
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
