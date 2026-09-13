# Copyright 2026 Ubuntu
# See LICENSE file for licensing details.

CHARMFILE := interface-consumer_amd64.charm
build: $(CHARMFILE)

lib/charms/microovn/v0/ovsdb.py: ../../lib/charms/microovn/v0/ovsdb.py
	mkdir -p lib/charms/microovn/
	cp -r ../../lib/charms/microovn/v0/ lib/charms/microovn/

poetry.lock: pyproject.toml
	poetry lock

charm-libs: lib/charms/microovn/v0/ovsdb.py

$(CHARMFILE): charm-libs src/charm.py charmcraft.yaml poetry.lock
	charmcraft pack

clean:
	rm -rf lib/charms/microovn/v0
	rm -rf $(CHARMFILE)
	charmcraft clean
