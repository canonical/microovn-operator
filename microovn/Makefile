DIRNAME := $(shell basename $(CURDIR))
CHARMFILE := microovn_ubuntu@24.04-amd64.charm
OVSDBLIB := lib/charms/microovn/v0/ovsdb.py
TOKENDISTLIB := lib/charms/microcluster_token_distributor/v0/token_distributor.py

build: $(CHARMFILE)

$(TOKENDISTLIB):
	charmcraft fetch-lib microcluster_token_distributor.token_distributor

charm-libs: $(TOKENDISTLIB) $(OVSDBLIB)

$(CHARMFILE): src/charm.py charmcraft.yaml metadata.yaml charm-libs
	charmcraft pack -v

clean:
	charmcraft clean
	rm $(CHARMFILE) -f
