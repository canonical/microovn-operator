DIRNAME := $(shell basename $(CURDIR))
CHARMFILE := microovn_ubuntu-22.04-amd64.charm 

build: $(CHARMFILE)

$(CHARMFILE): src/charm.py charmcraft.yaml
	charmcraft pack

clean:
	charmcraft clean
	rm $(CHARMFILE) -f
