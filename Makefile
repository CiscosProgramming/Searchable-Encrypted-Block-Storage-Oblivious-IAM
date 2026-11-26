.PHONY: build test clean oas-server oams-server obss-server oas-cli oams-cli obss-cli

MVN ?= mvn
JAVA ?= java
CP := target/classes

build:
	$(MVN) -q test-compile

test:
	$(MVN) test

clean:
	$(MVN) -q clean
	rm -rf runtime/

oas-server:
	$(JAVA) -cp $(CP) io.oblivious.oas.OasServer

oams-server:
	$(JAVA) -cp $(CP) io.oblivious.oams.OamsServer

obss-server:
	$(JAVA) -cp $(CP) io.oblivious.obss.ObssServer

oas-cli:
	$(JAVA) -cp $(CP) io.oblivious.oas.OasClient

oams-cli:
	$(JAVA) -cp $(CP) io.oblivious.oams.OamsClient

obss-cli:
	$(JAVA) -cp $(CP) io.oblivious.obss.ObssCli
