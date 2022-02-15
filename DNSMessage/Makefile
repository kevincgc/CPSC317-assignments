JFLAGS = -g
JC = javac
JARFILE = DNSMessage.jar
SRC = $(shell find src -iname '*.java')
BIN = bin/production/DNSMessage
all: $(JARFILE)

.SUFFIXES: .java .class
$(BIN)/%.class: $(SRC)
	mkdir -p $(BIN)/
	$(JC) -sourcepath src -d $(BIN)/ $(JFLAGS) src/$*.java

$(JARFILE): $(BIN)/ca/ubc/cs/cs317/dnslookup/DNSMessageCUI.class
	jar cvfe $(JARFILE) ca.ubc.cs.cs317.dnslookup.DNSMessageCUI -C $(BIN) ca/

run: $(JARFILE)
	java -jar $(JARFILE)

clean:
	-rm -rf  $(JARFILE) $(BIN)/*
