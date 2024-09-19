JAVAC = javac
JAR = jar
JAVA = java
JFLAGS = -g -d bin -cp lib/*:.
SRC = .
BIN = bin
LIB = lib
MAIN = main

JAVA_FILES = $(shell find $(SRC)/common $(SRC)/samsung_ril -name "*.java")

default: compile jar

compile: $(JAVA_FILES)
	if [ -d $(BIN) ]; then rm -rf $(BIN); fi
	mkdir $(BIN)
	$(JAVAC) $(JFLAGS) $^

jar: $(JAVA_FILES)
	$(JAR) cvfm $(MAIN).jar $(SRC)/manifest.txt -C $(BIN) .

run: $(MAIN).jar
	$(JAVA) -cp $(LIB)/ghidra.jar:$(LIB)/json.jar:$(MAIN).jar $(MAIN)

clean:
	rm -rf $(BIN) $(MAIN).jar
