# --------------------------------------------------------------------------
#  Makefile
# --------------------------------------------------------------------------

CXXFLAGS ?= $(shell pkg-config --cflags live555) $(shell pcap-config --cflags)
LDFLAGS  ?= $(shell pkg-config --libs live555) $(shell pcap-config --libs) -lstdc++

EXE=rtp-pcap-replay
OBJ=$(EXE).o
SRC=$(EXE).cpp

all:
	@echo "Targets:"
	@echo "\tbuild\tcompiles and link"
	@echo "\tinstall\tinstall defaults to /usr/local/bin"
	@echo "\tclean\tremove compilation result"
	@echo "\tdistclean\treally clean"

build: $(EXE)

install:
	@echo "Nothing to do !"

clean:
	@rm -f $(EXE) $(OBJ)

distclean: clean


$(EXE): $(OBJ)

$(OBJ): $(SRC)

.PHONY: all build clean install distclean

