# ==============================================================================
# AAYOG_CHUNAV 3.0 - Makefile
# Secure Election Management and Online Voting System
# Compatible with macOS (clang/gcc with Homebrew/system OpenSSL) and Linux (gcc)
# ==============================================================================

CC ?= gcc
CFLAGS = -Wall -Wextra -O2 -pthread -Iinclude

# Detect OpenSSL include and library paths for macOS and Linux
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
    # Check common Homebrew OpenSSL locations on macOS
    ifneq ($(wildcard /opt/homebrew/opt/openssl@3/.*),)
        OPENSSL_DIR = /opt/homebrew/opt/openssl@3
    else ifneq ($(wildcard /opt/homebrew/opt/openssl/.*),)
        OPENSSL_DIR = /opt/homebrew/opt/openssl
    else ifneq ($(wildcard /usr/local/opt/openssl@3/.*),)
        OPENSSL_DIR = /usr/local/opt/openssl@3
    else ifneq ($(wildcard /usr/local/opt/openssl/.*),)
        OPENSSL_DIR = /usr/local/opt/openssl
    endif

    ifneq ($(OPENSSL_DIR),)
        CFLAGS += -I$(OPENSSL_DIR)/include
        LDFLAGS += -L$(OPENSSL_DIR)/lib
    endif
endif

LIBS = -lssl -lcrypto -pthread

SERVER_SRC = server.c src/election.c src/security.c src/admin.c src/http.c
CLIENT_SRC = client.c src/security.c
SERVER_BIN = server
CLIENT_BIN = client

.PHONY: all clean run-server run-client certs test reset-votes

all: certs $(SERVER_BIN) $(CLIENT_BIN)

certs:
	@if [ ! -f certs/server.crt ] || [ ! -f certs/server.key ]; then \
		echo "[BUILD] Generating required TLS certificates..."; \
		chmod +x scripts/generate_certs.sh && ./scripts/generate_certs.sh; \
	fi

$(SERVER_BIN): $(SERVER_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(SERVER_BIN) $(SERVER_SRC) $(LIBS)
	@echo "Built $(SERVER_BIN) (AAYOG_CHUNAV 2.0 Secure Engine) successfully."

$(CLIENT_BIN): $(CLIENT_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $(CLIENT_BIN) $(CLIENT_SRC) $(LIBS)
	@echo "Built $(CLIENT_BIN) (AAYOG_CHUNAV 2.0 Secure TLS Client) successfully."

clean:
	rm -f $(SERVER_BIN) $(CLIENT_BIN)
	rm -rf *.dSYM
	@echo "Cleaned build binaries."

reset-votes:
	rm -f data/voters.txt data/ballots.txt votes.txt data/election_*/ballots.txt
	@for f in data/election_*/voters.txt; do \
		if [ -f "$$f" ]; then \
			sed -i '' -E 's/\|1\|[0-9]{4}-[0-9]{2}-[0-9]{2}/|0|NONE/g' "$$f" 2>/dev/null || true; \
		fi \
	done
	@echo "Reset voting tallies and restored official voter roll."

run-server: $(SERVER_BIN) certs
	./$(SERVER_BIN)

run-client: $(CLIENT_BIN)
	./$(CLIENT_BIN)

test: all
	chmod +x test_system.sh test_web_and_cli.sh test_security.sh test_v3_multielection.sh test_concurrency.sh
	./test_system.sh
	./test_web_and_cli.sh
	./test_security.sh
	./test_v3_multielection.sh
	./test_concurrency.sh
