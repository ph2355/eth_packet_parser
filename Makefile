CC        ?= cc
CFLAGS    ?= -std=c99 -Wall -Wextra -Wpedantic -Werror -O2 -g
UNITY_DIR := vendor/unity
SAN_FLAGS := -std=c99 -Wall -Wextra -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer

.PHONY: all test sanitize clean

all: test_eth_ipv4

# Unity is third-party code: build it without -Werror/-Wpedantic.
unity.o: $(UNITY_DIR)/unity.c $(UNITY_DIR)/unity.h $(UNITY_DIR)/unity_internals.h
	$(CC) -std=c99 -O2 -g -c -o $@ $(UNITY_DIR)/unity.c

test_eth_ipv4: eth_ipv4.c test_eth_ipv4.c eth_ipv4.h unity.o
	$(CC) $(CFLAGS) -I$(UNITY_DIR) -o $@ eth_ipv4.c test_eth_ipv4.c unity.o

test: test_eth_ipv4
	./test_eth_ipv4

# Same tests under AddressSanitizer + UBSan (catches out-of-bounds reads).
sanitize:
	$(CC) $(SAN_FLAGS) -I$(UNITY_DIR) -o test_eth_ipv4_san \
	    eth_ipv4.c test_eth_ipv4.c $(UNITY_DIR)/unity.c
	./test_eth_ipv4_san

clean:
	rm -rf test_eth_ipv4 test_eth_ipv4_san unity.o *.dSYM
