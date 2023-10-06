CLANG ?= clang-10
CFLAGS ?= -O2 -g -Wall  -I/usr/include/x86_64-linux-gnu -Iheaders

LIBEBPF_TOP = /home/user/ebpf
EXAMPLES_HEADERS = $(LIBEBPF_TOP)/../headers

all: generate

generate: export BPF_CLANG=$(CLANG)
generate: export BPF_CFLAGS=$(CFLAGS)
generate: export BPF_HEADERS=$(EXAMPLES_HEADERS)
generate:
	go generate main.go

