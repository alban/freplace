all: generate build

generate:
	go generate ./...

build:
	go build -o freplace ./...

# Another useful resource to see the LLVM IR: https://godbolt.org/
ir:
	clang -cc1 bpf/freplace.c -o bpf/freplace.ll -emit-llvm -I./bpf -I/usr/include
