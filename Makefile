all: generate build

generate:
	go generate ./...

build:
	go build -o freplace ./...
