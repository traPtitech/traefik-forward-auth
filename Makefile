.PHONY: format
format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

.PHONY: test
test:
	go test -v ./...
