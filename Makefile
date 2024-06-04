
format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

test:
	go test -tags "viper_bind_struct" -v ./...

.PHONY: format test
