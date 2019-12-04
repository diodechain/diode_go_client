TESTS= $(shell go list ./... | grep -v gowasm_test)

.PHONY: test
test:
	go test $(TESTS)

.PHONY: install
install:
	go mod download

.PHONY: gateway
gateway:
	go build
	$(MAKE) gateway_copy

gateway_copy: diode_go_client
	scp -C diode_go_client root@diode.ws:
	ssh root@diode.ws 'svc -k .'
	touch gateway_copy
	
