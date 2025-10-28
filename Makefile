generate:
	go generate ./...

build-ebpf-tcpconnlat:
	go build -ldflags "-s -w" -o ebpf-tcpconnlat cmd/main.go

build: generate build-ebpf-tcpconnlat

clean:
	rm -f ebpf-tcpconnlat
	rm -f internal/probe/probe_bpf*.go
	rm -f internal/probe/probe_bpf*.o