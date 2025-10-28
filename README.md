# eBPF TCP Connection Latency Monitor

This repository is an adaptation of the [eunomia-bpf tcpconnlat example](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/13-tcpconnlat/README.md), using Go with [cilium/ebpf](https://github.com/cilium/ebpf) library for the userspace code instead of the original C implementation.

## Overview

This project demonstrates TCP connection latency monitoring using eBPF by tracing TCP connection establishment. It captures:
- TCP connection attempts (via `tcp_v4_connect` and `tcp_v6_connect` entry points)
- Connection completion (via `tcp_rcv_state_process` entry point)
- Connection metadata (process name, PID, source/destination addresses and ports)
- Connection latency measurement (time between SYN and SYN-ACK)

## Key Differences from Original

- **Userspace Language**: Go instead of C
- **BPF Library**: [cilium/ebpf](https://github.com/cilium/ebpf) instead of libbpf
- **Code Generation**: Uses `bpf2go` for generating Go bindings from eBPF C code
- **Modern API**: Leverages Go's type safety and error handling
- **Tracing Method**: Uses fentry probes instead of kprobes for better performance

## Architecture

```
ebpf-tcpconnlat/
├── bpf/
│   ├── tcpconnlat.bpf.c   # eBPF kernel-space program (C)
│   ├── tcpconnlat.h       # Event structure definitions
│   └── vmlinux.h          # Kernel type definitions (CO-RE)
├── cmd/
│   └── main.go            # Main entry point
├── internal/
│   ├── event/
│   │   └── event.go       # Event parsing and formatting
│   ├── probe/
│   │   ├── probe.go       # eBPF loader and manager
│   │   ├── probe_bpfeb.go # Generated (big-endian)
│   │   └── probe_bpfel.go # Generated (little-endian)
│   └── timer/
│       └── timer.go       # Timing utilities
└── Makefile
```

## Requirements

- Linux kernel 5.8+ with BTF support and fentry/fexit capability
- Go 1.21+
- `clang` and `llvm` for compiling eBPF programs
- Root/CAP_BPF privileges to load eBPF programs

## Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ebpf-tcpconnlat.git
cd ebpf-tcpconnlat

# Install dependencies
go mod download

# Generate eBPF bindings and build
make build
```

## Usage

```bash
# Run with default settings (show all connections)
sudo ./ebpf-tcpconnlat

# Set minimum connection latency filter (in microseconds)
sudo ./ebpf-tcpconnlat -minus 1000

# Filter by specific process ID
sudo ./ebpf-tcpconnlat -pid 1234

# Combine filters
sudo ./ebpf-tcpconnlat -minus 500 -pid 1234
```

### Command-line Options

- `-minus <microseconds>`: Minimum connection latency in microseconds to report (default: 0)
- `-pid <process_id>`: Process ID to filter connections for (default: 0, shows all processes)

## Output Format

```
TIME       PID    COMM         IP SADDR            LPORT  DADDR            DPORT LAT(ms)
22:10:29   10774  node         v4 192.168.5.1      40394  140.82.114.21    47873 84.803
22:11:08   28966  curl         v4 192.168.5.1      60168  172.217.20.164   47873 7.620
22:11:24   573    sshd         v4 127.0.0.1        45676  127.0.0.1        5548  27.667
```

- **TIME**: Connection completion timestamp (HH:MM:SS)
- **PID**: Process ID that initiated the connection
- **COMM**: Process command name (truncated to 16 chars)
- **IP**: IP version (4 for IPv4, 6 for IPv6)
- **SADDR**: Source IP address
- **DADDR**: Destination IP address
- **DPORT**: Destination port
- **LAT(ms)**: Connection latency in miliseconds

## How It Works

### Kernel-Space (eBPF)

The eBPF programs (`bpf/tcpconnlat.bpf.c`) attach to kernel function entry points using fentry probes:

1. **`fentry_tcp_v4_connect`** and **`fentry_tcp_v6_connect`**: Triggered when a TCP connection is initiated
   - Records connection start timestamp
   - Stores process metadata (PID, command name)
   - Uses socket pointer as key in hash map

2. **`fentry_tcp_rcv_state_process`**: Triggered during TCP state processing
   - Detects SYN-ACK reception (connection establishment)
   - Retrieves start timestamp from hash map
   - Calculates connection latency
   - Applies filtering based on minimum latency and PID
   - Captures connection details (addresses, ports)
   - Sends event to userspace via perf event array

Events are sent to userspace via a perf event buffer for efficient data transfer.

### User-Space (Go)

The Go application:

1. Loads the compiled eBPF object into the kernel
2. Sets filtering parameters (minimum latency, target PID)
3. Attaches fentry programs to kernel functions
4. Reads events from the perf event buffer
5. Parses and formats connection latency data
6. Displays real-time TCP connection information

## Development

### Modifying eBPF Code

1. Edit `bpf/tcpconnlat.bpf.c`
2. Run `make generate` to regenerate Go bindings
3. Rebuild with `make build`

### Code Generation

The `//go:generate` directive in `internal/probe/probe.go` uses `bpf2go`:

```go
//go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/tcpconnlat.bpf.c -- -O2
```

This generates:
- `probe_bpfel.go` / `probe_bpfeb.go`: Architecture-specific bindings
- `probe_bpfel.o` / `probe_bpfeb.o`: Compiled eBPF bytecode

## Troubleshooting

**Error: Failed to load BPF object**
- Ensure you're running with root privileges
- Check kernel version supports BTF (`ls /sys/kernel/btf/vmlinux`)
- Verify fentry/fexit support in kernel config

**Error: Failed to link fentry program**
- Check if kernel supports fentry probes (kernel 5.5+)
- Ensure BTF is available for target functions
- Try using kprobe version (uncomment kprobe sections in eBPF code)

**Error: Permission denied**
- Run with `sudo` or grant CAP_BPF capability
- Check `/sys/fs/bpf` is mounted
- Ensure proper memory limits are set

## Use Cases

- **Network Performance Analysis**: Identify slow connection establishments
- **Application Monitoring**: Track connection latency for specific applications
- **Debugging Network Issues**: Pinpoint connection bottlenecks
- **Security Monitoring**: Monitor outbound connections from processes

## References

- [Original eunomia-bpf tcpconnlat tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial/blob/main/src/13-tcpconnlat/README.md)
- [cilium/ebpf library](https://github.com/cilium/ebpf)
- [eBPF documentation](https://ebpf.io/)
- [BCC tcpconnlat tool](https://github.com/iovisor/bcc/blob/master/tools/tcpconnlat.py)
- [Linux TCP state machine](https://tools.ietf.org/html/rfc793)

## License

MIT