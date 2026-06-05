# 🚀 DNS Relay - Computer Network Course Design

## 📖 Project Overview

A DNS relay server implemented in C language, supporting DNS caching, request forwarding, and real-time monitoring. This project is the course design assignment for "Computer Network", running on Linux environment.

## ✨ Features

- ✅ **DNS Protocol Parsing** - Full support for DNS message format
- ✅ **Lazy & Periodic Clenaup Cache Mechanism** - Efficient caching of DNS query results
- ✅ **Concurrent Processing** - Support for multiple simultaneous clients
- ✅ **Configuration Support** - Runtime configuration updates

## 🛠️ Development Environment

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install gcc make gdb git -y

# CentOS/RHEL
sudo yum install gcc make gdb git -y
```

### Recommended Environment

- **OS**: Ubuntu 24.04 LTS / WSL2
- **Compiler**: GCC 13.3.0
- **Debugger**: GDB 15.0.50
- **Editor**: VSCode with C/C++ extension

## 🚀 Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/AUV888/DNS_Relay.git
```

### 2. Build Project

```bash
make
```

Output: `./bin/DNS_Relay`

### 3. Run Server

```bash
# Required: -s/--server specifies the upstream DNS server (dotted-decimal IPv4)
sudo ./bin/DNS_Relay -s 8.8.8.8

# Listen on a custom port (avoids needing sudo if >= 1024)
./bin/DNS_Relay -s 8.8.8.8 -l 5353

# Run in non-blocking mode with debug log
./bin/DNS_Relay -s 8.8.8.8 -n -d ./logs/relay.log

# Print full help
./bin/DNS_Relay
```

> Listening on port 53 requires root privileges. Use `-l <port>` to bind to a
> non-privileged port for testing.

## ⚙️ Command-line Arguments

All options follow GNU style: short (`-d`), long (`--debug`), and single-dash
long forms (`--d`) are all accepted; short flags can be combined (e.g. `-dn`)
as long as flags requiring an argument appear last.

| Argument         | Short | Argument        | Default       | Description                                                                              |
| ---------------- | ----- | --------------- | ------------- | ---------------------------------------------------------------------------------------- |
| `--server`       | `-s`  | `<ipv4>`        | *(required)*  | Upstream DNS server address in dotted-decimal form. Program exits with usage if missing. |
| `--debug`        | `-d`  | `[log_file]`    | off           | Enable debug logging. If `log_file` is omitted, an auto-named file is used.              |
| `--moredebug`    | `-m`  | `[log_file]`    | off           | More verbose debug logging; otherwise the same as `--debug`.                             |
| `--cached`       | `-c`  | `<file>`        | none          | Load pre-cached DNS records from `<file>` at startup.                                    |
| `--nonblocking`  | `-n`  | *(none)*        | blocking      | Switch the event loop to non-blocking I/O. Without this flag, blocking mode is used.     |
| `--listenport`   | `-l`  | `<1-65535>`     | `53`          | Local UDP port to listen on for client DNS queries.                                      |
| `--upstreamport` | `-u`  | `<1-65535>`     | `53`          | Destination UDP port when forwarding queries to the upstream server.                     |

### Examples

```bash
# Required server only
./bin/DNS_Relay -s 8.8.8.8

# Custom listen / upstream port
./bin/DNS_Relay -s 8.8.8.8 -l 5353 -u 53

# Non-blocking + verbose log
./bin/DNS_Relay -s 8.8.8.8 -n -m ./logs/verbose.log

# Long-option style
./bin/DNS_Relay --server 8.8.8.8 --listenport 5353 --nonblocking
```

## 📁 Project Structure

```
DNS_Relay/
├── bin/                       # Build output (executable + .o files)
│   └── DNS_Relay              #   final binary
├── include/                   # Public headers
│   ├── DNS_arguments.h        #   command-line argument globals & parser
│   ├── DNS_cache.h            #   DNS cache (lazy + periodic cleanup)
│   ├── DNS_convert.h          #   DNS wire format encode / decode
│   ├── DNS_debug.h            #   binary 128-bit log writer + event enums
│   ├── DNS_id.h               #   transaction-ID remapping table
│   ├── DNS_server.h           #   socket setup, blocking / non-blocking loops
│   ├── DNS_struct.h           #   DNS message data structures
│   └── DNS_util.h             #   uint8_t pointer stack used during parsing
├── src/                       # Implementation files
│   ├── main.c                 #   program entry, calls parse_arguments + server
│   ├── DNS_arguments.c        #   GNU-style argv parser
│   ├── DNS_cache.c            #   cache implementation
│   ├── DNS_convert.c          #   DNS protocol (de)serializer
│   ├── DNS_debug.c            #   128-bit binary log file writer
│   ├── DNS_id.c               #   ID-mapping bookkeeping
│   ├── DNS_server.c           #   recvfrom / sendto event loop
│   └── DNS_util.c             #   helper utilities
├── logs/                      # Default location for binary log files (manual mkdir)
├── Makefile                   # Build configuration (gcc -Wall -g -O0)
└── README.md                  # This file
```

> The log directory (`./logs/`) is **not** created automatically; create it
> yourself (`mkdir -p logs`) before using `-d`/`-m` with a path under `logs/`.

## 📊 Usage Examples

### Basic Testing

```bash
# To be completed
```

## 🔧 Build Options

```bash
# Standard build
make

# Clean build files
make clean
```

## 📝 Configuration Example

```ini
# To be completed
```

## 🐛 Troubleshooting

### Common Issues

**Q: "bin directory does not exist" during build**

```bash
mkdir -p bin
make
```

## 📈 Performance Metrics

| Metric         | Expected | Description                     |
| -------------- | -------- | ------------------------------- |
| Cache hit rate | --       | Efficiency for repeated queries |
| Response time  | --       | Average query latency           |
| Memory usage   | --       | Runtime memory consumption      |

## 👥 Development Team

| Name   | Student ID | Responsibilities |
| ------ | ---------- | ---------------- |
| AUV888 | --         | --               |
| --     | --         | --               |
| --     | --         | --               |
