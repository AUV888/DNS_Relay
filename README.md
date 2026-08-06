# 🚀 DNS Relay - Curriculum Practice of Computer Networks

## 📖 Project Overview

A DNS relay server implemented in C language, supporting DNS caching, request forwarding, and real-time monitoring. This project is the curriculum practice assignment for "Computer Network" from BUPT, running on Linux environment.

**This project received a score of 99 out of 100 in Curriculum Practice of Computer Networks (1.5 credits).**

To reproduce the figures, please refer to [./artifact_evaluation/AE_README.md](./artifact_evaluation/AE_README.md).

## ✨ Features

- ✅ **High Performance** - 0 Cache: **9218** QPS, Mixed Cache: **33218** QPS, Full Cache: **132869** QPS
- ✅ **DNS Protocol Parsing** - Full support for DNS message format
- ✅ **Lazy & Periodic Cleanup Cache Mechanism** - Efficient caching of DNS query results
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

| Argument           | Short  | Argument       | Default        | Description                                                                              |
| ------------------ | ------ | -------------- | -------------- | ---------------------------------------------------------------------------------------- |
| `--server`       | `-s` | `<ipv4>`     | *(required)* | Upstream DNS server address in dotted-decimal form. Program exits with usage if missing. |
| `--debug`        | `-d` | `[log_file]` | off            | Enable debug logging. If `log_file` is omitted, an auto-named file is used.            |
| `--moredebug`    | `-m` | `[log_file]` | off            | More verbose debug logging; otherwise the same as `--debug`.                           |
| `--cached`       | `-c` | `<file>`     | none           | Load pre-cached DNS records from `<file>` at startup.                                  |
| `--nonblocking`  | `-n` | *(none)*     | blocking       | Switch the event loop to non-blocking I/O. Without this flag, blocking mode is used.     |
| `--listenport`   | `-l` | `<1-65535>`  | `53`         | Local UDP port to listen on for client DNS queries.                                      |
| `--upstreamport` | `-u` | `<1-65535>`  | `53`         | Destination UDP port when forwarding queries to the upstream server.                     |

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
│   ├── DNS_readlog.h          #   print debug info for moredebug mode
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
│   ├── DNS_readlog.c          #   print debug info for moredebug mode
|   ├── DNS_logparser.c        #   parser for binary logs
│   └── DNS_util.c             #   helper utilities
├── Makefile                   # Build configuration
└── README.md                  # This file
```

## 📊 Usage Examples

### Basic Testing

```bash
sudo ./bin/DNS_Relay -l 5678 -s 8.8.8.8 -c ./artifact_evaluation/cached_domain.txt -d ./testing.log
dnsperf 127.0.0.1 -d ./artifact_evaluation/A_Request.txt -Q 50000 -q 50000 -p 5678 -l 60
```

### Configure Cached Domains
To use the `--cached (-c)` option, you need to prepare a list that records the IPv4 - domain pairs. This is an example:
```text
142.251.150.119 www.google.com
20.205.243.166 github.com

0.0.0.0 blocklist_website.com

10.3.8.6 internal_website.com
```

## 🔧 Build Options

```bash
# Standard build
make

# Clean build files
make clean

# Debug build
make debug
```

## 📝 Log Parsing

When you enabled `--debug (-d)` or `--moredebug (-m)` option, you will get a binary log file which is not friendly for human to read. To help you better monitor what happened to the server as well as ensuring its high performance, we introduced a utility program `Parser` to help reading the log.

`Parser` is located at `./bin` by default, which is the same directory where `DNS_Relay` locates. `Parser` reads binary data from `stdin` by `scanf()` and prints out the readable information to `stdout` by `printf()`. We highly recommend that you use pipe. A typical usage of `Parser` may be:

```bash
# Save to a file and read it later
cat /path/to/file | ./bin/Parser > /path/to/output/file 2>&1

# Read immediately and find out the keyword you want to search
cat /path/to/file | ./bin/Parser | grep -i "warn"
```

## 📈 Performance Metrics

| Metric                                            | Expected         | Description                                                                                                                                                                        |
| ------------------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Zero Cache Avg. Latency                           | 0.393s           | Average query latency<br />Average RTT from Beijing to 8.8.8.8 is 250~350ms                                                                                                        |
| Mixed Cache Avg. Latency<br />(Approx. 23% cache) | 0.075s           | Average query latency<br />Under high concurrency stress test (50,000 queries)                                                                                                     |
| Full Cache Avg. Latency                           | 0.000723s        | Average query latency                                                                                                                                                              |
| Zero Cache QPS                                    | approx. 9,200    | Query per second without any cached DNS.<br />Tested on a MacBook Pro (M4 Pro) at Wednesday afternoon in Beijing residential area.<br />Upstream server is 8.8.8.8 (Google DNS).   |
| Mixed Cache QPS<br />(Approx. 23% cache)          | approx. 33,200   | Query per second when A record is partially cached.<br />Tested on a WSL, 8-core-laptop at Friday night in Beijing residential area.<br />Upstream server is 8.8.8.8 (Google DNS). |
| Full Cache QPS                                    | approx. 133,000 | Query per second when A record is fully cached.<br />Tested on a WSL, 8-core-laptop at Wednesday afternoon in Beijing residential area.                                            |

## 👥 Development Team

| Name   | Student ID | Responsibilities |
| ------ | ---------- | ---------------- |
| AUV888 | --         | All              |
