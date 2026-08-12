# 🚀 **SND** - **S**ND's **N**on-recursive **D**NS

[![C Standards](https://img.shields.io/badge/Language-POSIX%20C-blue.svg)]()  [![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-brightgreen.svg)]()  [![Academic Score](https://img.shields.io/badge/Course%20Score-99%2F100-brightgreen.svg)]()  [![Artifacts Available](https://img.shields.io/badge/Artifacts-Available-brightgreen)](./artifact_evaluation/AE_README.md)

## 📖 Project Overview

**SND** (**S**ND's **N**on-recursive **D**NS) is a lightweight, high-performance DNS relay server engineered in pure POSIX C, supporting DNS caching, request forwarding, and full logging. This project is the curriculum practice assignment for *Computer Network* from BUPT, running in a Linux / macOS environment.

The project's original name was **DNS Relay**, but we changed its name to emphasize that it is not merely a passive forwarder, but a high-capacity non-recursive DNS engine capable of blazingly fast local table lookups at scale (benchmarked at **1M+** entries) alongside transparent relaying.

> 🎓 **Course Project Notice:** This project was developed as the curriculum practice assignment for *Computer Networks* at BUPT and received a final score of **99 / 100** (1.5 credits).
>
> 🔬 **Artifact Evaluation:** To reproduce our figures and benchmark results, please refer to [./artifact_evaluation/AE_README.md](./artifact_evaluation/AE_README.md).

## ✨ Features

- ✅ **High Performance** - Zero Cache: **9,218** QPS, Mixed Cache: **33,218** QPS, Full Cache: **132,869** QPS
<blockquote>

<details>
<summary>More details about performance</summary>
<br>
<p> <strong>Testing caveats and methodology:</strong> The "Zero Cache" QPS value (9,218) was measured using the recommended 60-second test, which processes a 1M-record file approximately 1.34 times. This results in about 34% of queries being repeated and served from the cache, thus <strong>not representing a purely uncached scenario</strong>. We retain this figure because it demonstrates the system's throughput ceiling under favorable network conditions (low RTT) and serves as an upper-bound reference.</p>

<p> <strong>Real-world performance and variability:</strong> In a strictly uncached test (using a 20-second duration to avoid repetition) with a realistic 250 ms RTT to the upstream server, the system sustains approximately <strong>7,000 QPS</strong>. Furthermore, QPS is highly dependent on the network environment and the client hardware. For example, tests on a MacBook Pro typically yield higher results than on a WSL (Windows Subsystem for Linux) laptop due to differences in the network stack and loopback latency. Tuning kernel socket buffer sizes provides an additional performance gain of 12.24% (Zero Cache) and 8.80% (Full Cache).</p>

<p> Given this variability, <strong>the Full Cache QPS (132,869) is the most important and stable indicator of the system's internal processing capability</strong>, as it is independent of external network conditions. We recommend focusing on this metric to evaluate the core engine's performance.</p>
</details>
</blockquote>

- ✅ **DNS Protocol Parsing** - Full support for DNS message format
- ✅ **Lazy & Periodic Cleanup Cache Mechanism** - Efficient caching of DNS query results
- ✅ **Concurrent Processing** - Support for multiple simultaneous clients
- ✅ **Configuration Support** - Runtime configuration updates
- ❌ **Single-Threaded by Design** - Click [here](https://github.com/AUV888/DNS_Relay/blob/feature_multithread/README.md) to explore our experiments with multithreading and performance trade-offs

## 🛠️ Development Environment

### Recommended Environment

- **OS**: Ubuntu 24.04 LTS / macOS 26
- **Compiler**: GCC 13.3.0 / Apple clang 21.0.0
- **Debugger**: GDB 15.0.50 / LLDB Apple Swift 6.3.3
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

Output: `./bin/SND`

### 3. Run Server

```bash
# Required: -s/--server specifies the upstream DNS server (dotted-decimal IPv4)
sudo ./bin/SND -s 8.8.8.8

# Listen on a custom port (avoids needing sudo if >= 1024)
./bin/SND -s 8.8.8.8 -l 5353

# Run in non-blocking mode with debug log
./bin/SND -s 8.8.8.8 -n -d ./logs/relay.log

# Print full help
./bin/SND
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
| `--cached`       | `-c` | `<file>`     | none           | Load pre-cached DNS records from `<file>` at startup.                                  |
| `--nonblocking`  | `-n` | *(none)*     | blocking       | Switch the event loop to non-blocking I/O. Without this flag, blocking mode is used.     |
| `--listenport`   | `-l` | `<1-65535>`  | `53`         | Local UDP port to listen on for client DNS queries.                                      |
| `--upstreamport` | `-u` | `<1-65535>`  | `53`         | Destination UDP port when forwarding queries to the upstream server.                     |

### Examples

```bash
# Required server only
./bin/SND -s 8.8.8.8

# Custom listen / upstream port
./bin/SND -s 8.8.8.8 -l 5353 -u 53

# Long-option style
./bin/SND --server 8.8.8.8 --listenport 5353 --nonblocking
```

## 📁 Project Structure

```
SND/
├── bin/                       # Build output (executable + .o files)
│   └── SND                    #   final binary
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
|   ├── DNS_logparser.c        #   parser for binary logs
│   └── DNS_util.c             #   helper utilities
├── Makefile                   # Build configuration
└── README.md                  # This file
```

## 📊 Usage Examples

### Basic Testing

```bash
sudo ./bin/SND -l 5678 -s 8.8.8.8 -c ./artifact_evaluation/cached_domain.txt -d ./testing.log
dnsperf 127.0.0.1 -d ./artifact_evaluation/A_Request.txt -Q 50000 -q 50000 -p 5678 -l 60
```

### Configure Cached Domains

To use the `--cached (-c)` option, you need to prepare a list that records the IPv4 - domain pairs. This is an example:

```text
# cached_domain.txt

# Standard local mappings 
142.251.150.119 www.google.com
20.205.243.166 github.com

# Blocklist
0.0.0.0 blocklist_website.com

# Internal network mappings
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

When you enabled `--debug (-d)` option, you will get a binary log file which is not friendly for human to read. To help you better monitor what happened to the server as well as ensuring its high performance, we introduced a utility program `Parser` to help reading the log.

`Parser` is located at `./bin` by default, which is the same directory where `SND` locates. `Parser` reads binary data from `stdin` and prints out the readable information to `stdout`. We highly recommend that you use pipe. A typical usage of `Parser` may be:

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

| Contributor | Responsibilities                                                                                 |
| ----------- | ------------------------------------------------------------------------------------------------ |
| AUV888      | System Architecture,<br /> I/O Event Loop, Protocol Parsing,<br /> Binary Logging & Benchmarking |
