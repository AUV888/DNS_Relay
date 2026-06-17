# Artifcat Evaluation Guide

This Guide is to help you reproduce the results that we have showed in `README.md`. We assume that the environment has already been set up based on the `README.md` in the
root directory of the repository.

## 1. Basic Features

Please make sure that you are in the root directory of the repository and run

```bash
make clean && make
sudo ./bin/DNS_Relay -l 5678 -s 8.8.8.8 -c ./artifact_evaluation/cached_domain.txt
```

If you want to test more arguments, please refer to the argument lists below.

| Argument           | Short  | Argument       | Default        | Description                                                                              |
| ------------------ | ------ | -------------- | -------------- | ---------------------------------------------------------------------------------------- |
| `--server`       | `-s` | `<ipv4>`     | *(required)* | Upstream DNS server address in dotted-decimal form. Program exits with usage if missing. |
| `--debug`        | `-d` | `[log_file]` | off            | Enable debug logging. If `log_file` is omitted, an auto-named file is used.            |
| `--moredebug`    | `-m` | `[log_file]` | off            | More verbose debug logging; otherwise the same as `--debug`.                           |
| `--cached`       | `-c` | `<file>`     | none           | Load pre-cached DNS records from `<file>` at startup.                                  |
| `--nonblocking`  | `-n` | *(none)*     | blocking       | Switch the event loop to non-blocking I/O. Without this flag, blocking mode is used.     |
| `--listenport`   | `-l` | `<1-65535>`  | `53`         | Local UDP port to listen on for client DNS queries.                                      |
| `--upstreamport` | `-u` | `<1-65535>`  | `53`         | Destination UDP port when forwarding queries to the upstream server.                     |

After that, you can open a new terminal to run `nslookup` command to test basic features, for example

```bash
nslookup

#make sure that you've entered the interactive mode

server 127.0.0.1
set port=5678 type=A
www.google.com

#test blocked domains (This domain exists but we block it deliberately)
www.bupt.edu.cn

#expected results: 
#Server:		127.0.0.1
#Address:	127.0.0.1#5678

#** server can't find www.bupt.edu.cn: NXDOMAIN
```

If you desire to test other types of DNS requests, for example, MX, just use

```bash
set type=MX
www.google.com
```

If you finished the basic tests, just press `Ctrl + C` and the program will exit gracefully.

## 2. No Cache QPS Test

Please make sure that you are in the root directory of the repository and you've compiled the binary file before.

If you haven't installed `dnsperf`, use the command below

```bash
#MacOS
brew install dnsperf

#Ubuntu/Debian
sudo apt install dnsperf

#Fedora/RedHat
sudo dnf install dnsperf
```

Now, we'll start to test the no-cache QPS of our DNS server.

```bash
#Terminal 1
sudo ./bin/DNS_Relay -l 5678 -s 8.8.8.8
```

```bash
#Terminal 2
dnsperf -s 127.0.0.1 -d ./artifact_evaluation/A_Request.txt -Q 50000 -q 50000 -p 5678 -l 60 | tee ./artifact_evaluation/No_Cache.log
```

If your network is fast enough or your organization does not have high-frequency UDP packets speed limits, you'll probably see the log like this:

```plaintext
DNS Performance Testing Tool
Version 2.15.0

[Status] Command line: dnsperf -s 127.0.0.1 -d ./artifact_evaluation/A_Request.txt -Q 50000 -q 50000 -p 5678 -l 60
[Status] Sending queries (to 127.0.0.1:5678)
[Status] Started at: Wed Jun 10 16:16:03 2026
[Status] Stopping after 60.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         1348573
  Queries completed:    598351 (44.37%)
  Queries lost:         750222 (55.63%)
  Unexpected IDs:       211 (0.02%)

  Response codes:       NOERROR 561269 (93.80%), SERVFAIL 8169 (1.37%), NXDOMAIN 28896 (4.83%), REFUSED 17 (0.00%)
  Average packet size:  request 32, response 59
  Run time (s):         64.906003
  Queries per second:   9218.731278

  Average Latency (s):  0.392673 (min 0.000025, max 4.996178)
  Latency StdDev (s):   0.583499
```

The QPS will fluctuate due to your network status, but it will be at least 1k QPS. We tested this result at residential area in Beijing at Wednesday afternoon, which is less stressful than rush hours. If you try to reproduce it at 3 AM in Beijing residential area, the result may be more astonishing.

## 3. Mixed Cache QPS

Considering that many DNS packet have a TTL for 5 minutes and we cache almost every DNS type A request that was received from upstream server, we suggest you **perform this right after performing operations in section 2**. If you haven't do this in 5 minutes, please kill this program and perform section 2 again to cache them.

Please make sure that you are in the root directory of the repository and you've compiled the binary file before. You can run commands below.

```bash
#Terminal 1
sudo ./bin/DNS_Relay -l 5678 -s 8.8.8.8
```

```bash
#Terminal 2
dnsperf -s 127.0.0.1 -d ./artifact_evaluation/A_Request.txt -Q 50000 -q 50000 -p 5678 -l 60 | tee ./artifact_evaluation/Mixed_Cache.log
```

You'll probably see log like this:

```plaintext
DNS Performance Testing Tool
Version 2.14.0

[Status] Command line: dnsperf -s 127.0.0.1 -d ./artifact_evaluation/A_Request.txt -Q 50000 -q 50000 -p 5678 -l 60
[Status] Sending queries (to 127.0.0.1:5678)
[Status] Started at: Fri Jun 12 21:02:10 2026
[Status] Stopping after 60.000000 seconds
[Status] Testing complete (time limit)

Statistics:

  Queries sent:         2483433
  Queries completed:    2152564 (86.68%)
  Queries lost:         330869 (13.32%)

  Response codes:       NOERROR 2049565 (95.22%), SERVFAIL 24837 (1.15%), NXDOMAIN 78102 (3.63%), REFUSED 60 (0.00%)
  Average packet size:  request 32, response 52
  Run time (s):         64.799209
  Queries per second:   33218.985744

  Average Latency (s):  0.074630 (min 0.000006, max 4154504685.550254)
  Latency StdDev (s):   0.254015
```

Note that the total queries sent in Section 3 (2.48 million) exceed the number of cached records populated in Section 2 (~0.56 million). Therefore, this test represents a mixed workload: a small percentage of queries hit the cache, while the remaining are forwarded to the upstream server. This mixed scenario actually reflects real-world deployment more accurately than a pure cache-hit test. The QPS improvement from ~9k to ~33k demonstrates the effectiveness of our caching mechanism even under partial cache miss conditions.

## 4. Devices

Zero cache results were tested on a MacBook Pro (M4 Pro chip).

Mixed cache results were tested on a WSL laptop (AMD Ryzen R7-8845H chip).
