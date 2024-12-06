# `ioburst`

**ioburst** is a block IO monitoring tool that leverages eBPF to track disk IO operations, identify bursts that exceed configured thresholds, and print histograms at program exit. It can run in various verbosity modes, display cumulative stats, and emit detailed completion records for IOs considered to be in a "burst" state.

## Features

- **Latency Histograms:** Separates IO completions into standard vs. burst latencies and generates log2-based latency histograms at the end of the run.
- **Burst Detection:** Compares per-device IO rates against user-defined IOPS/Bandwidth limits. IOs issued during intervals that exceed these limits are marked as burst operations.
- **Cumulative Stats:** Tracks total normal and burst IO operations, bandwidth, and concurrency over time.
- **Verbose Logging:** Offers multiple verbosity levels. At the highest level, it logs every IO event, allowing you to correlate bursts directly with their completions.

## Usage

```
ioburst [-h] [-d DEVICE] [--bandwidth MB/S] [--iops IOPS]
        [-c COUNT] [-i INTERVAL] [-v] [-p PID] [-m|-s|-u|-n]

Options:
  -d, --device DEVICE    Monitor the specified block device(s). Can be repeated.
  --bandwidth MB/S       Bandwidth limit for burst detection (default: 125 MB/s).
  --iops IOPS            IOPS limit for burst detection (default: 3000 IOPS).
  -c, --count COUNT      Number of intervals before exiting (default: run indefinitely).
  -i, --interval SEC     Interval between printed stats (default: 1.0s).
  -v, --verbose          Increase verbosity.
                         -v: print burst IO completions
                         -vv: print all IO completions
  -p PID, --pid PID     Only monitor IOs from these PIDs (can accept multiple PIDs separated by whitespace).
  -m, --milliseconds     Display latency in milliseconds.
  -s, --seconds          Display latency in seconds.
  -u, --microseconds     Display latency in microseconds.
  -n, --nanoseconds      Display latency in nanoseconds.
  -H, --humanized        Use human-friendly units (default).
```

### Examples

```
# Monitor a single device with default thresholds:
ioburst -d /dev/nvme0n1

# Monitor all discovered NVMe devices, print every 1s, exit after 10 intervals:
ioburst -c 10

# Show burst-only completions:
ioburst -d /dev/nvme0n1 -v

# Show only fio operations:
ioburst -d /dev/nvme0n1 -v -p "$(pgrep fio)"

# Show all completions (both normal and burst):
ioburst -d /dev/nvme0n1 -vv
```

### Example Output

```
# ioburst -c 5
Monitoring devices: /dev/nvme0n1, /dev/nvme2n1, /dev/nvme3n1, /dev/nvme4n1

2024-12-06 22:55:45
Device            IOPS  MB/s  Burst IOPS  Burst MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1       12    0.1           0         0.0         1
/dev/nvme2n1       12    0.1           0         0.0         1
/dev/nvme3n1        2    0.0           0         0.0         1
/dev/nvme4n1        6    0.0           0         0.0         1

2024-12-06 22:55:46
Device            IOPS  MB/s  Burst IOPS  Burst MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1        1    0.0           0         0.0         1
/dev/nvme2n1       42    0.2           0         0.0         1
/dev/nvme3n1        0    0.0           0         0.0         0
/dev/nvme4n1       20    0.1           0         0.0         1

2024-12-06 22:55:47
Device            IOPS  MB/s  Burst IOPS  Burst MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1     2958  184.4        1787       111.9       126
/dev/nvme2n1     2947  182.8        1772       110.9       128
/dev/nvme3n1     2913  181.9        1856       116.1       134
/dev/nvme4n1     2924  182.2        1734       108.4       129

2024-12-06 22:55:48
Device            IOPS  MB/s  Burst IOPS  Burst MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1     1958  122.2           0         0.0       122
/dev/nvme2n1     1927  119.1           0         0.0       119
/dev/nvme3n1     1936  120.9           0         0.0       120
/dev/nvme4n1     1960  122.0           0         0.0       124

2024-12-06 22:55:49
Device            IOPS  MB/s  Burst IOPS  Burst MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1     1931  120.6           0         0.0       108
/dev/nvme2n1     1977  121.9           0         0.0        88
/dev/nvme3n1     1937  120.9           0         0.0        89
/dev/nvme4n1     1948  121.5           0         0.0        96

Standard Latency Histogram by Device:

Device: /dev/nvme0n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
     512.00 µs -       1.02 ms        82    465.51 µs       38.17 ms
       1.02 ms -       2.05 ms       272    653.88 µs      177.85 ms
       2.05 ms -       4.09 ms       206      1.45 ms      299.65 ms
       4.10 ms -       8.19 ms        37      3.07 ms      113.61 ms
       8.19 ms -      16.38 ms        77      6.19 ms      476.42 ms
      16.38 ms -      32.77 ms      1323     11.88 ms       15.72 s
      32.77 ms -      65.53 ms        23     17.93 ms      412.45 ms
      65.54 ms -     131.07 ms      3493     59.70 ms      208.53 s
     131.07 ms -     262.14 ms       501     78.12 ms       39.14 s

Device: /dev/nvme2n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
     128.00 µs -     255.00 µs         1    112.00 µs      112.00 µs
       1.02 ms -       2.05 ms       323    787.11 µs      254.24 ms
       2.05 ms -       4.09 ms      1617      1.40 ms        2.26 s
       4.10 ms -       8.19 ms       114      3.07 ms      349.87 ms
       8.19 ms -      16.38 ms        14      4.68 ms       65.55 ms
      16.38 ms -      32.77 ms         1     12.82 ms       12.82 ms
      32.77 ms -      65.53 ms       108     27.59 ms        2.98 s
      65.54 ms -     131.07 ms      3433     53.67 ms      184.25 s
     131.07 ms -     262.14 ms       488     74.15 ms       36.18 s

Device: /dev/nvme3n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
     256.00 µs -     511.00 µs         1    192.00 µs      192.00 µs
       1.02 ms -       2.05 ms       339    786.84 µs      266.74 ms
       2.05 ms -       4.09 ms       398      1.40 ms      556.21 ms
       4.10 ms -       8.19 ms       193      2.96 ms      570.58 ms
       8.19 ms -      16.38 ms       204      6.29 ms        1.28 s
      16.38 ms -      32.77 ms       304     11.51 ms        3.50 s
      32.77 ms -      65.53 ms       522     23.99 ms       12.52 s
      65.54 ms -     131.07 ms      3465     51.82 ms      179.57 s
     131.07 ms -     262.14 ms       417     74.41 ms       31.03 s

Device: /dev/nvme4n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
     512.00 µs -       1.02 ms         5    494.20 µs        2.47 ms
       1.02 ms -       2.05 ms      1431    740.96 µs        1.06 s
       2.05 ms -       4.09 ms       166      1.43 ms      237.70 ms
       4.10 ms -       8.19 ms       193      2.79 ms      538.27 ms
       8.19 ms -      16.38 ms       116      6.12 ms      710.04 ms
      16.38 ms -      32.77 ms       119      9.86 ms        1.17 s
      32.77 ms -      65.53 ms        88     27.68 ms        2.44 s
      65.54 ms -     131.07 ms      3495     52.08 ms      182.00 s
     131.07 ms -     262.14 ms       423     72.55 ms       30.69 s

Burst Latency Histogram by Device:

Device: /dev/nvme0n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
     512.00 µs -       1.02 ms        55    484.82 µs       26.66 ms
       1.02 ms -       2.05 ms       320    638.02 µs      204.17 ms
       2.05 ms -       4.09 ms        86      1.66 ms      142.83 ms
       4.10 ms -       8.19 ms       101      2.45 ms      247.12 ms
       8.19 ms -      16.38 ms         8      6.61 ms       52.90 ms
      16.38 ms -      32.77 ms        23     12.41 ms      285.44 ms
      32.77 ms -      65.53 ms        34     25.60 ms      870.32 ms
      65.54 ms -     131.07 ms       206     56.09 ms       11.56 s
     131.07 ms -     262.14 ms         6     77.88 ms      467.29 ms

Device: /dev/nvme2n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
       2.05 ms -       4.09 ms       555      1.41 ms      782.56 ms
       4.10 ms -       8.19 ms         4      2.93 ms       11.71 ms
       8.19 ms -      16.38 ms        11      6.22 ms       68.41 ms
      16.38 ms -      32.77 ms        22     12.02 ms      264.34 ms
      32.77 ms -      65.53 ms        37     26.67 ms      986.65 ms
      65.54 ms -     131.07 ms       186     52.44 ms        9.75 s
     131.07 ms -     262.14 ms        24     73.87 ms        1.77 s

Device: /dev/nvme3n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
       8.19 ms -      16.38 ms         2      6.15 ms       12.30 ms
      16.38 ms -      32.77 ms       703     11.77 ms        8.27 s
      32.77 ms -      65.53 ms        29     23.07 ms      668.96 ms
      65.54 ms -     131.07 ms       190     50.80 ms        9.65 s
     131.07 ms -     262.14 ms        15     72.76 ms        1.09 s

Device: /dev/nvme4n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
     512.00 µs -       1.02 ms         1    508.00 µs      508.00 µs
       1.02 ms -       2.05 ms        59    738.56 µs       43.58 ms
       2.05 ms -       4.09 ms       488      1.42 ms      692.05 ms
       4.10 ms -       8.19 ms        10      2.45 ms       24.53 ms
       8.19 ms -      16.38 ms        10      6.14 ms       61.39 ms
      16.38 ms -      32.77 ms        23     12.04 ms      276.98 ms
      32.77 ms -      65.53 ms        49     27.19 ms        1.33 s
      65.54 ms -     131.07 ms       149     47.29 ms        7.05 s
     131.07 ms -     262.14 ms        35     72.03 ms        2.52 s

Max Concurrency Histogram:
          Range     Count
-------------------------
          1 - 1         8
       64 - 127         9
      128 - 255         3

Cumulative Stats by Device:
Device              Normal IOs Normal MB Burst IOs  Burst MB Total IOs  Total MB
--------------------------------------------------------------------------------
/dev/nvme0n1              6016     374.6       839      52.4      6855     427.0
/dev/nvme2n1              6101     374.5       837      52.3      6938     426.8
/dev/nvme3n1              5845     365.0       939      58.7      6784     423.7
/dev/nvme4n1              6037     374.8       822      51.4      6859     426.2
```

```
# ioburst -c 5 -d /dev/nvme0n1 -v
Monitoring devices: /dev/nvme0n1

2024-12-06 22:57:44
Device            IOPS  MB/s  Burst.IOPS  Burst.MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1       12    0.5           0         0.0         1

2024-12-06 22:57:45
Device            IOPS  MB/s  Burst.IOPS  Burst.MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1       12    0.1           0         0.0         1
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=13398us BURST
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=13470us BURST
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=13248us BURST
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=13354us BURST
# SNipped 1946 additional VERBOSE lines
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=60967us BURST
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=61775us BURST
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=60507us BURST
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=61032us BURST
VERBOSE: Dev=271581185 Comm=fio RWBS=WS Size=65536B Latency=61482us BURST

2024-12-06 22:57:46
Device            IOPS  MB/s  Burst.IOPS  Burst.MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1     2963  185.0        1956       122.2       124

2024-12-06 22:57:47
Device            IOPS  MB/s  Burst.IOPS  Burst.MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1        4    0.2           0         0.0       110

2024-12-06 22:57:48
Device            IOPS  MB/s  Burst.IOPS  Burst.MB/s  MaxConcur
-----------------------------------------------------------------
/dev/nvme0n1     1918  119.8           0         0.0        91

Standard Latency Histogram by Device:

Device: /dev/nvme0n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
     512.00 µs -       1.02 ms         1    507.00 µs      507.00 µs
       1.02 ms -       2.05 ms        12    897.58 µs       10.77 ms
       2.05 ms -       4.09 ms        26      1.45 ms       37.78 ms
       4.10 ms -       8.19 ms        22      2.86 ms       62.96 ms
       8.19 ms -      16.38 ms        33      5.97 ms      196.98 ms
      16.38 ms -      32.77 ms      1703     13.05 ms       22.22 s
      32.77 ms -      65.53 ms       119     16.77 ms        2.00 s
      65.54 ms -     131.07 ms      3601     60.49 ms      217.84 s
     131.07 ms -     262.14 ms       406     78.66 ms       31.93 s

Burst Latency Histogram by Device:

Device: /dev/nvme0n1
                 Latency Range     Count         Avg     Total Time
--------------------------------------------------------------------
      16.38 ms -      32.77 ms       642     11.05 ms        7.09 s
      32.77 ms -      65.53 ms        41     23.27 ms      953.95 ms
      65.54 ms -     131.07 ms       257     57.64 ms       14.81 s
     131.07 ms -     262.14 ms        39     73.66 ms        2.87 s

Max Concurrency Histogram:
          Range     Count
-------------------------
          1 - 1         2
       64 - 127         3

Cumulative Stats by Device:
Device              Normal IOs Normal MB Burst IOs  Burst MB Total IOs  Total MB
--------------------------------------------------------------------------------
/dev/nvme0n1              5923     369.0       979      61.2      6902     430.2
```

## Contributing

Contributions are welcome. Please open an issue or submit a pull request with any improvements, bug fixes, or feature requests.
