#!/usr/bin/env python3
"""
ioburst - Monitor disk IO operations, track performance, and identify bursts exceeding device thresholds.

This tool attaches to block layer tracepoints using eBPF to monitor specified block devices.
It tracks IO bandwidth, IOPS, and distinguishes "burst" operations that exceed configured
thresholds from "standard" operations. Upon exit, it prints latency histograms for both
standard and burst IOs. It can operate in a verbose mode that streams all completed IO events.

Key Features:
  - Tracks cumulative and per-interval stats for normal and burst IOs.
  - Monitors concurrency and provides histograms.
  - Offers adjustable limits for bandwidth and IOPS.
  - Reports final histograms and cumulative stats at exit.

Usage:
   ioburst [-h] [-d DEVICE] [--bandwidth MB/S] [--iops IOPS]
           [-c COUNT] [-i INTERVAL] [-v] [-p PID] [-m|-s|-u|-n]

Examples:
   # Monitor /dev/nvme0n1 with verbose burst-only output:
   ioburst -d /dev/nvme0n1 -v

   # Monitor automatically discovered NVMe devices, print stats every 1s, exit after 10 iterations:
   ioburst -c 10

   # Show all IO completions (both burst and normal):
   ioburst -d /dev/nvme0n1 -vv

Notes:
   - The -v/--verbose flag can be specified multiple times:
       -v : only print burst IO events
       -vv: print all IO events
   - IOs exceeding device thresholds are recorded as burst operations.
   - Histograms at the end display both counts and total time spent in each latency bucket.
   - Units can be adjusted with -m, -s, -u, -n or left as humanized by default.
"""

import argparse
import math
from pathlib import Path
from bcc import BPF
import os
import time
import ctypes as ct
from datetime import datetime
from collections import defaultdict

################################################################################
# BPF Program (in bpf_text)
#
# This bpf code tracks per-request latency by capturing block_rq_issue and
# block_rq_complete events. It logs normal vs. burst IO based on bandwidth/IOPS
# thresholds and stores latency histograms. It uses two histograms: one for
# standard IO operations and one for burst IO operations that exceeded given
# thresholds. It also maintains per-device cumulative stats and concurrency
# information.
#
#  - Use log2 histograms for latency.
#  - Maintains burst counters for IOs and bytes over the configured limits.
#  - Tracks concurrency to understand peak parallelism.
#  - A "burst" IO is defined as one completed during a period where limits
#    (bandwidth or IOPS) were exceeded.
#  - Requests are keyed by device, sector, and rwbs string to correlate issue
#    and completion events.
################################################################################

bpf_text = r"""
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>
#include <bcc/proto.h>

#define RWBS_LEN 8
#define COMM_LEN 16

struct io_limits {
    u64 bytes_per_sec;
    u64 iops_per_sec;
};

struct io_stats {
    u64 bytes;
    u64 iops;
    u64 last_update;
    u64 burst_bytes;
    u64 burst_iops;
    u64 current_concurrent;
    u64 max_concurrent;
    u64 total_normal_bytes;
    u64 total_normal_iops;
    u64 total_burst_bytes;
    u64 total_burst_iops;
};

struct rq_key {
    u32 dev;
    u64 sector;
    u32 nr_sector;
    char rwbs[RWBS_LEN];
};

struct rq_val {
    u64 start_ns;
    u32 tgid;
    char comm[COMM_LEN];
    u8 is_burst;
};

struct hist_key {
    u32 dev;
    u32 bucket;
};

struct hist_data {
    u64 count;
    u64 total_time_us;
};

struct event_data {
    u32 dev;
    u64 latency_us;
    u64 size;
    char rwbs[RWBS_LEN];
    char comm[COMM_LEN];
    u8 is_burst;
};

BPF_HASH(requests, struct rq_key, struct rq_val);
BPF_HASH(latency_hist_normal, struct hist_key, struct hist_data);
BPF_HASH(latency_hist_burst, struct hist_key, struct hist_data);
BPF_HASH(io_limits, u32, struct io_limits);
BPF_HASH(io_stats, u32, struct io_stats);
BPF_HASH(pid_filter, u32, u8);
BPF_HASH(filtering_enabled, u32, u8);

BPF_PERF_OUTPUT(events);

static __always_inline void update_stats_issue(u32 dev_key, u32 nr_sector) {
    struct io_limits *limits = io_limits.lookup(&dev_key);
    if (!limits) return;

    struct io_stats *stats = io_stats.lookup(&dev_key);
    u64 now = bpf_ktime_get_ns();

    if (!stats) {
        struct io_stats new_stats = {};
        new_stats.last_update = now;
        io_stats.update(&dev_key, &new_stats);
        stats = io_stats.lookup(&dev_key);
        if (!stats) return;
    }

    // Each second, reset counters used to check if current IOs exceed limits
    if (now - stats->last_update > 1000000000) {
        stats->bytes = 0;
        stats->iops = 0;
        stats->burst_bytes = 0;
        stats->burst_iops = 0;
        stats->last_update = now;
    }

    u64 bytes = (u64)nr_sector * 512ULL;
    stats->bytes += bytes;
    stats->iops++;
    stats->current_concurrent++;
    if (stats->current_concurrent > stats->max_concurrent)
        stats->max_concurrent = stats->current_concurrent;

    // We track burst activity so we know how many IOs were over the limit.
    if (stats->bytes > limits->bytes_per_sec || stats->iops > limits->iops_per_sec) {
        stats->burst_bytes += bytes;
        stats->burst_iops++;
    }

    io_stats.update(&dev_key, stats);
}

static __always_inline void update_stats_complete(u32 dev_key, u32 nr_sector, bool is_burst) {
    struct io_stats *stats = io_stats.lookup(&dev_key);
    if (!stats) return;

    u64 bytes = (u64)nr_sector * 512ULL;
    if (is_burst) {
        stats->total_burst_bytes += bytes;
        stats->total_burst_iops++;
    } else {
        stats->total_normal_bytes += bytes;
        stats->total_normal_iops++;
    }

    // Reduce concurrency after completion
    if (stats->current_concurrent > 0)
        stats->current_concurrent--;

    io_stats.update(&dev_key, stats);
}

TRACEPOINT_PROBE(block, block_rq_issue) {
    u32 z = 0;
    u8 *enabled = filtering_enabled.lookup(&z);
    if (enabled && *enabled == 1) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 tgid = pid_tgid >> 32; // This is the process pid (tgid)

        u8 *exists = pid_filter.lookup(&tgid);
        if (!exists) {
            return 0; // This tgid is not monitored
        }
    }

    struct rq_key key = {};
    key.dev = args->dev;
    key.sector = args->sector;
    key.nr_sector = args->nr_sector;
    __builtin_memcpy(key.rwbs, args->rwbs, RWBS_LEN);

    struct rq_val val = {};
    val.start_ns = bpf_ktime_get_ns();
    bpf_probe_read_str(val.comm, sizeof(val.comm), (void*)args->comm);

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tgid = pid_tgid >> 32;
    val.tgid = tgid;

    requests.update(&key, &val);

    u32 dev_key = args->dev;
    update_stats_issue(dev_key, args->nr_sector);

    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    struct rq_key key = {};
    key.dev = args->dev;
    key.sector = args->sector;
    key.nr_sector = args->nr_sector;
    __builtin_memcpy(key.rwbs, args->rwbs, RWBS_LEN);

    struct rq_val *val = requests.lookup(&key);
    if (!val)
        return 0;

    u64 now = bpf_ktime_get_ns();
    u64 latency_ns = now - val->start_ns;

    // Retrieve the tgid of the process that issued the IO
    u32 tgid = val->tgid;

    // Check if filtering is enabled and if this tgid is allowed
    u32 z = 0;
    u8 *enabled = filtering_enabled.lookup(&z);
    if (enabled && *enabled == 1) {
        u8 *exists = pid_filter.lookup(&tgid);
        if (!exists) {
            // Not a monitored tgid, remove from requests and skip processing
            requests.delete(&key);
            return 0;
        }
    }

    // Now that we know we want to process this event, remove it from the map
    requests.delete(&key);

    u64 latency_us = latency_ns / 1000;

    u32 dev_key = args->dev;
    struct io_stats *stats = io_stats.lookup(&dev_key);
    if (!stats) return 0;
    struct io_limits *limits = io_limits.lookup(&dev_key);
    if (!limits) return 0;

    // Determine if over limits
    bool over_limits = false;
    if (stats->bytes > limits->bytes_per_sec || stats->iops > limits->iops_per_sec) {
        u64 bytes = (u64)args->nr_sector * 512ULL;
        stats->burst_bytes += bytes;
        stats->burst_iops++;
        over_limits = true;
    }

    bool is_burst = over_limits;
    update_stats_complete(args->dev, args->nr_sector, is_burst);

    // Log latency in the appropriate histogram
    u64 bucket = bpf_log2l(latency_us);
    struct hist_key hkey = {
        .dev = args->dev,
        .bucket = (u32)bucket
    };

    struct hist_data init_val = {};
    struct hist_data *histp;
    if (is_burst) {
        histp = latency_hist_burst.lookup_or_init(&hkey, &init_val);
    } else {
        histp = latency_hist_normal.lookup_or_init(&hkey, &init_val);
    }

    if (histp) {
        histp->count += 1;
        histp->total_time_us += latency_us;
    }

    // Submit event for verbose output
    struct event_data evt = {};
    evt.dev = args->dev;
    evt.latency_us = latency_us;
    u64 bytes = (u64)args->nr_sector * 512ULL;
    evt.size = bytes;
    __builtin_memcpy(evt.rwbs, args->rwbs, RWBS_LEN);
    __builtin_memcpy(evt.comm, val->comm, COMM_LEN);
    evt.is_burst = is_burst ? 1 : 0;

    events.perf_submit(args, &evt, sizeof(evt));

    return 0;
}
"""

################################################################################
# CTYPE STRUCTS
################################################################################

class IOLimits(ct.Structure):
    _fields_ = [
        ("bytes_per_sec", ct.c_uint64),
        ("iops_per_sec", ct.c_uint64)
    ]

class IOStats(ct.Structure):
    _fields_ = [
        ("bytes", ct.c_uint64),
        ("iops", ct.c_uint64),
        ("last_update", ct.c_uint64),
        ("burst_bytes", ct.c_uint64),
        ("burst_iops", ct.c_uint64),
        ("current_concurrent", ct.c_uint64),
        ("max_concurrent", ct.c_uint64),
        ("total_normal_bytes", ct.c_uint64),
        ("total_normal_iops", ct.c_uint64),
        ("total_burst_bytes", ct.c_uint64),
        ("total_burst_iops", ct.c_uint64)
    ]

class HistKey(ct.Structure):
    _fields_ = [
        ("dev", ct.c_uint32),
        ("bucket", ct.c_uint32),
    ]

class HistData(ct.Structure):
    _fields_ = [
        ("count", ct.c_uint64),
        ("total_time_us", ct.c_uint64)
    ]

class EventData(ct.Structure):
    _fields_ = [
        ("dev", ct.c_uint32),
        ("latency_us", ct.c_uint64),
        ("size", ct.c_uint64),
        ("rwbs", ct.c_char * 8),
        ("comm", ct.c_char * 16),
        ("is_burst", ct.c_ubyte)
    ]

################################################################################
# GLOBALS
################################################################################

concurrency_hist = defaultdict(int)
TIME_UNIT_MODE = 'human'

################################################################################
# FUNCTIONS (ALPHABETICALLY SORTED)
################################################################################

def discover_devices():
    """
    Discover a default set of NVMe devices to monitor, excluding the boot device if identified.
    Returns a sorted list of device paths.
    """
    boot_device = None
    boot_link = Path('/dev/disk/by-label/BOOT')
    if boot_link.exists():
        boot_device = os.path.realpath(boot_link).split('p')[0]

    devices = []
    for device in Path('/sys/block').glob('nvme*n1'):
        dev_path = f"/dev/{device.name}"
        if boot_device and dev_path == boot_device:
            continue
        devices.append(dev_path)

    return sorted(devices)

def format_time_us(value_us):
    """
    Convert a latency in microseconds to a human-friendly string with appropriate units.
    For large latencies, use ms or s. This helps in histogram printing.
    """
    if value_us < 1000:
        value = value_us
        unit = "µs"
    elif value_us < 1000000:
        value = value_us / 1000.0
        unit = "ms"
    else:
        value = value_us / 1000000.0
        unit = "s"
    return f"{value:10.2f} {unit:<2}"

def main():
    """
    Parse arguments, attach BPF probes, and run the monitoring loop.
    After user interruption or after a specified count, print histograms and stats.
    """
    parser = argparse.ArgumentParser(description='Monitor block device IO')
    parser.add_argument('-d', '--device', action='append', help='Device to monitor')
    parser.add_argument('--bandwidth', type=int, default=125, help='Bandwidth limit in MB/s')
    parser.add_argument('--iops', type=int, default=3000, help='IOPS limit')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of iterations')
    parser.add_argument('-i', '--interval', type=float, default=1.0, help='Sampling interval in seconds')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='Increase verbosity: -v for burst only, -vv for all IOs.')
    parser.add_argument('-p', '--pid', action='extend',
                    type=lambda x: [int(v) for v in x.strip().split()],
                    default=[],
                    help='Only monitor IOs from these PIDs (can accept multiple PIDs separated by whitespace).')

    unit_group = parser.add_mutually_exclusive_group()
    unit_group.add_argument('-m', '--milliseconds', action='store_true')
    unit_group.add_argument('-s', '--seconds', action='store_true')
    unit_group.add_argument('-u', '--microseconds', action='store_true')
    unit_group.add_argument('-n', '--nanoseconds', action='store_true')
    unit_group.add_argument('-H', '--humanized', action='store_true', default=True)

    args = parser.parse_args()

    if args.milliseconds:
        time_unit = 'ms'
    elif args.seconds:
        time_unit = 's'
    elif args.microseconds:
        time_unit = 'us'
    elif args.nanoseconds:
        time_unit = 'ns'
    else:
        time_unit = 'human'

    devices = args.device if args.device else discover_devices()
    if not devices:
        print("No devices found to monitor")
        return 1

    print(f"Monitoring devices: {', '.join(devices)}")

    b = BPF(text=bpf_text)
    set_device_limits(b, devices, args.bandwidth * 1024 * 1024, args.iops)

    # If no PIDs specified, means no filtering by PID. We can handle that logic in BPF.
    # If PIDs specified, for each PID, add it to the pid_filter map.
    if args.pid:  # args.pid is a list of PIDs
        b["filtering_enabled"][ct.c_uint32(0)] = ct.c_ubyte(1)
        for p in args.pid:
            b["pid_filter"][ct.c_uint32(p)] = ct.c_ubyte(1)
    else:
        b["filtering_enabled"][ct.c_uint32(0)] = ct.c_ubyte(0)

    global TIME_UNIT_MODE
    TIME_UNIT_MODE = time_unit

    if args.verbose > 0:
        b["events"].open_perf_buffer(lambda cpu, data, size: print_event(cpu, data, size, args, b))

    iteration = 0
    try:
        while args.count == 0 or iteration < args.count:
            if args.verbose > 0:
                # Poll perf buffer to print events
                start = time.time()
                while (time.time() - start) < args.interval:
                    b.perf_buffer_poll(timeout=100)
            else:
                time.sleep(args.interval)

            print_stats(b, devices)
            iteration += 1
    except KeyboardInterrupt:
        pass
    finally:
        print_latency_histograms(b, devices, "Standard", "latency_hist_normal")
        print_latency_histograms(b, devices, "Burst", "latency_hist_burst")
        print_concurrency_histogram(concurrency_hist)
        print_cumulative_stats(b, devices)

def make_dev(major, minor):
    """
    Convert major/minor numbers to a single dev_t-like value used as a device key.
    """
    return (major << 20) | minor

def print_concurrency_histogram(concurrency_hist):
    """
    Print a concurrency histogram showing how often concurrency fell into log2-based buckets.
    """
    range_width = 15
    count_width = 10

    hdr_range = "Range"
    hdr_count = "Count"
    hdr_line = f"{hdr_range:>{range_width}}{hdr_count:>{count_width}}"
    sep_line = "-" * (range_width + count_width)

    print("\nMax Concurrency Histogram:")
    print(hdr_line)
    print(sep_line)

    for bucket, c in sorted(concurrency_hist.items()):
        low = 1 << bucket
        high = (1 << (bucket + 1)) - 1
        range_str = f"{low} - {high}"
        row = f"{range_str:>{range_width}}{c:>{count_width}}"
        print(row)

def print_cumulative_stats(b, devices):
    """
    Print cumulative stats for each device, including normal and burst IO totals.
    """
    device_width = 20
    normal_ios_width = 10
    normal_mb_width = 10
    burst_ios_width = 10
    burst_mb_width = 10
    total_ios_width = 10
    total_mb_width = 10

    hdr_device = "Device"
    hdr_normal_ios = "Normal IOs"
    hdr_normal_mb = "Normal MB"
    hdr_burst_ios = "Burst IOs"
    hdr_burst_mb = "Burst MB"
    hdr_total_ios = "Total IOs"
    hdr_total_mb = "Total MB"

    hdr_line = (f"{hdr_device:<{device_width}}"
                f"{hdr_normal_ios:>{normal_ios_width}}"
                f"{hdr_normal_mb:>{normal_mb_width}}"
                f"{hdr_burst_ios:>{burst_ios_width}}"
                f"{hdr_burst_mb:>{burst_mb_width}}"
                f"{hdr_total_ios:>{total_ios_width}}"
                f"{hdr_total_mb:>{total_mb_width}}")

    sep_line = "-" * (device_width + normal_ios_width + normal_mb_width +
                      burst_ios_width + burst_mb_width + total_ios_width + total_mb_width)

    print("\nCumulative Stats by Device:")
    print(hdr_line)
    print(sep_line)

    for device in devices:
        try:
            st = os.stat(device)
            dev = (os.major(st.st_rdev) << 20) | os.minor(st.st_rdev)
            stats = b['io_stats'][ct.c_uint32(dev)]
            normal_mb = stats.total_normal_bytes / (1024*1024)
            burst_mb = stats.total_burst_bytes / (1024*1024)
            total_iops = stats.total_normal_iops + stats.total_burst_iops
            total_mb = normal_mb + burst_mb

            row = (f"{device:<{device_width}}"
                   f"{stats.total_normal_iops:>{normal_ios_width}}"
                   f"{normal_mb:>{normal_mb_width}.1f}"
                   f"{stats.total_burst_iops:>{burst_ios_width}}"
                   f"{burst_mb:>{burst_mb_width}.1f}"
                   f"{total_iops:>{total_ios_width}}"
                   f"{total_mb:>{total_mb_width}.1f}")
            print(row)
        except (KeyError, FileNotFoundError):
            print(f"{device:<{device_width}}{'No stats available':>{normal_ios_width+normal_mb_width+burst_ios_width+burst_mb_width+total_ios_width+total_mb_width}}")

def print_event(cpu, data, size, args, b):
    """
    Print a single IO event if it meets verbosity criteria.
    In -v mode, only burst IOs are printed.
    In -vv mode, all IOs are printed.
    """
    evt = b["events"].event(data)
    comm_str = evt.comm.decode('utf-8', 'replace').rstrip('\x00')
    rwbs_str = evt.rwbs.decode('utf-8', 'replace').rstrip('\x00')

    if args.verbose == 1 and evt.is_burst == 0:
        return

    print(f"VERBOSE: Dev={evt.dev} Comm={comm_str} RWBS={rwbs_str} "
          f"Size={evt.size}B Latency={evt.latency_us}us "
          f"{'BURST' if evt.is_burst else 'NORMAL'}")

def print_latency_histograms(b, devices, title, map_name):
    """
    Print latency histograms for either standard or burst IOs.
    Each bucket is log2-based, showing count and total time spent.
    """
    print(f"\n{title} Latency Histogram by Device:")
    hist_map = b.get_table(map_name)

    range_width = 30
    count_width = 10
    avg_width = 12
    total_width = 15

    hdr_range = "Latency Range"
    hdr_count = "Count"
    hdr_avg = "Avg"
    hdr_total = "Total Time"

    hdr_line = (f"{hdr_range:>{range_width}}"
                f"{hdr_count:>{count_width}}"
                f"{hdr_avg:>{avg_width}}"
                f"{hdr_total:>{total_width}}")

    sep_line = "-" * (range_width + count_width + avg_width + total_width + 1)

    for device in devices:
        try:
            st = os.stat(device)
            dev = (os.major(st.st_rdev) << 20) | os.minor(st.st_rdev)
            device_hist = defaultdict(lambda: [0,0])

            for k, v in hist_map.items():
                if k.dev == dev:
                    device_hist[k.bucket][0] = v.count
                    device_hist[k.bucket][1] = v.total_time_us

            print(f"\nDevice: {device}")
            if not device_hist:
                print("No latency data available")
                continue

            print(hdr_line)
            print(sep_line)

            for bucket in sorted(device_hist.keys()):
                count = device_hist[bucket][0]
                ttime_us = device_hist[bucket][1]
                if count > 0:
                    latency_start_us = (1 << bucket)
                    latency_end_us = ((1 << (bucket + 1)) - 1)
                    avg_us = ttime_us / count

                    latency_start_str = format_time_us(latency_start_us)
                    latency_end_str = format_time_us(latency_end_us)
                    avg_str = format_time_us(avg_us)
                    ttime_str = format_time_us(ttime_us)
                    range_str = f"{latency_start_str} - {latency_end_str}"

                    row = (f"{range_str:>{range_width}}"
                           f"{str(count):>{count_width}}"
                           f"{avg_str:>{avg_width}}"
                           f"{ttime_str:>{total_width}}")
                    print(row)

        except (KeyError, FileNotFoundError):
            print(f"{device}: No latency data available")

def print_stats(b, devices):
    """
    Print current interval stats for each device, including IOPS, MB/s, and concurrency.
    After printing, reset counters for the next interval.
    """
    print(f"\n{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Device            IOPS  MB/s  Burst IOPS  Burst MB/s  MaxConcur")
    print("-" * 65)

    for device in devices:
        try:
            st = os.stat(device)
            major = os.major(st.st_rdev)
            minor = os.minor(st.st_rdev)
            dev = make_dev(major, minor)
            stats = b['io_stats'][ct.c_uint32(dev)]

            mb_per_sec = stats.bytes / (1024 * 1024)
            burst_mb_per_sec = stats.burst_bytes / (1024 * 1024)

            print(f"{device:15} {stats.iops:5} {mb_per_sec:6.1f} {stats.burst_iops:11} "
                  f"{burst_mb_per_sec:11.1f} {stats.max_concurrent:9}")

            # Update concurrency histogram
            concurrency = stats.max_concurrent
            bucket = 0
            if concurrency > 0:
                bucket = int(math.log2(concurrency))
            concurrency_hist[bucket] += 1

            # Reset stats counters for next iteration
            stats.bytes = 0
            stats.iops = 0
            stats.burst_bytes = 0
            stats.burst_iops = 0
            stats.max_concurrent = stats.current_concurrent
            stats.last_update = int(time.time() * 1e9)
            b['io_stats'][ct.c_uint32(dev)] = stats

        except (KeyError, FileNotFoundError):
            print(f"{device:15} No stats available")

def set_device_limits(b, device_paths, bytes_per_sec, iops_per_sec):
    """
    Set per-device IO bandwidth and IOPS limits, which define when IOs are considered "burst."
    """
    limits = IOLimits(bytes_per_sec, iops_per_sec)
    for device_path in device_paths:
        try:
            st = os.stat(device_path)
            major = os.major(st.st_rdev)
            minor = os.minor(st.st_rdev)
            dev = make_dev(major, minor)
            b['io_limits'][ct.c_uint32(dev)] = limits
        except FileNotFoundError:
            print(f"Device {device_path} not found")

if __name__ == '__main__':
    main()
