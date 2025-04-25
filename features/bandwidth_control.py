import psutil, GPUtil
import time
import win32com.client, platform
from collections import deque

# Global variables to track instantaneous usage calculations
previous_sent = 0
previous_received = 0
previous_time = None

# We'll store (timestamp, sent_mbps, received_mbps) for the last hour
traffic_data = deque()

def get_current_bandwidth_usage():
    """
    Computes current (instant) bandwidth usage in Mbps
    and also aggregates usage over the last hour.
    Returns a dict with:
      {
        'instant': {'sent': x, 'received': y},
        'hour': {
           'min_sent': ...,
           'max_sent': ...,
           'avg_sent': ...,
           'min_received': ...,
           'max_received': ...,
           'avg_received': ...
        }
      }
    }
    """
    global previous_sent, previous_received, previous_time, traffic_data

    net_stats = psutil.net_io_counters()
    current_sent = net_stats.bytes_sent
    current_received = net_stats.bytes_recv
    current_time = time.time()

    # On the first call, initialize counters
    if previous_time is None:
        previous_sent = current_sent
        previous_received = current_received
        previous_time = current_time
        # Return zero for instant usage on the very first call
        return {
            'instant': {'sent': 0.0, 'received': 0.0},
            'hour': {
                'min_sent': 0.0, 'max_sent': 0.0, 'avg_sent': 0.0,
                'min_received': 0.0, 'max_received': 0.0, 'avg_received': 0.0
            }
        }

    elapsed_time = current_time - previous_time
    # Avoid division-by-zero if elapsed_time is 0 or negative
    if elapsed_time <= 0:
        elapsed_time = 1

    # Calculate how many bytes were sent/received in this interval
    diff_sent = current_sent - previous_sent
    diff_received = current_received - previous_received

    # Update previous trackers
    previous_sent = current_sent
    previous_received = current_received
    previous_time = current_time

    # Convert bytes per second to Mbps:
    sent_mbps = (diff_sent * 8) / (1024 * 1024 * elapsed_time)
    received_mbps = (diff_received * 8) / (1024 * 1024 * elapsed_time)

    # Optional clamp to prevent unrealistic spikes
    max_allowed_mbps = 1000
    sent_mbps = min(sent_mbps, max_allowed_mbps)
    received_mbps = min(received_mbps, max_allowed_mbps)

    # Store this data point in a deque
    traffic_data.append((current_time, sent_mbps, received_mbps))

    # Remove data points older than one hour (3600 seconds)
    one_hour_ago = current_time - 3600
    while traffic_data and traffic_data[0][0] < one_hour_ago:
        traffic_data.popleft()

    # Calculate min, max, avg over the last hour
    # If the deque is empty (very unlikely here), return 0 for stats
    if not traffic_data:
        hour_stats = {
            'min_sent': 0.0, 'max_sent': 0.0, 'avg_sent': 0.0,
            'min_received': 0.0, 'max_received': 0.0, 'avg_received': 0.0
        }
    else:
        min_sent = min(dp[1] for dp in traffic_data)
        max_sent = max(dp[1] for dp in traffic_data)
        avg_sent = sum(dp[1] for dp in traffic_data) / len(traffic_data)

        min_received = min(dp[2] for dp in traffic_data)
        max_received = max(dp[2] for dp in traffic_data)
        avg_received = sum(dp[2] for dp in traffic_data) / len(traffic_data)

        hour_stats = {
            'min_sent': round(min_sent, 2),
            'max_sent': round(max_sent, 2),
            'avg_sent': round(avg_sent, 2),
            'min_received': round(min_received, 2),
            'max_received': round(max_received, 2),
            'avg_received': round(avg_received, 2)
        }

    return {
        'instant': {
            'sent': round(sent_mbps, 2),
            'received': round(received_mbps, 2)
        },
        'hour': hour_stats
    }


def get_gpu_temperature():
    """Fetch GPU temperature using GPUtil."""
    try:
        gpus = GPUtil.getGPUs()
        return round(gpus[0].temperature, 2) if gpus else 0
    except Exception as e:
        print(f"Error fetching GPU temperature: {e}")
        return 0

def get_disk_usage():
    """Fetch the disk usage percentage for the main drive."""
    try:
        disk_usage = psutil.disk_usage("C:")
        print(f"C Drive Usage: {disk_usage.percent}%")
        return disk_usage.percent
    except Exception as e:
        print(f"Error fetching C drive usage: {e}")

def get_cpu_processes():
    """Return top 10 processes sorted by CPU usage."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(processes, key=lambda p: p.get('cpu_percent', 0), reverse=True)[:10]

def get_memory_processes():
    """Return top 10 processes sorted by memory usage."""
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'memory_percent']):
        try:
            processes.append(proc.info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return sorted(processes, key=lambda p: p.get('memory_percent', 0), reverse=True)[:10]

def get_gpu_processes():
    """Return processes using the GPU (up to 10)."""
    gpu_processes = []
    gpus = GPUtil.getGPUs()
    for gpu in gpus:
        if gpu.processes:
            for proc in gpu.processes:
                pid = proc.get('pid')
                try:
                    p = psutil.Process(pid)
                    gpu_processes.append({
                        'pid': pid,
                        'name': p.name(),
                        'gpu_memory_usage': proc.get('gpu_memory_usage', 0)
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    return sorted(gpu_processes, key=lambda p: p.get('gpu_memory_usage', 0), reverse=True)[:10]




