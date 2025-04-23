import os
import logging
import multiprocessing
import statistics
from datetime import datetime, timedelta
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from typing import Dict, Any

from ddos import execute_attack

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

manager = multiprocessing.Manager()
attack_processes: Dict[str, multiprocessing.Process] = {}
attack_stats = manager.dict()
attack_logs = manager.dict()
rate_limits: Dict[str, list] = {}  # IP -> list of datetime timestamps

RATE_LIMIT = 10  # max 10 attack requests per IP
RATE_WINDOW = timedelta(minutes=1)

# Header-based verification
@app.middleware("http")
async def verify_frontend_key(request: Request, call_next):
    expected_key = os.getenv("FRONTEND_KEY")
    incoming_key = request.headers.get("x-frontend-key")
    if expected_key and incoming_key != expected_key:
        return JSONResponse(status_code=403, content={"detail": "Forbidden: Invalid or missing frontend key."})
    return await call_next(request)

class AttackConfig(BaseModel):
    target_url: str
    duration: int
    intensity: int
    concurrent_connections: int
    attack_type: str

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

class AttackStats(BaseModel):
    requests_sent: int = 0
    connections_open: int = 0
    bytes_sent: int = 0
    errors: int = 0
    start_time: datetime = None
    complete: bool = False
    latency_samples: list = []
    http_status_codes: dict = {}
    timeout_count: int = 0
    bandwidth: dict = {}
    connection_metrics: dict = {}
    request_performance: dict = {}

    def to_dict(self) -> Dict[str, Any]:
        base = self.dict()
        latencies = base.get('latency_samples', []) or []
        min_latency = min(latencies) if latencies else None
        max_latency = max(latencies) if latencies else None
        avg_latency = statistics.mean(latencies) if latencies else None
        median_latency = statistics.median(latencies) if latencies else None
        base.update({
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'min_latency': min_latency,
            'max_latency': max_latency,
            'avg_latency': avg_latency,
            'median_latency': median_latency
        })
        return base

@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Service is running"}

@app.post("/api/attack/start")
async def start_attack(config: AttackConfig, request: Request):
    ip = request.client.host
    now = datetime.utcnow()
    request_times = rate_limits.setdefault(ip, [])
    request_times = [t for t in request_times if now - t < RATE_WINDOW]

    if len(request_times) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Rate limit exceeded. Try again later.")

    request_times.append(now)
    rate_limits[ip] = request_times

    attack_id = str(len(attack_processes) + 1)
    attack_stats[attack_id] = manager.dict({
        "requests_sent": 0,
        "errors": 0,
        "bytes_sent": 0,
        "complete": False,
        "start_time": now.isoformat(),
        "latency_samples": manager.list(),
        "http_status_codes": manager.dict(),
        "timeout_count": 0,
        "bandwidth": manager.dict({"total_data_transferred": 0, "peak_download": 0, "download_history": manager.list()}),
        "connection_metrics": manager.dict({"attempts": 0, "successes": 0, "active_connections": 0, "lifetimes": manager.list()}),
        "request_performance": manager.dict()
    })
    attack_logs[attack_id] = manager.list()

    process = multiprocessing.Process(
        target=execute_attack,
        args=(config, attack_stats[attack_id], attack_logs[attack_id]),
    )
    process.start()
    attack_processes[attack_id] = process
    logger.info(f"Started attack {attack_id} from {ip} with config {config}")
    return {"attack_id": attack_id}

@app.get("/api/attack/{attack_id}/stop")
async def stop_attack(attack_id: str):
    if attack_id in attack_processes:
        proc = attack_processes.pop(attack_id)
        proc.terminate()
        proc.join(timeout=5)
        if attack_id in attack_stats:
            attack_stats[attack_id]["complete"] = True
        logger.info(f"Stopped attack {attack_id}")
        return {"status": "stopped"}
    raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/logs")
async def get_logs(attack_id: str):
    if attack_id in attack_logs:
        return {"logs": list(attack_logs[attack_id])}
    raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/stats")
async def get_stats(attack_id: str):
    if attack_id in attack_stats:
        return {"stats": dict(attack_stats[attack_id])}
    raise HTTPException(status_code=404, detail="Attack not found")

@app.get("/api/attack/{attack_id}/stats/realtime")
async def get_realtime_stats(attack_id: str):
    if attack_id in attack_stats:
        return {"stats": dict(attack_stats[attack_id])}
    raise HTTPException(status_code=404, detail="Attack not found")

@app.on_event("shutdown")
def shutdown_cleanup():
    for pid, proc in attack_processes.items():
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=5)
    attack_processes.clear()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
