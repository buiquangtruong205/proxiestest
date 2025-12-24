import uvicorn
import sys
import socket
from contextlib import asynccontextmanager
from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from proxy_engine import ProxyChecker

# Global checker instance
checker = ProxyChecker()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for session management"""
    # Startup: Initialize session
    await checker.__aenter__()
    print("[OK] ProxyChecker session initialized")
    yield
    # Shutdown: Cleanup session
    await checker.__aexit__(None, None, None)
    print("[CLOSED] ProxyChecker session closed")

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class ProxyInput(BaseModel):
    host: str
    port: int
    login: str = ""
    password: str = ""
    protocol: str = "auto"  # 'auto', 'http', 'socks5', 'https'

@app.post("/api/check-proxy")
async def check_single_proxy(proxy: ProxyInput):
    """
    Check single proxy with RFC-compliant protocol detection
    
    Supports:
    - auto: Auto-detect protocol (SOCKS5, HTTP, HTTPS)
    - socks5: Force SOCKS5 (RFC 1928/1929)
    - http: Force HTTP (RFC 7230)
    - https: Force HTTPS/CONNECT (RFC 7231)
    """
    result = await checker.check_proxy_async(
        proxy.dict(), 
        timeout=10
    )
    return result

@app.get("/")
async def root():
    return {"message": "🔌 Proxy Checker API - RFC Compliant", "status": "running"}

if __name__ == "__main__":
    import json
    import os
    
    # Tự động tìm cổng trống
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    
    # Ghi port vào frontend/public để Vite serve được
    public_dir = os.path.join(os.path.dirname(__file__), '..', 'fontend', 'public')
    os.makedirs(public_dir, exist_ok=True)
    
    port_file = os.path.join(public_dir, 'port.json')
    with open(port_file, 'w') as f:
        json.dump({'port': port, 'url': f'http://127.0.0.1:{port}'}, f)
    
    print(f"")
    print(f"========================================")
    print(f"  Proxy Checker API - RFC Compliant")
    print(f"  Running on: http://127.0.0.1:{port}")
    print(f"  Port saved to: {port_file}")
    print(f"========================================")
    print(f"")
    sys.stdout.flush()

    uvicorn.run(app, host="127.0.0.1", port=port)