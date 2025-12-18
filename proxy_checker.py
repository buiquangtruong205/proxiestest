#!/usr/bin/env python3
"""
🔥 PROXY CHECKER - Production-Quality
======================================
Công cụ check proxy live/die tối ưu cho PyQt6 integration.

Tính năng:
- Session Singleton (1 aiohttp session duy nhất)
- Async DNS Resolution (không blocking)
- Smart Protocol Detection với Early Exit
- Timeout Budget phân bổ hợp lý
- Judge URL Fallback
- RFC-compliant validation
- Async Generator cho UI callback

Logic check (RFC-compliant):
1. TCP Connect Test
2. Smart Protocol Detection (SOCKS5/HTTP/HTTPS) với Early Exit
3. Verify Forward (Judge URL với fallback)

Usage CLI:
    python proxy_checker.py proxies.txt --concurrency 500 --timeout 10

Usage PyQt6:
    async with ProxyChecker() as checker:
        async for result in checker.check_proxies_async(proxies):
            update_ui(result)
"""

import asyncio
import aiohttp
import argparse
import time
import sys
import socket
import struct
import io
import os
import re
import base64
from dataclasses import dataclass
from typing import List, Optional, Dict, AsyncGenerator, Callable, Any
from enum import Enum

# Thư mục chứa script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Fix UTF-8 encoding cho Windows console (chỉ dùng khi chạy CLI)
if sys.platform == 'win32' and sys.stdout:
    try:
        sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')
    except Exception:
        pass


# ==================== CONSTANTS ====================
# RFC 1929: Username/Password tối đa 255 bytes
MAX_AUTH_BYTES = 255

# Regex parse HTTP status line (RFC 7230)
HTTP_STATUS_REGEX = re.compile(r'^HTTP/\d\.\d\s+(\d{3})\b')

# Judge URLs với fallback
DEFAULT_JUDGE_URLS = [
    "http://httpbin.org/ip",
    "http://api.ipify.org",
    "http://checkip.amazonaws.com"
]

# IP pattern để extract từ response
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def get_max_concurrency() -> int:
    """
    Lấy giới hạn concurrent connections dựa theo OS.
    
    Windows: Max ~500 (do giới hạn select() ~512 FDs)
    macOS/Linux: Có thể lên 1000+
    """
    if sys.platform == 'win32':
        return 500
    else:
        return 1000


class ProxyStatus(Enum):
    LIVE = "LIVE"
    DIE = "DIE"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


@dataclass
class ProxyResult:
    """Kết quả check proxy."""
    proxy: str
    status: ProxyStatus
    protocol: Optional[str] = None
    response_time_ms: int = 0
    public_ip: Optional[str] = None
    error: Optional[str] = None


class ProxyChecker:
    """
    Async Proxy Checker - Production Quality.
    
    Tính năng:
    - Session Singleton: Chỉ 1 aiohttp.ClientSession
    - Async DNS: Dùng loop.getaddrinfo, không blocking
    - Smart Protocol Detection: Early exit khi tìm thấy protocol
    - Timeout Budget: TCP 20%, Handshake 30%, Verify 50%
    - Judge URL Fallback
    - Async Generator cho PyQt6 integration
    
    Usage:
        async with ProxyChecker(timeout=10) as checker:
            async for result in checker.check_proxies_async(proxies):
                # Xử lý từng result
                pass
    """
    
    def __init__(
        self, 
        concurrency: Optional[int] = None, 
        timeout: int = 10,
        judge_urls: Optional[List[str]] = None,
        callback: Optional[Callable[[ProxyResult, int, int], None]] = None
    ):
        """
        Khởi tạo ProxyChecker.
        
        Args:
            concurrency: Số kết nối đồng thời (None = tự động theo OS)
            timeout: Timeout tổng (giây)
            judge_urls: Danh sách Judge URL (có fallback)
            callback: Callback function(result, checked, total) cho UI
        """
        # Tự động set concurrency theo OS nếu không chỉ định
        if concurrency is None:
            concurrency = get_max_concurrency()
        
        self.concurrency = min(concurrency, get_max_concurrency())
        self.timeout = timeout
        self.judge_urls = judge_urls or DEFAULT_JUDGE_URLS
        self.callback = callback
        
        # Timeout budget
        self.tcp_timeout = max(1, int(timeout * 0.2))
        self.handshake_timeout = max(1, int(timeout * 0.3))
        self.verify_timeout = max(2, int(timeout * 0.5))
        
        # Session singleton (khởi tạo trong __aenter__)
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Semaphore để giới hạn concurrent
        self.semaphore = asyncio.Semaphore(self.concurrency)
        
        # Batch size cho Windows compatibility
        self._batch_size = min(200, self.concurrency)
        
        # Statistics
        self.total = 0
        self.checked = 0
        self.live_count = 0
        self.die_count = 0
    
    async def __aenter__(self):
        """Context manager entry - khởi tạo session singleton."""
        connector = aiohttp.TCPConnector(
            limit=0,  # Không giới hạn (dùng semaphore thay thế)
            ttl_dns_cache=300,  # Cache DNS 5 phút
            use_dns_cache=True,
            ssl=False  # Tắt SSL verify để tăng tốc
        )
        self.session = aiohttp.ClientSession(connector=connector)
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        """Context manager exit - đóng session."""
        if self.session:
            await self.session.close()
            self.session = None
    
    # ==================== ASYNC DNS RESOLUTION ====================
    async def _resolve_ip(self, host: str, port: int = 80) -> Optional[str]:
        """
        Async DNS resolution - không blocking.
        
        Thay thế socket.gethostbyname() bằng loop.getaddrinfo().
        
        Args:
            host: Hostname cần resolve
            port: Port (dùng cho getaddrinfo)
            
        Returns:
            IP address hoặc None nếu lỗi
        """
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(
                host, port, 
                family=socket.AF_INET,
                type=socket.SOCK_STREAM
            )
            if addr_info:
                return addr_info[0][4][0]
            return None
        except Exception:
            return None
    
    # ==================== VALIDATION ====================
    def _validate_auth_length(self, username: str, password: str) -> Optional[str]:
        """
        Kiểm tra độ dài user/pass theo RFC 1929 (max 255 bytes).
        
        Returns:
            Error message nếu không hợp lệ, None nếu OK
        """
        if username:
            user_bytes = len(username.encode('utf-8'))
            if user_bytes > MAX_AUTH_BYTES:
                return f"Username quá dài ({user_bytes} bytes, max {MAX_AUTH_BYTES})"
        
        if password:
            pass_bytes = len(password.encode('utf-8'))
            if pass_bytes > MAX_AUTH_BYTES:
                return f"Password quá dài ({pass_bytes} bytes, max {MAX_AUTH_BYTES})"
        
        return None
    
    def _parse_http_status(self, response_str: str) -> Optional[int]:
        """
        Parse HTTP status code từ response string.
        
        Sử dụng regex thay vì string matching lỏng lẻo.
        
        Returns:
            Status code (int) hoặc None nếu invalid
        """
        lines = response_str.split('\r\n')
        if not lines:
            return None
        
        match = HTTP_STATUS_REGEX.match(lines[0])
        if match:
            return int(match.group(1))
        return None
    
    # ==================== PROXY PARSING ====================
    def parse_proxy_line(self, line: str) -> Optional[dict]:
        """
        Parse proxy line - hỗ trợ nhiều format.
        
        Formats:
        - host:port
        - host:port:user:pass
        - protocol://host:port
        - protocol://host:port:user:pass
        """
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        protocol = None
        
        # Check có protocol prefix không
        if "://" in line:
            parts = line.split("://", 1)
            protocol = parts[0].lower()
            line = parts[1]
        
        # Parse host:port:user:pass
        parts = line.split(":")
        if len(parts) < 2:
            return None
        
        try:
            host = parts[0]
            port = int(parts[1])
            user = parts[2] if len(parts) > 2 else ""
            password = parts[3] if len(parts) > 3 else ""
            
            return {
                'host': host,
                'port': port,
                'login': user,
                'password': password,
                'protocol': protocol,
                'original': f"{host}:{port}"
            }
        except (ValueError, IndexError):
            return None
    
    # ==================== TCP CONNECT TEST ====================
    async def _test_tcp_connect(self, host: str, port: int) -> bool:
        """
        STEP 0: Test TCP connection.
        
        Dùng asyncio.open_connection (non-blocking).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.tcp_timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False
    
    # ==================== SOCKS5 HANDSHAKE (RFC 1928 + 1929) ====================
    async def _test_socks5_handshake(
        self, host: str, port: int, 
        username: str, password: str
    ) -> Dict:
        """
        Test SOCKS5 handshake theo RFC 1928 + 1929.
        
        Handshake flow:
        1. Client gửi: VER | NMETHODS | METHODS
        2. Server trả: VER | METHOD
        3. Nếu cần auth: RFC 1929 subnegotiation
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.handshake_timeout
            )
            
            try:
                # STEP 1: Gửi greeting
                if username and password:
                    # Hỗ trợ: No auth (0x00) + Username/Password (0x02)
                    writer.write(b'\x05\x02\x00\x02')
                else:
                    # Chỉ No auth (0x00)
                    writer.write(b'\x05\x01\x00')
                await writer.drain()
                
                # STEP 2: Đọc response
                response = await asyncio.wait_for(
                    reader.read(2), 
                    timeout=self.handshake_timeout
                )
                
                if len(response) < 2:
                    return {'success': False, 'error': 'Invalid SOCKS5 response'}
                
                version, method = response[0], response[1]
                
                # Verify SOCKS5 version
                if version != 0x05:
                    return {'success': False, 'error': f'Not SOCKS5 (version={version})'}
                
                # STEP 3: Handle authentication
                if method == 0x02:  # Username/Password auth required
                    if not username or not password:
                        return {'success': False, 'error': 'Auth required but no credentials'}
                    
                    # RFC 1929: Username/Password subnegotiation
                    auth_packet = bytes([0x01, len(username)]) + username.encode()
                    auth_packet += bytes([len(password)]) + password.encode()
                    writer.write(auth_packet)
                    await writer.drain()
                    
                    auth_response = await asyncio.wait_for(
                        reader.read(2), 
                        timeout=self.handshake_timeout
                    )
                    if len(auth_response) < 2 or auth_response[1] != 0x00:
                        return {'success': False, 'error': 'SOCKS5 auth failed'}
                
                elif method == 0xFF:
                    return {'success': False, 'error': 'No acceptable auth method'}
                
                # Handshake thành công!
                return {'success': True, 'protocol': 'socks5'}
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    # ==================== HTTP PROXY HANDSHAKE (RFC 7230) ====================
    async def _test_http_handshake(
        self, host: str, port: int,
        username: str, password: str
    ) -> Dict:
        """
        Test HTTP Proxy handshake.
        
        Gửi request HEAD đến proxy và check response.
        Dùng regex để parse status code (strict).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.handshake_timeout
            )
            
            try:
                # Gửi HTTP request qua proxy
                request = f"HEAD http://httpbin.org/ip HTTP/1.1\r\n"
                request += f"Host: httpbin.org\r\n"
                
                # Add auth header nếu có
                if username and password:
                    credentials = base64.b64encode(
                        f"{username}:{password}".encode()
                    ).decode()
                    request += f"Proxy-Authorization: Basic {credentials}\r\n"
                
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                # Đọc response
                response = await asyncio.wait_for(
                    reader.read(1024), 
                    timeout=self.handshake_timeout
                )
                response_str = response.decode('utf-8', errors='ignore')
                
                # Parse HTTP status với regex (strict)
                status_code = self._parse_http_status(response_str)
                if status_code:
                    if status_code in (200, 301, 302):
                        return {'success': True, 'protocol': 'http'}
                    elif status_code == 407:
                        return {'success': False, 'error': 'Proxy auth required'}
                
                return {'success': False, 'error': 'Invalid HTTP response'}
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    # ==================== HTTPS CONNECT HANDSHAKE (RFC 7231) ====================
    async def _test_https_handshake(
        self, host: str, port: int,
        username: str, password: str
    ) -> Dict:
        """
        Test HTTPS CONNECT tunnel.
        
        CONNECT method để tạo tunnel qua proxy.
        Dùng regex để parse status code (strict).
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.handshake_timeout
            )
            
            try:
                # CONNECT request
                request = f"CONNECT httpbin.org:443 HTTP/1.1\r\n"
                request += f"Host: httpbin.org:443\r\n"
                
                if username and password:
                    credentials = base64.b64encode(
                        f"{username}:{password}".encode()
                    ).decode()
                    request += f"Proxy-Authorization: Basic {credentials}\r\n"
                
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                # Đọc response
                response = await asyncio.wait_for(
                    reader.read(1024), 
                    timeout=self.handshake_timeout
                )
                response_str = response.decode('utf-8', errors='ignore')
                
                # Parse HTTP status với regex (strict)
                status_code = self._parse_http_status(response_str)
                if status_code:
                    if status_code == 200:
                        return {'success': True, 'protocol': 'https'}
                    elif status_code == 407:
                        return {'success': False, 'error': 'Proxy auth required'}
                
                return {'success': False, 'error': 'CONNECT failed'}
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    # ==================== SMART PROTOCOL DETECTION (Early Exit) ====================
    async def _detect_protocol(
        self, host: str, port: int, 
        username: str, password: str,
        known_protocol: Optional[str] = None
    ) -> Optional[str]:
        """
        Smart Protocol Detection với Early Exit.
        
        Sử dụng asyncio.wait(return_when=FIRST_COMPLETED).
        Ngay khi tìm thấy protocol thành công -> Cancel các task còn lại.
        
        Returns:
            Protocol name ('socks5', 'http', 'https') hoặc None
        """
        # Nếu đã biết protocol, chỉ test nó
        if known_protocol and known_protocol in ('socks5', 'http', 'https'):
            if known_protocol == 'socks5':
                result = await self._test_socks5_handshake(host, port, username, password)
            elif known_protocol == 'http':
                result = await self._test_http_handshake(host, port, username, password)
            else:
                result = await self._test_https_handshake(host, port, username, password)
            
            return known_protocol if result['success'] else None
        
        # Tạo tasks cho tất cả protocols
        tasks = {
            asyncio.create_task(
                self._test_socks5_handshake(host, port, username, password)
            ): 'socks5',
            asyncio.create_task(
                self._test_http_handshake(host, port, username, password)
            ): 'http',
            asyncio.create_task(
                self._test_https_handshake(host, port, username, password)
            ): 'https'
        }
        
        found_protocol = None
        
        while tasks:
            # Chờ task đầu tiên hoàn thành
            done, pending = await asyncio.wait(
                tasks.keys(), 
                return_when=asyncio.FIRST_COMPLETED
            )
            
            for task in done:
                try:
                    result = task.result()
                    if result.get('success'):
                        found_protocol = tasks[task]
                        # Hủy tất cả tasks còn lại
                        for t in pending:
                            t.cancel()
                        # Đợi cancel hoàn tất
                        if pending:
                            await asyncio.gather(*pending, return_exceptions=True)
                        return found_protocol
                except Exception:
                    pass
                
                # Loại task khỏi dict
                del tasks[task]
        
        return None
    
    # ==================== VERIFY FORWARD (Judge URL với Fallback) ====================
    async def _verify_forward(
        self, host: str, port: int, 
        username: str, password: str, 
        protocol: str
    ) -> Dict:
        """
        Verify proxy có thể forward request thật.
        
        Thử từng Judge URL cho đến khi thành công (fallback).
        
        SOCKS5 cần xử lý riêng bằng raw socket.
        """
        if protocol == 'socks5':
            return await self._verify_socks5_forward(host, port, username, password)
        
        # HTTP/HTTPS dùng aiohttp session singleton
        for judge_url in self.judge_urls:
            try:
                result = await self._try_judge_url_http(
                    host, port, username, password, protocol, judge_url
                )
                if result['success']:
                    return result
            except Exception:
                continue
        
        return {'success': False, 'error': 'All judge URLs failed'}
    
    async def _try_judge_url_http(
        self, host: str, port: int,
        username: str, password: str,
        protocol: str, judge_url: str
    ) -> Dict:
        """Thử verify forward với 1 judge URL (HTTP/HTTPS)."""
        # Build proxy URL
        if username and password:
            proxy_url = f"{protocol}://{username}:{password}@{host}:{port}"
        else:
            proxy_url = f"{protocol}://{host}:{port}"
        
        timeout_config = aiohttp.ClientTimeout(total=self.verify_timeout)
        
        try:
            if self.session:
                # Dùng session singleton
                async with self.session.get(
                    judge_url, 
                    proxy=proxy_url,
                    timeout=timeout_config
                ) as response:
                    if response.status == 200:
                        body = await response.text()
                        public_ip = self._extract_ip(body)
                        return {'success': True, 'public_ip': public_ip}
            else:
                # Fallback nếu không có session
                connector = aiohttp.TCPConnector(limit=10, force_close=True)
                async with aiohttp.ClientSession(
                    connector=connector,
                    timeout=timeout_config
                ) as session:
                    async with session.get(judge_url, proxy=proxy_url) as response:
                        if response.status == 200:
                            body = await response.text()
                            public_ip = self._extract_ip(body)
                            return {'success': True, 'public_ip': public_ip}
            
            return {'success': False, 'error': f'Status {response.status}'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    async def _verify_socks5_forward(
        self, host: str, port: int,
        username: str, password: str
    ) -> Dict:
        """
        Verify SOCKS5 forward bằng asyncio (non-blocking).
        
        Không dùng socket.connect blocking!
        Dùng asyncio.open_connection cho tất cả.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.verify_timeout
            )
            
            try:
                # SOCKS5 handshake
                if username and password:
                    greeting = b'\x05\x02\x00\x02'
                else:
                    greeting = b'\x05\x01\x00'
                
                writer.write(greeting)
                await writer.drain()
                
                response = await asyncio.wait_for(
                    reader.read(2), 
                    timeout=self.verify_timeout
                )
                
                if len(response) != 2 or response[0] != 0x05:
                    return {'success': False, 'error': 'SOCKS5 handshake failed'}
                
                selected_method = response[1]
                
                # Handle authentication
                if selected_method == 0x02:
                    if not username or not password:
                        return {'success': False, 'error': 'SOCKS5 requires auth'}
                    
                    auth_request = (
                        bytes([0x01, len(username)]) + 
                        username.encode('utf-8') + 
                        bytes([len(password)]) + 
                        password.encode('utf-8')
                    )
                    writer.write(auth_request)
                    await writer.drain()
                    
                    auth_response = await asyncio.wait_for(
                        reader.read(2), 
                        timeout=self.verify_timeout
                    )
                    if len(auth_response) != 2 or auth_response[1] != 0x00:
                        return {'success': False, 'error': 'SOCKS5 auth failed'}
                
                elif selected_method != 0x00:
                    return {'success': False, 'error': f'Unsupported method: {selected_method}'}
                
                # CONNECT to test endpoint
                # Thử từng judge URL
                for judge_url in self.judge_urls:
                    result = await self._socks5_connect_and_request(
                        reader, writer, judge_url
                    )
                    if result['success']:
                        return result
                
                return {'success': False, 'error': 'All judge URLs failed for SOCKS5'}
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'SOCKS5 forward timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    async def _socks5_connect_and_request(
        self, reader: asyncio.StreamReader, 
        writer: asyncio.StreamWriter,
        judge_url: str
    ) -> Dict:
        """
        SOCKS5 CONNECT và gửi HTTP request qua tunnel.
        
        Dùng async DNS resolution thay vì socket.gethostbyname.
        """
        try:
            # Parse URL
            # Ví dụ: "http://api.ipify.org" -> host="api.ipify.org", port=80
            if judge_url.startswith('http://'):
                url_part = judge_url[7:]
            elif judge_url.startswith('https://'):
                url_part = judge_url[8:]
            else:
                url_part = judge_url
            
            if '/' in url_part:
                test_host = url_part.split('/')[0]
                path = '/' + '/'.join(url_part.split('/')[1:])
            else:
                test_host = url_part
                path = '/'
            
            test_port = 80
            
            # Async DNS resolution (không blocking!)
            test_ip = await self._resolve_ip(test_host, test_port)
            if not test_ip:
                # Fallback IP cho api.ipify.org
                test_ip = '64.233.160.147'
            
            # SOCKS5 CONNECT request
            connect_request = (
                b'\x05' +                           # VER = 5
                b'\x01' +                           # CMD = 1 (CONNECT)
                b'\x00' +                           # RSV = 0
                b'\x01' +                           # ATYP = 1 (IPv4)
                socket.inet_aton(test_ip) +         # DST.ADDR
                struct.pack('>H', test_port)        # DST.PORT
            )
            
            writer.write(connect_request)
            await writer.drain()
            
            response = await asyncio.wait_for(
                reader.read(10), 
                timeout=self.verify_timeout
            )
            
            if len(response) < 2 or response[0] != 0x05 or response[1] != 0x00:
                return {'success': False, 'error': 'SOCKS5 CONNECT failed'}
            
            # Gửi HTTP request qua SOCKS5 tunnel
            http_request = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {test_host}\r\n"
                f"User-Agent: ProxyChecker/2.0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode('utf-8')
            
            writer.write(http_request)
            await writer.drain()
            
            # Đọc response
            response_data = b''
            for _ in range(10):
                try:
                    chunk = await asyncio.wait_for(
                        reader.read(1024), 
                        timeout=2
                    )
                    if not chunk:
                        break
                    response_data += chunk
                    if b'\r\n\r\n' in response_data:
                        break
                except asyncio.TimeoutError:
                    break
            
            if not response_data:
                return {'success': False, 'error': 'No response through SOCKS5'}
            
            response_str = response_data.decode('utf-8', errors='ignore')
            
            # Check HTTP response và extract IP
            status_code = self._parse_http_status(response_str)
            if status_code == 200:
                public_ip = self._extract_ip(response_str)
                return {'success': True, 'public_ip': public_ip or 'SOCKS5-OK'}
            
            return {'success': False, 'error': f'HTTP {status_code}'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    def _extract_ip(self, body: str) -> Optional[str]:
        """Extract IP từ response body."""
        import json
        
        try:
            data = json.loads(body)
            if 'origin' in data:
                return data['origin'].split(',')[0].strip()
            if 'ip' in data:
                return data['ip']
            if 'query' in data:
                return data['query']
        except Exception:
            pass
        
        # Fallback: regex
        match = IP_PATTERN.search(body)
        return match.group() if match else None
    
    # ==================== MAIN CHECK FUNCTION ====================
    async def check_single_proxy(self, proxy_data: dict) -> ProxyResult:
        """
        Check một proxy.
        
        Quy trình:
        1. Validate auth length (RFC)
        2. TCP Connect
        3. Smart Protocol Detection (với early exit)
        4. Verify Forward
        """
        async with self.semaphore:
            start_time = time.time()
            host = proxy_data['host']
            port = proxy_data['port']
            username = proxy_data.get('login', '')
            password = proxy_data.get('password', '')
            
            # STEP 0: Validate auth length (RFC 1929)
            auth_error = self._validate_auth_length(username, password)
            if auth_error:
                return ProxyResult(
                    proxy=proxy_data['original'],
                    status=ProxyStatus.ERROR,
                    error=auth_error
                )
            
            # STEP 1: TCP Connect
            tcp_ok = await self._test_tcp_connect(host, port)
            if not tcp_ok:
                elapsed_ms = int((time.time() - start_time) * 1000)
                return ProxyResult(
                    proxy=proxy_data['original'],
                    status=ProxyStatus.DIE,
                    response_time_ms=elapsed_ms,
                    error="TCP Connect failed"
                )
            
            # STEP 2: Smart Protocol Detection (Early Exit)
            known_protocol = proxy_data.get('protocol')
            detected_protocol = await self._detect_protocol(
                host, port, username, password, known_protocol
            )
            
            if not detected_protocol:
                elapsed_ms = int((time.time() - start_time) * 1000)
                return ProxyResult(
                    proxy=proxy_data['original'],
                    status=ProxyStatus.DIE,
                    response_time_ms=elapsed_ms,
                    error="No valid protocol"
                )
            
            # STEP 3: Verify Forward
            forward_result = await self._verify_forward(
                host, port, username, password, detected_protocol
            )
            
            elapsed_ms = int((time.time() - start_time) * 1000)
            
            if forward_result['success']:
                return ProxyResult(
                    proxy=proxy_data['original'],
                    status=ProxyStatus.LIVE,
                    protocol=detected_protocol.upper(),
                    response_time_ms=elapsed_ms,
                    public_ip=forward_result.get('public_ip')
                )
            else:
                return ProxyResult(
                    proxy=proxy_data['original'],
                    status=ProxyStatus.DIE,
                    protocol=detected_protocol.upper(),
                    response_time_ms=elapsed_ms,
                    error=forward_result.get('error', 'Forward failed')
                )
    
    # ==================== ASYNC GENERATOR (PyQt6 Integration) ====================
    async def check_proxies_async(
        self, proxies: List[dict]
    ) -> AsyncGenerator[ProxyResult, None]:
        """
        Check proxies với async generator.
        
        Dùng cho PyQt6 integration - yield từng result.
        Callback được gọi nếu có.
        
        Usage:
            async with ProxyChecker() as checker:
                async for result in checker.check_proxies_async(proxies):
                    update_ui(result)
        """
        self.total = len(proxies)
        self.checked = 0
        self.live_count = 0
        self.die_count = 0
        
        # Process theo batch để tránh quá tải
        for batch_start in range(0, len(proxies), self._batch_size):
            batch = proxies[batch_start:batch_start + self._batch_size]
            tasks = [self.check_single_proxy(p) for p in batch]
            
            for coro in asyncio.as_completed(tasks):
                try:
                    result = await coro
                except Exception as e:
                    result = ProxyResult(
                        proxy="unknown",
                        status=ProxyStatus.ERROR,
                        error=str(e)[:50]
                    )
                
                self.checked += 1
                if result.status == ProxyStatus.LIVE:
                    self.live_count += 1
                else:
                    self.die_count += 1
                
                # Call callback nếu có
                if self.callback:
                    try:
                        self.callback(result, self.checked, self.total)
                    except Exception:
                        pass
                
                yield result
    
    async def check_proxies(self, proxies: List[dict]) -> List[ProxyResult]:
        """
        Check proxies và trả về list kết quả.
        
        Wrapper cho check_proxies_async.
        """
        results = []
        async for result in self.check_proxies_async(proxies):
            results.append(result)
        return results


# ==================== CLI FUNCTIONS ====================
def load_proxies(file_path: str) -> List[dict]:
    """
    Load proxies từ file.
    
    Hỗ trợ format:
    - host:port:user:pass
    - protocol://host:port:user:pass
    - Section headers: HTTP:, SOCKS5:, HTTPS:
    """
    checker = ProxyChecker()
    proxies = []
    current_protocol = None
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                # Check section headers
                if line.upper() in ['HTTP:', 'HTTPS:', 'SOCKS5:', 'SOCKS4:']:
                    current_protocol = line.upper().replace(':', '').lower()
                    continue
                
                proxy = checker.parse_proxy_line(line)
                if proxy:
                    if not proxy.get('protocol') and current_protocol:
                        proxy['protocol'] = current_protocol
                    proxies.append(proxy)
                    
    except FileNotFoundError:
        pass
    
    return proxies


def save_results(results: List[ProxyResult], output_file: str):
    """Lưu kết quả ra file."""
    live_proxies = [r for r in results if r.status == ProxyStatus.LIVE]
    die_proxies = [r for r in results if r.status != ProxyStatus.LIVE]
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("PROXY CHECK RESULTS\n")
        f.write(f"Total: {len(results)} | Live: {len(live_proxies)} | Die: {len(die_proxies)}\n")
        f.write("=" * 70 + "\n\n")
        
        f.write("-" * 40 + "\n")
        f.write(f"[LIVE] {len(live_proxies)} proxies\n")
        f.write("-" * 40 + "\n")
        for r in live_proxies:
            line = f"[LIVE] {r.proxy} | {r.protocol} | {r.response_time_ms}ms"
            if r.public_ip:
                line += f" | IP: {r.public_ip}"
            f.write(line + "\n")
        
        f.write("\n")
        
        f.write("-" * 40 + "\n")
        f.write(f"[DIE] {len(die_proxies)} proxies\n")
        f.write("-" * 40 + "\n")
        for r in die_proxies:
            status = r.status.value
            error_info = f" | Error: {r.error}" if r.error else ""
            line = f"[{status}] {r.proxy} | {r.response_time_ms}ms{error_info}"
            f.write(line + "\n")


async def main_async():
    """Main async function cho CLI."""
    parser = argparse.ArgumentParser(
        description="🔥 Proxy Checker CLI - Production Quality"
    )
    
    default_input = os.path.join(SCRIPT_DIR, "sample_proxies.txt")
    default_output = os.path.join(SCRIPT_DIR, "live_proxies.txt")
    
    parser.add_argument("input_file", nargs='?', default=default_input,
                        help="File chứa danh sách proxy")
    parser.add_argument("-c", "--concurrency", type=int, default=None,
                        help=f"Số kết nối đồng thời (default: {get_max_concurrency()} for this OS)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Timeout (default: 10s)")
    parser.add_argument("-o", "--output", default=default_output,
                        help="File xuất kết quả")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Không hiện progress")
    
    args = parser.parse_args()
    
    # Banner
    if not args.quiet:
        print("=" * 60)
        print("PROXY CHECKER CLI TOOL - Production Quality")
        print("=" * 60)
        print(f"OS: {sys.platform} | Max Concurrency: {get_max_concurrency()}")
        print(f"Input: {args.input_file}")
        print(f"Concurrency: {args.concurrency or 'auto'}")
        print(f"Timeout: {args.timeout}s")
        print(f"Output: {args.output}")
        print("-" * 60)
        print("Features: Session Singleton, Async DNS, Early Exit, Fallback URLs")
        print("=" * 60)
    
    # Load
    if not args.quiet:
        print("\n[INFO] Loading proxies...")
    proxies = load_proxies(args.input_file)
    
    if not proxies:
        if not args.quiet:
            print("[ERROR] Không có proxy hợp lệ!")
        sys.exit(1)
    
    if not args.quiet:
        print(f"[OK] Loaded {len(proxies)} proxies\n")
        print("[START] Bắt đầu check...\n")
    
    start_time = time.time()
    
    # Progress callback cho CLI
    def cli_progress(result: ProxyResult, checked: int, total: int):
        if args.quiet:
            return
        status_icon = "[LIVE]" if result.status == ProxyStatus.LIVE else "[DIE]"
        protocol = result.protocol or "N/A"
        print(f"\rChecked {checked}/{total} - "
              f"Last: {result.proxy} ({protocol}) {result.response_time_ms}ms {status_icon}", 
              end="", flush=True)
    
    # Check với context manager
    async with ProxyChecker(
        concurrency=args.concurrency,
        timeout=args.timeout,
        callback=cli_progress if not args.quiet else None
    ) as checker:
        results = await checker.check_proxies(proxies)
    
    elapsed = time.time() - start_time
    
    if not args.quiet:
        print()  # New line after progress
    
    # Statistics
    live = sum(1 for r in results if r.status == ProxyStatus.LIVE)
    die = sum(1 for r in results if r.status != ProxyStatus.LIVE)
    
    if not args.quiet:
        print("\n" + "=" * 60)
        print("KẾT QUẢ")
        print("=" * 60)
        print(f"[LIVE] Live: {live}")
        print(f"[DIE] Die: {die}")
        print(f"[TIME] Time: {elapsed:.2f}s")
        print(f"[SPEED] Speed: {len(proxies)/elapsed:.1f} proxies/second")
        
        # Protocol breakdown
        protocol_stats = {}
        for r in results:
            if r.status == ProxyStatus.LIVE and r.protocol:
                if r.protocol not in protocol_stats:
                    protocol_stats[r.protocol] = {'count': 0, 'times': []}
                protocol_stats[r.protocol]['count'] += 1
                protocol_stats[r.protocol]['times'].append(r.response_time_ms)
        
        print("-" * 60)
        if protocol_stats:
            for proto, stats in protocol_stats.items():
                times = stats['times']
                min_time = min(times)
                max_time = max(times)
                print(f"[{proto}] {stats['count']} live (response {min_time}-{max_time}ms)")
        
        print(f"[DIE] {die} proxies failed")
        print("-" * 60)
    
    # Save
    save_results(results, args.output)
    
    if not args.quiet:
        print(f"\n[SAVED] Đã lưu kết quả vào: {args.output}")
        print(f"        - Live: {live}")
        print(f"        - Die: {die}")
        print("=" * 60)
        print("[DONE] HOÀN THÀNH!")


def main():
    """Entry point."""
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
