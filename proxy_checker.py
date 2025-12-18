#!/usr/bin/env python3
"""
🔥 PROXY CHECKER CLI TOOL
=========================
Công cụ check proxy live/die sử dụng logic từ project lớn.

Logic check (RFC-compliant):
1. TCP Connect Test
2. SOCKS5 Handshake (RFC 1928 + 1929)     .
3. HTTP Proxy Handshake (RFC 7230)
4. HTTPS CONNECT Handshake (RFC 7231)
5. Verify Forward (Judge URL)

Usage:
    python proxy_checker.py proxies.txt --concurrency 500 --timeout 10
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
from dataclasses import dataclass
from typing import List, Optional, Dict
from enum import Enum

# Thư mục chứa script - dùng để tìm file mặc định
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Fix UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')


class ProxyStatus(Enum):
    LIVE = "LIVE"
    DIE = "DIE"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


@dataclass
class ProxyResult:
    proxy: str
    status: ProxyStatus
    protocol: Optional[str] = None
    response_time_ms: int = 0
    public_ip: Optional[str] = None
    error: Optional[str] = None


class ProxyChecker:
    """
    Async Proxy Checker sử dụng logic từ project lớn.
    
    QUY TRÌNH CHECK (RFC-compliant):
    1. TCP Connect Test
    2. Test SOCKS5 Handshake (RFC 1928 + 1929)
    3. Test HTTP Proxy Handshake (RFC 7230)
    4. Test HTTPS CONNECT Handshake (RFC 7231)
    5. Verify Forward capability
    """
    
    # Judge URLs
    JUDGE_URLS = [
        "http://httpbin.org/ip",
        "http://ip-api.com/json",
    ]
    
    def __init__(self, concurrency: int = 500, timeout: int = 10):
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)
        
        # Statistics
        self.total = 0
        self.checked = 0
        self.live_count = 0
        self.die_count = 0
        
    def parse_proxy_line(self, line: str) -> Optional[dict]:
        """Parse proxy line - hỗ trợ nhiều format."""
        line = line.strip()
        if not line or line.startswith('#'):
            return None
            
        protocol = None
        
        # Check có protocol không
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
    async def _test_tcp_connect(self, host: str, port: int, timeout: int) -> bool:
        """STEP 0: Test TCP connection."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    # ==================== SOCKS5 HANDSHAKE (RFC 1928 + 1929) ====================
    async def _test_socks5_handshake(self, host: str, port: int, 
                                      username: str, password: str, timeout: int) -> Dict:
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
                timeout=timeout
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
                response = await asyncio.wait_for(reader.read(2), timeout=timeout)
                
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
                    
                    auth_response = await asyncio.wait_for(reader.read(2), timeout=timeout)
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
    async def _test_http_handshake(self, host: str, port: int,
                                    username: str, password: str, timeout: int) -> Dict:
        """
        Test HTTP Proxy handshake.
        
        Gửi request HEAD đến proxy và check response.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            try:
                # Gửi HTTP request qua proxy
                request = f"HEAD http://httpbin.org/ip HTTP/1.1\r\n"
                request += f"Host: httpbin.org\r\n"
                
                # Add auth header nếu có
                if username and password:
                    import base64
                    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                    request += f"Proxy-Authorization: Basic {credentials}\r\n"
                
                request += "Connection: close\r\n\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                # Đọc response
                response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                response_str = response.decode('utf-8', errors='ignore')
                
                # Check HTTP response
                if response_str.startswith('HTTP/'):
                    status_line = response_str.split('\r\n')[0]
                    if ' 200 ' in status_line or ' 301 ' in status_line or ' 302 ' in status_line:
                        return {'success': True, 'protocol': 'http'}
                    elif ' 407 ' in status_line:
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
    async def _test_https_handshake(self, host: str, port: int,
                                     username: str, password: str, timeout: int) -> Dict:
        """
        Test HTTPS CONNECT tunnel.
        
        CONNECT method để tạo tunnel qua proxy.
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            try:
                # CONNECT request
                request = f"CONNECT httpbin.org:443 HTTP/1.1\r\n"
                request += f"Host: httpbin.org:443\r\n"
                
                if username and password:
                    import base64
                    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                    request += f"Proxy-Authorization: Basic {credentials}\r\n"
                
                request += "\r\n"
                
                writer.write(request.encode())
                await writer.drain()
                
                # Đọc response
                response = await asyncio.wait_for(reader.read(1024), timeout=timeout)
                response_str = response.decode('utf-8', errors='ignore')
                
                # Check HTTP 200 Connection Established
                if 'HTTP/' in response_str:
                    if ' 200 ' in response_str:
                        return {'success': True, 'protocol': 'https'}
                    elif ' 407 ' in response_str:
                        return {'success': False, 'error': 'Proxy auth required'}
                
                return {'success': False, 'error': 'CONNECT failed'}
                
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    # ==================== VERIFY FORWARD (Judge URL) ====================
    async def _verify_forward(self, host: str, port: int, username: str, 
                               password: str, protocol: str, timeout: int) -> Dict:
        """
        Verify proxy co the forward request that.
        
        Gui request den Judge URL va verify response.
        """
        # SOCKS5 can xu ly rieng bang raw socket
        if protocol == 'socks5':
            return await self._verify_socks5_forward(host, port, username, password, timeout)
        
        # HTTP/HTTPS dung aiohttp
        try:
            # Build proxy URL
            if username and password:
                proxy_url = f"{protocol}://{username}:{password}@{host}:{port}"
            else:
                proxy_url = f"{protocol}://{host}:{port}"
            
            connector = aiohttp.TCPConnector(limit=10, force_close=True)
            timeout_config = aiohttp.ClientTimeout(total=timeout)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=timeout_config
            ) as session:
                judge_url = self.JUDGE_URLS[0]
                
                async with session.get(judge_url, proxy=proxy_url) as response:
                    if response.status == 200:
                        body = await response.text()
                        public_ip = self._extract_ip(body)
                        return {
                            'success': True,
                            'public_ip': public_ip
                        }
                    
            return {'success': False, 'error': f'Status {response.status}'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    # ==================== SOCKS5 FORWARD VERIFICATION (Raw Socket) ====================
    async def _verify_socks5_forward(self, host: str, port: int, username: str,
                                      password: str, timeout: int) -> Dict:
        """
        Verify SOCKS5 co the forward request that khong.
        
        Quy trinh:
        1. SOCKS5 handshake day du
        2. CONNECT toi api.ipify.org:80
        3. Gui HTTP GET request
        4. Nhan IP response
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            await asyncio.get_event_loop().run_in_executor(None, sock.connect, (host, port))
            
            # SOCKS5 handshake
            if username and password:
                greeting = b'\x05\x02\x00\x02'
            else:
                greeting = b'\x05\x01\x00'
            
            await asyncio.get_event_loop().run_in_executor(None, sock.send, greeting)
            response = await asyncio.get_event_loop().run_in_executor(None, sock.recv, 2)
            
            if len(response) != 2 or response[0] != 0x05:
                sock.close()
                return {'success': False, 'error': 'SOCKS5 handshake failed in forward test'}
            
            selected_method = response[1]
            
            # Handle authentication
            if selected_method == 0x02:  # Username/Password
                if not username or not password:
                    sock.close()
                    return {'success': False, 'error': 'SOCKS5 requires auth for forward test'}
                
                auth_request = bytes([0x01, len(username)]) + username.encode('utf-8') + bytes([len(password)]) + password.encode('utf-8')
                await asyncio.get_event_loop().run_in_executor(None, sock.send, auth_request)
                
                auth_response = await asyncio.get_event_loop().run_in_executor(None, sock.recv, 2)
                if len(auth_response) != 2 or auth_response[1] != 0x00:
                    sock.close()
                    return {'success': False, 'error': 'SOCKS5 auth failed in forward test'}
            
            elif selected_method != 0x00:
                sock.close()
                return {'success': False, 'error': f'SOCKS5 unsupported method: {selected_method}'}
            
            # CONNECT to test endpoint
            test_host = 'api.ipify.org'
            test_port = 80
            
            # Resolve hostname to IP
            try:
                test_ip = socket.gethostbyname(test_host)
            except:
                test_ip = '64.233.160.147'  # Fallback IP
            
            connect_request = (
                b'\x05' +                           # VER = 5
                b'\x01' +                           # CMD = 1 (CONNECT)
                b'\x00' +                           # RSV = 0
                b'\x01' +                           # ATYP = 1 (IPv4)
                socket.inet_aton(test_ip) +         # DST.ADDR
                struct.pack('>H', test_port)        # DST.PORT
            )
            
            await asyncio.get_event_loop().run_in_executor(None, sock.send, connect_request)
            response = await asyncio.get_event_loop().run_in_executor(None, sock.recv, 10)
            
            if len(response) < 2 or response[0] != 0x05 or response[1] != 0x00:
                sock.close()
                return {'success': False, 'error': 'SOCKS5 CONNECT failed in forward test'}
            
            # Send HTTP request through SOCKS5 tunnel
            http_request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {test_host}\r\n"
                f"User-Agent: ProxyChecker/1.0\r\n"
                f"Connection: close\r\n"
                f"\r\n"
            ).encode('utf-8')
            
            await asyncio.get_event_loop().run_in_executor(None, sock.send, http_request)
            
            # Read response
            response_data = b''
            for _ in range(10):  # Max 10 reads
                try:
                    chunk = await asyncio.get_event_loop().run_in_executor(None, sock.recv, 1024)
                    if not chunk:
                        break
                    response_data += chunk
                    if b'\r\n\r\n' in response_data:  # End of headers
                        break
                except:
                    break
            
            sock.close()
            
            if not response_data:
                return {'success': False, 'error': 'No response through SOCKS5 tunnel'}
            
            response_str = response_data.decode('utf-8', errors='ignore')
            
            # Extract IP from response
            if 'HTTP/' in response_str and ('200' in response_str or response_str.count('.') >= 3):
                # Try to find IP in response
                import re
                ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                ips = re.findall(ip_pattern, response_str)
                public_ip = ips[0] if ips else 'SOCKS5-FORWARD-OK'
                
                return {'success': True, 'public_ip': public_ip}
            else:
                return {'success': False, 'error': 'Invalid HTTP response through SOCKS5'}
                
        except socket.timeout:
            return {'success': False, 'error': 'SOCKS5 forward timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)[:50]}
    
    def _extract_ip(self, body: str) -> Optional[str]:
        """Extract IP từ response body."""
        import re
        import json
        
        try:
            data = json.loads(body)
            if 'origin' in data:
                return data['origin'].split(',')[0].strip()
            if 'ip' in data:
                return data['ip']
            if 'query' in data:
                return data['query']
        except:
            pass
        
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, body)
        return match.group() if match else None
    
    # ==================== MAIN CHECK FUNCTION ====================
    async def check_single_proxy(self, proxy_data: dict) -> ProxyResult:
        """
        Check một proxy theo logic project lớn.
        
        QUY TRÌNH:
        1. TCP Connect
        2. Test SOCKS5 → HTTP → HTTPS (PARALLEL!)
        3. Verify Forward
        """
        async with self.semaphore:
            start_time = time.time()
            host = proxy_data['host']
            port = proxy_data['port']
            username = proxy_data.get('login', '')
            password = proxy_data.get('password', '')
            
            # STEP 0: Quick TCP Connect (reduced timeout)
            tcp_ok = await self._test_tcp_connect(host, port, min(3, self.timeout // 3))
            if not tcp_ok:
                elapsed_ms = int((time.time() - start_time) * 1000)
                return ProxyResult(
                    proxy=proxy_data['original'],
                    status=ProxyStatus.DIE,
                    response_time_ms=elapsed_ms,
                    error="TCP Connect failed"
                )
            
            # STEP 1: Test all protocols in PARALLEL for speed!
            protocols_to_test = ['socks5', 'http', 'https']  # SOCKS5 first (usually faster)
            handshake_timeout = min(3, self.timeout // 3)  # Quick handshake timeout
            
            # Nếu đã biết protocol, chỉ test nó
            if proxy_data.get('protocol'):
                known_protocol = proxy_data['protocol'].lower()
                if known_protocol in protocols_to_test:
                    protocols_to_test = [known_protocol]
            
            # Test handshakes in parallel!
            async def test_protocol(protocol):
                if protocol == 'socks5':
                    result = await self._test_socks5_handshake(
                        host, port, username, password, handshake_timeout
                    )
                elif protocol == 'http':
                    result = await self._test_http_handshake(
                        host, port, username, password, handshake_timeout
                    )
                else:
                    result = await self._test_https_handshake(
                        host, port, username, password, handshake_timeout
                    )
                if result['success']:
                    return protocol
                return None
            
            # Run all handshake tests in parallel
            handshake_tasks = [test_protocol(p) for p in protocols_to_test]
            handshake_results = await asyncio.gather(*handshake_tasks, return_exceptions=True)
            
            # Get first successful protocol
            successful_protocols = [p for p in handshake_results if p and not isinstance(p, Exception)]
            
            # STEP 2: Verify forward for successful protocols (prioritize SOCKS5)
            for protocol in ['socks5', 'http', 'https']:
                if protocol in successful_protocols:
                    forward_result = await self._verify_forward(
                        host, port, username, password, protocol, self.timeout
                    )
                    
                    if forward_result['success']:
                        elapsed_ms = int((time.time() - start_time) * 1000)
                        return ProxyResult(
                            proxy=proxy_data['original'],
                            status=ProxyStatus.LIVE,
                            protocol=protocol.upper(),
                            response_time_ms=elapsed_ms,
                            public_ip=forward_result.get('public_ip')
                        )
            
            # All failed
            elapsed_ms = int((time.time() - start_time) * 1000)
            return ProxyResult(
                proxy=proxy_data['original'],
                status=ProxyStatus.DIE,
                response_time_ms=elapsed_ms,
                error="No valid protocol"
            )
    
    async def check_proxies(self, proxies: List[dict]) -> List[ProxyResult]:
        """Check nhieu proxy dong thoi - batch processing for Windows compatibility."""
        self.total = len(proxies)
        self.checked = 0
        self.live_count = 0
        self.die_count = 0
        
        async def check_with_progress(proxy_data: dict) -> ProxyResult:
            result = await self.check_single_proxy(proxy_data)
            
            self.checked += 1
            if result.status == ProxyStatus.LIVE:
                self.live_count += 1
            else:
                self.die_count += 1
            
            self._print_progress(result)
            return result
        
        # Windows has ~512 file descriptor limit in select()
        # Process in batches to avoid hitting the limit
        BATCH_SIZE = min(200, self.concurrency)  # Safe batch size for Windows
        all_results = []
        
        for i in range(0, len(proxies), BATCH_SIZE):
            batch = proxies[i:i + BATCH_SIZE]
            tasks = [check_with_progress(p) for p in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for r in results:
                if isinstance(r, Exception):
                    all_results.append(ProxyResult(
                        proxy="unknown",
                        status=ProxyStatus.ERROR,
                        error=str(r)[:50]
                    ))
                else:
                    all_results.append(r)
        
        return all_results
    
    def _print_progress(self, result: ProxyResult):
        """In tien do check."""
        status_icon = "[LIVE]" if result.status == ProxyStatus.LIVE else "[DIE]"
        protocol = result.protocol or "N/A"
        time_ms = result.response_time_ms
        
        print(f"\rChecked {self.checked}/{self.total} - "
              f"Live: {self.live_count} - Die: {self.die_count} | "
              f"Last: {result.proxy} ({protocol}) {time_ms}ms {status_icon}", end="")
        
        if self.checked == self.total:
            print()


def load_proxies(file_path: str) -> List[dict]:
    """
    Load proxies từ file.
    
    Hỗ trợ format:
    - HTTP:
      host:port:user:pass
    - SOCKS5:
      host:port:user:pass
    - protocol://host:port:user:pass
    - host:port:user:pass
    """
    checker = ProxyChecker()
    proxies = []
    current_protocol = None  # Track current section protocol
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue
                
                # Check for section headers (HTTP:, SOCKS5:, HTTPS:)
                if line.upper() in ['HTTP:', 'HTTPS:', 'SOCKS5:', 'SOCKS4:']:
                    current_protocol = line.upper().replace(':', '').lower()
                    print(f"[INFO] Section: {current_protocol.upper()}")
                    continue
                
                # Parse proxy line
                proxy = checker.parse_proxy_line(line)
                if proxy:
                    # Apply section protocol if proxy doesn't have explicit protocol
                    if not proxy.get('protocol') and current_protocol:
                        proxy['protocol'] = current_protocol
                    proxies.append(proxy)
                    
    except FileNotFoundError:
        print(f"[ERROR] File khong ton tai: {file_path}")
        sys.exit(1)
    
    return proxies


def save_results(results: List[ProxyResult], output_file: str):
    """Lưu kết quả ra file - bao gồm cả LIVE và DIE với tốc độ phản hồi."""
    live_proxies = [r for r in results if r.status == ProxyStatus.LIVE]
    die_proxies = [r for r in results if r.status != ProxyStatus.LIVE]
    
    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write("=" * 70 + "\n")
        f.write("PROXY CHECK RESULTS\n")
        f.write(f"Total: {len(results)} | Live: {len(live_proxies)} | Die: {len(die_proxies)}\n")
        f.write("=" * 70 + "\n\n")
        
        # LIVE proxies section
        f.write("-" * 40 + "\n")
        f.write(f"[LIVE] {len(live_proxies)} proxies\n")
        f.write("-" * 40 + "\n")
        for r in live_proxies:
            line = f"[LIVE] {r.proxy} | {r.protocol} | {r.response_time_ms}ms"
            if r.public_ip:
                line += f" | IP: {r.public_ip}"
            f.write(line + "\n")
        
        f.write("\n")
        
        # DIE proxies section
        f.write("-" * 40 + "\n")
        f.write(f"[DIE] {len(die_proxies)} proxies\n")
        f.write("-" * 40 + "\n")
        for r in die_proxies:
            status = r.status.value  # LIVE, DIE, TIMEOUT, ERROR
            error_info = f" | Error: {r.error}" if r.error else ""
            line = f"[{status}] {r.proxy} | {r.response_time_ms}ms{error_info}"
            f.write(line + "\n")
    
    print(f"\n[SAVED] Da luu ket qua vao: {output_file}")
    print(f"        - Live: {len(live_proxies)}")
    print(f"        - Die: {len(die_proxies)}")


async def main():
    """Main function."""
    parser = argparse.ArgumentParser(
        description="🔥 Proxy Checker CLI - RFC-compliant handshake detection"
    )
    # Default paths relative to script directory
    default_input = os.path.join(SCRIPT_DIR, "sample_proxies.txt")
    default_output = os.path.join(SCRIPT_DIR, "live_proxies.txt")
    
    parser.add_argument("input_file", nargs='?', default=default_input,
                        help="File chứa danh sách proxy (default: sample_proxies.txt)")
    parser.add_argument("-c", "--concurrency", type=int, default=500,
                        help="Số kết nối đồng thời (default: 500)")
    parser.add_argument("-t", "--timeout", type=int, default=10,
                        help="Timeout (default: 10s)")
    parser.add_argument("-o", "--output", default=default_output,
                        help="File xuất kết quả (default: live_proxies.txt)")
    
    args = parser.parse_args()
    
    # Banner
    print("=" * 60)
    print("PROXY CHECKER CLI TOOL (RFC-compliant)")
    print("=" * 60)
    print(f"Input: {args.input_file}")
    print(f"Concurrency: {args.concurrency}")
    print(f"Timeout: {args.timeout}s")
    print(f"Output: {args.output}")
    print("-" * 60)
    print("Logic: TCP -> HTTPS -> HTTP -> SOCKS5 -> Verify Forward")
    print("=" * 60)
    
    # Load
    print("\n[INFO] Loading proxies...")
    proxies = load_proxies(args.input_file)
    print(f"[OK] Loaded {len(proxies)} proxies\n")
    
    if not proxies:
        print("[ERROR] Khong co proxy hop le!")
        sys.exit(1)
    
    # Check
    print("[START] Bat dau check...\n")
    start_time = time.time()
    
    checker = ProxyChecker(
        concurrency=args.concurrency,
        timeout=args.timeout
    )
    results = await checker.check_proxies(proxies)
    
    elapsed = time.time() - start_time
    
    # Statistics
    print("\n" + "=" * 60)
    print("KET QUA")
    print("=" * 60)
    
    live = sum(1 for r in results if r.status == ProxyStatus.LIVE)
    die = sum(1 for r in results if r.status != ProxyStatus.LIVE)
    
    print(f"[LIVE] Live: {live}")
    print(f"[DIE] Die: {die}")
    print(f"[TIME] Time: {elapsed:.2f}s")
    print(f"[SPEED] Speed: {len(proxies)/elapsed:.1f} proxies/second")
    
    # Protocol breakdown with response time ranges
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
    
    print("=" * 60)
    print("[DONE] HOAN THANH!")


if __name__ == "__main__":
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    
    asyncio.run(main())
