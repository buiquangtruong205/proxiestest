"""
Proxy Checker Service - Optimized RFC-Compliant Protocol Detection

� PPERFORMANCE OPTIMIZATIONS:
- Session Singleton: Single aiohttp.ClientSession for entire lifecycle
- Async DNS Resolution: Non-blocking loop.getaddrinfo() 
- Smart Protocol Detection: Early exit with asyncio.FIRST_COMPLETED
- Resource Management: Proper connection pooling and cleanup

🔎 PROTOCOL DETECTION THEO CHUẨN RFC:
- RFC 1928: SOCKS Protocol Version 5
- RFC 7230: HTTP/1.1 Message Syntax and Routing  
- RFC 7231: HTTP/1.1 Semantics and Content (CONNECT method)

🔒 SECURITY & ROBUSTNESS:
- Strict HTTP parsing with regex patterns
- Timeout budget allocation (TCP: 20%, Handshake: 30%, Verify: 50%)
- Judge URL fallback mechanism
- Byte limit validation for SOCKS5 auth
"""

import asyncio
import aiohttp
import socket
import time
import sys
import re
import struct
from typing import List, Dict, Callable, Optional, AsyncGenerator, Union
import threading


class ProxyChecker:
    """
    Optimized Proxy Checker with Session Management and Smart Detection
    
    Features:
    - Session Singleton: Single aiohttp.ClientSession lifecycle
    - Async DNS Resolution: Non-blocking getaddrinfo
    - Smart Protocol Detection: Early exit on first success
    - Resource Management: Proper cleanup and connection pooling
    
    Note: PyQt6 signals have been replaced with callback functions.
    Use set_callback() to register callbacks for events.
    """
    
    # Judge URLs với fallback mechanism
    JUDGE_URLS = [
        'http://httpbin.org/ip',
        'http://api.ipify.org',
        'http://checkip.amazonaws.com'
    ]
    
    # HTTP Response Pattern (Strict RFC compliance)
    HTTP_RESPONSE_PATTERN = re.compile(r'^HTTP/\d\.\d\s+(200|301|302|407)\b')
    
    def __init__(self):
        self.is_checking = False
        self.stop_requested = False
        self.session = None
        
        # Callback functions (thay thế pyqtSignal)
        self._on_progress_updated: Optional[Callable[[int, int], None]] = None
        self._on_proxy_checked: Optional[Callable[[int, dict], None]] = None
        self._on_batch_completed: Optional[Callable[[list], None]] = None
        self._on_proxy_status_updated: Optional[Callable[[int, str, float], None]] = None
        self._on_check_completed: Optional[Callable[[list], None]] = None
        self._on_error_occurred: Optional[Callable[[str], None]] = None
        
        # Platform-specific concurrency limits
        self.max_concurrent = self._get_platform_concurrent_limit()
    
    # ==================== CALLBACK SETTERS (thay thế pyqtSignal.connect) ====================
    
    def set_on_progress_updated(self, callback: Callable[[int, int], None]):
        """Set callback for progress updates. Args: (current, total)"""
        self._on_progress_updated = callback
    
    def set_on_proxy_checked(self, callback: Callable[[int, dict], None]):
        """Set callback for single proxy checked. Args: (row_index, result)"""
        self._on_proxy_checked = callback
    
    def set_on_batch_completed(self, callback: Callable[[list], None]):
        """Set callback for batch completion. Args: (all_results)"""
        self._on_batch_completed = callback
    
    def set_on_proxy_status_updated(self, callback: Callable[[int, str, float], None]):
        """Set callback for proxy status updates. Args: (profile_id, status, response_time)"""
        self._on_proxy_status_updated = callback
    
    def set_on_check_completed(self, callback: Callable[[list], None]):
        """Set callback for check completion. Args: (results)"""
        self._on_check_completed = callback
    
    def set_on_error_occurred(self, callback: Callable[[str], None]):
        """Set callback for errors. Args: (error_message)"""
        self._on_error_occurred = callback
    
    # ==================== CALLBACK EMITTERS (thay thế pyqtSignal.emit) ====================
    
    def _emit_progress_updated(self, current: int, total: int):
        """Emit progress update callback"""
        if self._on_progress_updated:
            try:
                self._on_progress_updated(current, total)
            except Exception:
                pass
    
    def _emit_proxy_checked(self, index: int, result: dict):
        """Emit proxy checked callback"""
        if self._on_proxy_checked:
            try:
                self._on_proxy_checked(index, result)
            except Exception:
                pass
    
    def _emit_batch_completed(self, results: list):
        """Emit batch completed callback"""
        if self._on_batch_completed:
            try:
                self._on_batch_completed(results)
            except Exception:
                pass
    
    def _emit_proxy_status_updated(self, profile_id: int, status: str, response_time: float):
        """Emit proxy status updated callback"""
        if self._on_proxy_status_updated:
            try:
                self._on_proxy_status_updated(profile_id, status, response_time)
            except Exception:
                pass
    
    def _emit_check_completed(self, results: list):
        """Emit check completed callback"""
        if self._on_check_completed:
            try:
                self._on_check_completed(results)
            except Exception:
                pass
    
    def _emit_error_occurred(self, error_message: str):
        """Emit error occurred callback"""
        if self._on_error_occurred:
            try:
                self._on_error_occurred(error_message)
            except Exception:
                pass
    
    def _get_platform_concurrent_limit(self) -> int:
        """
        Detect OS and set appropriate concurrent connection limits
        
        Returns:
            int: Maximum concurrent connections based on platform
        """
        if sys.platform == "win32":
            return 500  # Windows select() limit
        elif sys.platform in ["darwin", "linux"]:
            return 1000  # macOS/Linux can handle more
        else:
            return 300  # Conservative fallback
    
    async def __aenter__(self):
        """Async context manager entry - Initialize session"""
        # TCPConnector tối ưu: giới hạn cache DNS, keepalive
        connector = aiohttp.TCPConnector(
            limit=0,  # No limit on total connections
            ttl_dns_cache=300,  # Cache DNS for 5 minutes
            use_dns_cache=True,
            ssl=False,  # Tắt SSL verify để tăng tốc check
            enable_cleanup_closed=True,
            force_close=True  # Don't reuse connections
        )
        
        # Timeout configuration
        timeout = aiohttp.ClientTimeout(
            total=10,  # Total timeout
            connect=2,  # TCP connect timeout (20% of total)
            sock_read=3  # Socket read timeout
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout
        )
        
        # Note: DNS resolution uses loop.getaddrinfo() in _resolve_ip_async
        # No need for aiohttp.AsyncResolver (which requires aiodns)
        return self
    
    async def __aexit__(self, exc_type, exc, tb):
        """Async context manager exit - Cleanup session"""
        if self.session:
            await self.session.close()
            self.session = None
        
    async def check_proxy_async(self, proxy_data: Dict, timeout: int = 10) -> Dict:
        """
        Smart Protocol Detection with Early Exit Strategy
        
        🚀 OPTIMIZATIONS:
        - Early Exit: Stop on first successful protocol detection
        - Timeout Budget: TCP(20%) + Handshake(30%) + Verify(50%)
        - Async DNS Resolution: Non-blocking getaddrinfo
        - Strict Parsing: RFC-compliant response validation
        
        Args:
            proxy_data: Dict containing host, port, login, password
            timeout: Total timeout budget in seconds
            
        Returns:
            Dict: Detailed result with protocol, IP, timing info
        """
        host = proxy_data.get('host', '')
        port = proxy_data.get('port', 0)
        username = proxy_data.get('login', '')
        password = proxy_data.get('password', '')
        
        # Input validation
        if not host or not port:
            return self._build_fail_result("Invalid Host/Port", 0)
        
        # Validate SOCKS5 auth byte limits (RFC 1928/1929)
        if username and len(username.encode('utf-8')) > 255:
            return self._build_fail_result("Username too long (>255 bytes)", 0)
        if password and len(password.encode('utf-8')) > 255:
            return self._build_fail_result("Password too long (>255 bytes)", 0)
        
        start_time = time.time()
        
        # Timeout budget allocation
        tcp_timeout = timeout * 0.2  # 20% for TCP connect
        handshake_timeout = timeout * 0.3  # 30% for handshake
        verify_timeout = timeout * 0.5  # 50% for forward verification
        
        try:
            # STEP 1: Async DNS Resolution
            resolved_ip = await self._resolve_ip_async(host, int(tcp_timeout))
            target_host = resolved_ip if resolved_ip else host
            
            # STEP 2: TCP Connect Test
            tcp_ok = await self._test_tcp_connect_async(target_host, port, tcp_timeout)
            if not tcp_ok:
                response_time = int((time.time() - start_time) * 1000)
                return self._build_fail_result("TCP Connect failed", response_time)
            
            # STEP 3: Smart Protocol Detection (Early Exit)
            protocol_result = await self._smart_protocol_detection(
                target_host, port, username, password, handshake_timeout
            )
            
            if not protocol_result['success']:
                response_time = int((time.time() - start_time) * 1000)
                return self._build_fail_result("No valid protocol detected", response_time)
            
            detected_protocol = protocol_result['protocol']
            
            # STEP 4: Forward Verification
            forward_result = await self._verify_forward_with_fallback(
                target_host, port, username, password, detected_protocol, verify_timeout
            )
            
            response_time = int((time.time() - start_time) * 1000)
            
            if forward_result['success']:
                return {
                    'success': True,
                    'status': 'Live',
                    'info': f"Live | {detected_protocol.upper()} | {forward_result.get('public_ip', 'Hidden IP')}",
                    'response_time': response_time,
                    'public_ip': forward_result.get('public_ip', 'Unknown'),
                    'type': detected_protocol,
                    'verified_protocol': detected_protocol,
                    'protocols': [detected_protocol],
                    'handshake_verified': True,
                    'forward_verified': True,
                    'resolved_ip': resolved_ip
                }
            else:
                return self._build_fail_result("Handshake OK but forward failed", response_time)
                
        except asyncio.TimeoutError:
            response_time = int((time.time() - start_time) * 1000)
            return self._build_fail_result("Operation timeout", response_time)
        except Exception as e:
            response_time = int((time.time() - start_time) * 1000)
            return self._build_fail_result(f"Unexpected error: {str(e)[:50]}", response_time)
    
    async def _resolve_ip_async(self, host: str, timeout: float) -> Optional[str]:
        """
        Async DNS Resolution using loop.getaddrinfo (Non-blocking)
        
        Args:
            host: Hostname to resolve
            timeout: DNS resolution timeout
            
        Returns:
            str: Resolved IP address or None if failed
        """
        # If already IP address, return as-is
        try:
            import ipaddress
            ipaddress.ip_address(host)
            return host
        except ValueError:
            pass
        
        try:
            loop = asyncio.get_running_loop()
            # Non-blocking DNS resolve
            addr_info = await asyncio.wait_for(
                loop.getaddrinfo(host, None, family=socket.AF_INET),
                timeout=timeout
            )
            if addr_info:
                return addr_info[0][4][0]
        except (asyncio.TimeoutError, Exception):
            pass
        
        return None
    
    async def _test_tcp_connect_async(self, host: str, port: int, timeout: float) -> bool:
        """
        Non-blocking TCP Connect Test using asyncio.open_connection
        
        Args:
            host: Target host (preferably IP)
            port: Target port
            timeout: Connection timeout
            
        Returns:
            bool: True if connection successful
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, Exception):
            return False
    
    async def _smart_protocol_detection(self, host: str, port: int, username: str, 
                                       password: str, timeout: float) -> Dict:
        """
        Smart Protocol Detection with Early Exit Strategy
        
        Uses asyncio.wait(return_when=FIRST_COMPLETED) to exit as soon as
        one protocol is successfully detected, cancelling remaining tasks.
        
        Args:
            host: Target host (IP preferred)
            port: Target port
            username: Auth username
            password: Auth password  
            timeout: Handshake timeout budget
            
        Returns:
            Dict: {'success': bool, 'protocol': str, 'details': dict}
        """
        # Create tasks for all protocols
        tasks = {
            asyncio.create_task(self._test_socks5_handshake(host, port, username, password, timeout)): 'socks5',
            asyncio.create_task(self._test_http_handshake(host, port, username, password, timeout)): 'http',
            asyncio.create_task(self._test_https_handshake(host, port, username, password, timeout)): 'https'
        }
        
        found_protocol = None
        protocol_details = {}
        
        try:
            while tasks:
                # Wait for first task to complete
                done, pending = await asyncio.wait(
                    tasks.keys(), 
                    return_when=asyncio.FIRST_COMPLETED,
                    timeout=timeout
                )
                
                for task in done:
                    try:
                        result = await task
                        if result['success']:
                            found_protocol = tasks[task]
                            protocol_details = result
                            
                            # Cancel all remaining tasks immediately
                            for pending_task in pending:
                                pending_task.cancel()
                            
                            return {
                                'success': True,
                                'protocol': found_protocol,
                                'details': protocol_details
                            }
                    except Exception:
                        pass  # Task failed, continue with others
                    
                    # Remove completed task from tracking
                    del tasks[task]
                
                # If no success yet, continue with remaining tasks
                if not tasks:
                    break
                    
        except asyncio.TimeoutError:
            # Cancel all remaining tasks on timeout
            for task in tasks.keys():
                task.cancel()
        
        return {'success': False, 'protocol': None, 'details': {}}
    
    async def _test_socks5_handshake(self, host: str, port: int, username: str, 
                                   password: str, timeout: float) -> Dict:
        """
        RFC 1928/1929 SOCKS5 Handshake Test (Non-blocking)
        
        Uses asyncio.open_connection for non-blocking socket operations.
        Validates exact RFC compliance with proper byte-level protocol.
        
        Returns:
            Dict: {'success': bool, 'auth_method': str, 'error': str}
        """
        try:
            # Non-blocking connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            try:
                # RFC 1928: Client greeting
                if username and password:
                    # Offer both No Auth (0x00) and Username/Password (0x02)
                    greeting = b'\x05\x02\x00\x02'  # VER=5, NMETHODS=2, METHOD1=0, METHOD2=2
                else:
                    # Only offer No Authentication
                    greeting = b'\x05\x01\x00'      # VER=5, NMETHODS=1, METHOD1=0
                
                writer.write(greeting)
                await writer.drain()
                
                # RFC 1928: Server method selection
                response = await asyncio.wait_for(reader.read(2), timeout=timeout/2)
                
                if len(response) != 2:
                    return {'success': False, 'error': 'Invalid SOCKS5 response length'}
                
                if response[0] != 0x05:
                    return {'success': False, 'error': f'Not SOCKS5 - got version {response[0]}, expected 5'}
                
                selected_method = response[1]
                
                if selected_method == 0x00:  # No auth
                    return {'success': True, 'auth_method': 'No Authentication'}
                    
                elif selected_method == 0x02:  # Username/Password auth
                    if not username or not password:
                        return {'success': False, 'error': 'SOCKS5 requires auth but no credentials provided'}
                    
                    # RFC 1929: Username/Password Authentication
                    auth_request = bytes([0x01, len(username)]) + username.encode('utf-8') + bytes([len(password)]) + password.encode('utf-8')
                    writer.write(auth_request)
                    await writer.drain()
                    
                    auth_response = await asyncio.wait_for(reader.read(2), timeout=timeout/2)
                    
                    if len(auth_response) != 2 or auth_response[0] != 0x01:
                        return {'success': False, 'error': 'Invalid SOCKS5 auth response'}
                    
                    if auth_response[1] != 0x00:
                        return {'success': False, 'error': 'SOCKS5 authentication failed'}
                    
                    return {'success': True, 'auth_method': 'Username/Password Authentication'}
                    
                elif selected_method == 0xFF:
                    return {'success': False, 'error': 'SOCKS5 no acceptable methods'}
                    
                else:
                    return {'success': False, 'error': f'SOCKS5 unsupported method: 0x{selected_method:02X}'}
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'SOCKS5 handshake timeout'}
        except Exception as e:
            return {'success': False, 'error': f'SOCKS5 handshake error: {str(e)[:50]}'}
    
    async def _test_http_handshake(self, host: str, port: int, username: str, 
                                 password: str, timeout: float) -> Dict:
        """
        RFC 7230 HTTP Proxy Handshake Test with Strict Parsing
        
        Uses regex pattern matching for RFC-compliant response validation.
        Tests with lightweight request to minimize bandwidth usage.
        
        Returns:
            Dict: {'success': bool, 'status_code': int, 'error': str}
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            try:
                # Build auth header if credentials provided
                auth_header = ""
                if username and password:
                    import base64
                    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                    auth_header = f"Proxy-Authorization: Basic {credentials}\r\n"
                
                # RFC 7230: HTTP proxy request (lightweight test)
                http_request = (
                    "GET http://httpbin.org/ip HTTP/1.1\r\n"
                    "Host: httpbin.org\r\n"
                    f"{auth_header}"
                    "User-Agent: ProxyChecker/2.0\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode('utf-8')
                
                writer.write(http_request)
                await writer.drain()
                
                # Read response with timeout
                response = await asyncio.wait_for(reader.read(1024), timeout=timeout/2)
                
                if not response:
                    return {'success': False, 'error': 'No HTTP response'}
                
                response_str = response.decode('utf-8', errors='ignore')
                
                # Strict HTTP parsing with regex (RFC compliance)
                match = self.HTTP_RESPONSE_PATTERN.match(response_str)
                if match:
                    status_code = int(match.group(1))
                    return {
                        'success': True, 
                        'status_code': status_code,
                        'response_preview': response_str[:100]
                    }
                else:
                    return {'success': False, 'error': f'Invalid HTTP response format: {response_str[:50]}'}
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'HTTP handshake timeout'}
        except Exception as e:
            return {'success': False, 'error': f'HTTP handshake error: {str(e)[:50]}'}
    
    async def _test_https_handshake(self, host: str, port: int, username: str, 
                                  password: str, timeout: float) -> Dict:
        """
        RFC 7231 HTTPS Proxy (CONNECT Method) Handshake Test
        
        Tests CONNECT method with strict response parsing.
        Validates tunnel establishment capability.
        
        Returns:
            Dict: {'success': bool, 'status_code': int, 'error': str}
        """
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            try:
                # Build auth header if credentials provided
                auth_header = ""
                if username and password:
                    import base64
                    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                    auth_header = f"Proxy-Authorization: Basic {credentials}\r\n"
                
                # RFC 7231: CONNECT method (lightweight test target)
                connect_request = (
                    "CONNECT httpbin.org:80 HTTP/1.1\r\n"
                    "Host: httpbin.org:80\r\n"
                    f"{auth_header}"
                    "User-Agent: ProxyChecker/2.0\r\n"
                    "Proxy-Connection: Keep-Alive\r\n"
                    "\r\n"
                ).encode('utf-8')
                
                writer.write(connect_request)
                await writer.drain()
                
                # Read CONNECT response
                response = await asyncio.wait_for(reader.read(1024), timeout=timeout/2)
                
                if not response:
                    return {'success': False, 'error': 'No CONNECT response'}
                
                response_str = response.decode('utf-8', errors='ignore')
                
                # Strict CONNECT response parsing
                match = self.HTTP_RESPONSE_PATTERN.match(response_str)
                if match:
                    status_code = int(match.group(1))
                    if status_code == 200 and 'connection' in response_str.lower():
                        return {
                            'success': True,
                            'status_code': status_code,
                            'response_preview': response_str[:100]
                        }
                    else:
                        return {'success': False, 'error': f'CONNECT failed with status {status_code}'}
                else:
                    return {'success': False, 'error': f'Invalid CONNECT response: {response_str[:50]}'}
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'HTTPS handshake timeout'}
        except Exception as e:
            return {'success': False, 'error': f'HTTPS handshake error: {str(e)[:50]}'}
    
    def _build_fail_result(self, error_message: str, response_time: int) -> Dict:
        """
        Build standardized failure result.
        
        Args:
            error_message: Detailed error description
            response_time: Time taken for the test in milliseconds
            
        Returns:
            Dict: Standardized failure result
        """
        return {
            'success': False,
            'status': 'Dead',
            'info': f"Dead | {error_message}",
            'response_time': response_time,
            'public_ip': None,
            'resolved_ip': None,
            'type': None,
            'verified_protocol': None,
            'protocols': [],
            'error': error_message
        }
    
    async def _verify_forward_with_fallback(self, host: str, port: int, username: str, 
                                           password: str, protocol: str, timeout: float) -> Dict:
        """
        Forward Verification with Judge URL Fallback Mechanism
        
        Tests actual proxy forwarding capability using multiple judge URLs.
        Falls back to next URL if current one fails/times out.
        
        Args:
            host: Proxy host
            port: Proxy port  
            username: Auth username
            password: Auth password
            protocol: Detected protocol ('socks5', 'http', 'https')
            timeout: Forward verification timeout budget
            
        Returns:
            Dict: {'success': bool, 'public_ip': str, 'judge_url': str}
        """
        for judge_url in self.JUDGE_URLS:
            try:
                if protocol == 'socks5':
                    result = await self._verify_socks5_forward(host, port, username, password, judge_url, timeout/len(self.JUDGE_URLS))
                elif protocol == 'http':
                    result = await self._verify_http_forward(host, port, username, password, judge_url, timeout/len(self.JUDGE_URLS))
                elif protocol == 'https':
                    result = await self._verify_https_forward(host, port, username, password, judge_url, timeout/len(self.JUDGE_URLS))
                else:
                    return {'success': False, 'error': f'Unknown protocol: {protocol}'}
                
                if result['success']:
                    result['judge_url'] = judge_url
                    return result
                    
            except (asyncio.TimeoutError, Exception):
                continue  # Try next judge URL
        
        return {'success': False, 'error': 'All judge URLs failed'}
    
    async def _verify_socks5_forward(self, host: str, port: int, username: str, 
                                   password: str, judge_url: str, timeout: float) -> Dict:
        """
        SOCKS5 Forward Verification using asyncio.open_connection
        
        Performs full SOCKS5 handshake + authentication + CONNECT + HTTP request
        through the established tunnel to verify actual forwarding capability.
        
        Args:
            judge_url: Judge URL to test forwarding (e.g., 'http://httpbin.org/ip')
            
        Returns:
            Dict: {'success': bool, 'public_ip': str, 'error': str}
        """
        try:
            # Parse judge URL
            from urllib.parse import urlparse
            parsed = urlparse(judge_url)
            target_host = parsed.hostname
            target_port = parsed.port or 80
            target_path = parsed.path or '/'
            
            # Async DNS resolution for target
            target_ip = await self._resolve_ip_async(target_host, timeout/4)
            if not target_ip:
                return {'success': False, 'error': f'Failed to resolve {target_host}'}
            
            # Connect to SOCKS5 proxy
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout/4
            )
            
            try:
                # SOCKS5 handshake
                if username and password:
                    greeting = b'\x05\x02\x00\x02'
                else:
                    greeting = b'\x05\x01\x00'
                
                writer.write(greeting)
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(2), timeout=timeout/4)
                if len(response) != 2 or response[0] != 0x05:
                    return {'success': False, 'error': 'SOCKS5 handshake failed'}
                
                selected_method = response[1]
                
                # Handle authentication
                if selected_method == 0x02:  # Username/Password
                    if not username or not password:
                        return {'success': False, 'error': 'SOCKS5 requires auth'}
                    
                    auth_request = bytes([0x01, len(username)]) + username.encode('utf-8') + bytes([len(password)]) + password.encode('utf-8')
                    writer.write(auth_request)
                    await writer.drain()
                    
                    auth_response = await asyncio.wait_for(reader.read(2), timeout=timeout/4)
                    if len(auth_response) != 2 or auth_response[1] != 0x00:
                        return {'success': False, 'error': 'SOCKS5 auth failed'}
                
                elif selected_method != 0x00:
                    return {'success': False, 'error': f'SOCKS5 unsupported method: {selected_method}'}
                
                # CONNECT to target through SOCKS5
                connect_request = (
                    b'\x05' +                           # VER = 5
                    b'\x01' +                           # CMD = 1 (CONNECT)
                    b'\x00' +                           # RSV = 0
                    b'\x01' +                           # ATYP = 1 (IPv4)
                    socket.inet_aton(target_ip) +       # DST.ADDR
                    struct.pack('>H', target_port)      # DST.PORT
                )
                
                writer.write(connect_request)
                await writer.drain()
                
                response = await asyncio.wait_for(reader.read(10), timeout=timeout/4)
                if len(response) < 2 or response[0] != 0x05 or response[1] != 0x00:
                    return {'success': False, 'error': 'SOCKS5 CONNECT failed'}
                
                # Send HTTP request through tunnel
                http_request = (
                    f"GET {target_path} HTTP/1.1\r\n"
                    f"Host: {target_host}\r\n"
                    f"User-Agent: ProxyChecker/2.0\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode('utf-8')
                
                writer.write(http_request)
                await writer.drain()
                
                # Read HTTP response through tunnel
                response_data = await asyncio.wait_for(reader.read(4096), timeout=timeout/4)
                
                if not response_data:
                    return {'success': False, 'error': 'No response through SOCKS5 tunnel'}
                
                response_str = response_data.decode('utf-8', errors='ignore')
                
                # Extract IP from response
                if 'HTTP/' in response_str and '200' in response_str:
                    # Try to find IP in response body
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ips = re.findall(ip_pattern, response_str)
                    public_ip = ips[0] if ips else 'SOCKS5-VERIFIED'
                    
                    return {'success': True, 'public_ip': public_ip}
                else:
                    return {'success': False, 'error': f'Invalid HTTP response: {response_str[:50]}'}
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'SOCKS5 forward timeout'}
        except Exception as e:
            return {'success': False, 'error': f'SOCKS5 forward error: {str(e)[:50]}'}
    
    async def _verify_http_forward(self, host: str, port: int, username: str, 
                                 password: str, judge_url: str, timeout: float) -> Dict:
        """
        HTTP Proxy Forward Verification using aiohttp session
        
        Uses the singleton session to test actual HTTP proxy forwarding.
        Validates response and extracts public IP information.
        
        Returns:
            Dict: {'success': bool, 'public_ip': str, 'error': str}
        """
        try:
            # Build proxy URL with auth
            if username and password:
                proxy_url = f"http://{username}:{password}@{host}:{port}"
            else:
                proxy_url = f"http://{host}:{port}"
            
            # Use singleton session for HTTP proxy test
            async with self.session.get(
                judge_url,
                proxy=proxy_url,
                timeout=aiohttp.ClientTimeout(total=timeout),
                ssl=False,
                allow_redirects=False
            ) as response:
                
                if response.status == 200:
                    content = await response.text()
                    
                    # Try to extract IP from JSON response
                    try:
                        import json
                        if content.strip().startswith('{'):
                            data = json.loads(content)
                            public_ip = data.get('origin', data.get('ip', content.strip()))
                        else:
                            public_ip = content.strip()
                        
                        # Validate IP format
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        ips = re.findall(ip_pattern, public_ip)
                        if ips:
                            return {'success': True, 'public_ip': ips[0]}
                        else:
                            return {'success': True, 'public_ip': 'HTTP-VERIFIED'}
                            
                    except (json.JSONDecodeError, Exception):
                        # Fallback: look for IP pattern in raw content
                        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                        ips = re.findall(ip_pattern, content)
                        public_ip = ips[0] if ips else 'HTTP-VERIFIED'
                        return {'success': True, 'public_ip': public_ip}
                        
                elif response.status == 407:
                    return {'success': False, 'error': 'HTTP proxy authentication required'}
                else:
                    return {'success': False, 'error': f'HTTP proxy returned status {response.status}'}
                    
        except aiohttp.ClientProxyConnectionError:
            return {'success': False, 'error': 'HTTP proxy connection failed'}
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'HTTP forward timeout'}
        except Exception as e:
            return {'success': False, 'error': f'HTTP forward error: {str(e)[:50]}'}
    
    async def _verify_https_forward(self, host: str, port: int, username: str, 
                                  password: str, judge_url: str, timeout: float) -> Dict:
        """
        HTTPS Proxy (CONNECT Method) Forward Verification
        
        Establishes CONNECT tunnel and sends HTTP request through it
        to verify actual HTTPS proxy forwarding capability.
        
        Returns:
            Dict: {'success': bool, 'public_ip': str, 'error': str}
        """
        try:
            # Parse judge URL for CONNECT target
            from urllib.parse import urlparse
            parsed = urlparse(judge_url)
            target_host = parsed.hostname
            target_port = parsed.port or 80
            target_path = parsed.path or '/'
            
            # Connect to HTTPS proxy
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout/3
            )
            
            try:
                # Build auth header if credentials provided
                auth_header = ""
                if username and password:
                    import base64
                    credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                    auth_header = f"Proxy-Authorization: Basic {credentials}\r\n"
                
                # CONNECT request to establish tunnel
                connect_request = (
                    f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                    f"Host: {target_host}:{target_port}\r\n"
                    f"{auth_header}"
                    "User-Agent: ProxyChecker/2.0\r\n"
                    "Proxy-Connection: Keep-Alive\r\n"
                    "\r\n"
                ).encode('utf-8')
                
                writer.write(connect_request)
                await writer.drain()
                
                # Read CONNECT response
                response = await asyncio.wait_for(reader.read(1024), timeout=timeout/3)
                response_str = response.decode('utf-8', errors='ignore')
                
                # Validate CONNECT response with strict parsing
                match = self.HTTP_RESPONSE_PATTERN.match(response_str)
                if not match or int(match.group(1)) != 200:
                    return {'success': False, 'error': f'CONNECT failed: {response_str[:50]}'}
                
                # Send HTTP request through established tunnel
                http_request = (
                    f"GET {target_path} HTTP/1.1\r\n"
                    f"Host: {target_host}\r\n"
                    f"User-Agent: ProxyChecker/2.0\r\n"
                    f"Connection: close\r\n"
                    f"\r\n"
                ).encode('utf-8')
                
                writer.write(http_request)
                await writer.drain()
                
                # Read HTTP response through tunnel
                response_data = await asyncio.wait_for(reader.read(4096), timeout=timeout/3)
                
                if not response_data:
                    return {'success': False, 'error': 'No response through HTTPS tunnel'}
                
                response_str = response_data.decode('utf-8', errors='ignore')
                
                # Validate HTTP response and extract IP
                if 'HTTP/' in response_str and '200' in response_str:
                    # Extract IP from response body
                    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
                    ips = re.findall(ip_pattern, response_str)
                    public_ip = ips[0] if ips else 'HTTPS-VERIFIED'
                    
                    return {'success': True, 'public_ip': public_ip}
                else:
                    return {'success': False, 'error': f'Invalid tunnel response: {response_str[:50]}'}
                    
            finally:
                writer.close()
                await writer.wait_closed()
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'HTTPS forward timeout'}
        except Exception as e:
            return {'success': False, 'error': f'HTTPS forward error: {str(e)[:50]}'}
    
    async def _resolve_hostname_rfc8484(self, session, hostname: str) -> str:
        """
        DNS Resolution theo RFC 8484 (DNS-over-HTTPS).
        
        Tuân thủ RFC 8484 specification:
        - Use HTTPS for DNS queries
        - JSON format response
        - Proper error handling
        
        Args:
            session: aiohttp ClientSession
            hostname: Hostname to resolve
            
        Returns:
            str: Resolved IP address or empty string if failed
        """
        # Nếu đã là IP address, trả về luôn
        try:
            import ipaddress
            ipaddress.ip_address(hostname)
            return hostname  # Đã là IP
        except ValueError:
            pass  # Không phải IP, cần resolve
        
        try:
            # RFC 8484 compliant DNS-over-HTTPS query
            doh_url = "https://dns.google/resolve"
            params = {
                "name": hostname,
                "type": "A",
                "cd": "false",  # RFC 8484: DNSSEC checking disabled
                "do": "false"   # RFC 8484: DNSSEC OK bit
            }
            
            # RFC 8484 recommended timeout
            timeout_obj = aiohttp.ClientTimeout(total=5)
            headers = {
                'Accept': 'application/dns-json',  # RFC 8484 media type
                'User-Agent': 'RFC8484-Compliant-Client/1.0'
            }
            
            async with session.get(doh_url, params=params, headers=headers, timeout=timeout_obj) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # RFC 8484: Check response status
                    if data.get("Status") == 0:  # NOERROR
                        # Find first A record (type 1)
                        for record in data.get("Answer", []):
                            if record.get("type") == 1:  # A record
                                ip_addr = record.get("data", "")
                                # Validate IP format per RFC 791
                                if self._is_valid_ipv4_rfc791(ip_addr):
                                    return ip_addr
            
            return ""  # Resolution failed
            
        except Exception:
            return ""  # DNS resolution error
    
    def _is_valid_ipv4_rfc791(self, ip_str: str) -> bool:
        """
        Validate IPv4 address theo RFC 791.
        
        RFC 791 IPv4 format: A.B.C.D where each octet is 0-255
        """
        try:
            import ipaddress
            addr = ipaddress.IPv4Address(ip_str)
            return True
        except (ipaddress.AddressValueError, ValueError):
            return False
    
    async def _determine_protocols_to_test(self, host: str, port: int, proxy_type: str, 
                                         username: str, password: str) -> List[str]:
        """
        ✅ GIẢI PHÁP PHÂN BIỆT PROXY CHÍNH XÁC 100%
        
        🧠 NGUYÊN TẮC BẤT DI BẤT DỊCH:
        - Không đoán
        - Không dựa port
        - Không dựa format  
        - Chỉ tin handshake + phản hồi hợp lệ
        - Phải test forward thật
        
        📊 BẢNG KẾT LUẬN (KHÔNG CÃI ĐƯỢC):
        - Nhận 05 xx → SOCKS5
        - Nhận HTTP/1.x khi GET → HTTP
        - Nhận 200 Connection Established → HTTPS
        - Handshake OK nhưng không forward → Proxy fake
        - Không handshake nào match → Không phải proxy
        
        🔄 THỨ TỰ TEST MỚI (ƯU TIÊN HTTPS TRƯỚC):
        1. HTTPS/CONNECT (RFC 7231) - Protocol bảo mật cao nhất
        2. HTTP (RFC 7230) - Text protocol phổ biến
        3. SOCKS5 (RFC 1928) - Binary protocol cuối cùng
        """
        # THỨ TỰ MỚI - ƯU TIÊN HTTPS → HTTP → SOCKS5
        return ['https', 'http', 'socks5']
    
    async def _test_protocol_rfc_compliant(self, session, host: str, port: int, username: str, 
                                         password: str, protocol: str, test_endpoints: dict, 
                                         resolved_ip: str, timeout: int) -> Dict:
        """
        RFC-Compliant Protocol Testing.
        
        Tests protocols theo đúng RFC specifications:
        - RFC 1928: SOCKS Protocol Version 5
        - RFC 7230: HTTP/1.1 Message Syntax  
        - RFC 7231: HTTP/1.1 CONNECT Method
        
        Args:
            protocol: 'socks5', 'http', 'https'
            test_endpoints: RFC-compliant test targets
        """
        # Use resolved IP if available (RFC best practice)
        target_host = resolved_ip if resolved_ip else host
        
        if protocol == 'socks5':
            # RFC 1928: SOCKS Protocol Version 5
            result = await self._test_socks5_rfc1928(target_host, port, username, password, timeout)
            
            if result.get('success'):
                result['rfc_info'] = {
                    'rfc_number': '1928',
                    'rfc_title': 'SOCKS Protocol Version 5',
                    'auth_method': result.get('auth_method', 'No Authentication'),
                    'handshake_verified': True
                }
            
            return result
        
        elif protocol == 'http':
            # RFC 7230: HTTP/1.1 Message Syntax and Routing
            result = await self._test_http_rfc7230(session, target_host, port, username, password, 
                                                 test_endpoints['http_target'], timeout)
            
            if result.get('success'):
                result['rfc_info'] = {
                    'rfc_number': '7230',
                    'rfc_title': 'HTTP/1.1 Message Syntax and Routing',
                    'auth_method': 'Basic Authentication (RFC 7617)' if username else 'No Authentication',
                    'test_url': result.get('test_url', 'Unknown')
                }
            
            return result
        
        else:  # https
            # RFC 7231: HTTP/1.1 CONNECT Method
            result = await self._test_https_rfc7231(session, target_host, port, username, password, 
                                                  test_endpoints['connect_target'], timeout)
            
            if result.get('success'):
                result['rfc_info'] = {
                    'rfc_number': '7231',
                    'rfc_title': 'HTTP/1.1 CONNECT Method',
                    'auth_method': 'Basic Authentication over CONNECT' if username else 'No Authentication',
                    'connect_verified': True
                }
            
            return result
    
    async def _test_http_rfc7230(self, session, host: str, port: int, username: str, 
                               password: str, test_url: str, timeout: int) -> Dict:
        """
        RFC 7230 - HTTP/1.1 Message Syntax and Routing (Proxy Support).
        
        RFC 7230 Section 5.3.2: absolute-form for proxy requests
        Request format: GET http://target/ HTTP/1.1\r\nHost: target\r\n\r\n
        
        Expected responses per RFC 7231:
        - 200 OK: Successful proxy request
        - 407 Proxy Authentication Required: Auth needed (RFC 7235)
        - 502 Bad Gateway: Proxy cannot reach target
        
        Compliance: Strict HTTP/1.1 message format validation
        """
        
        # RFC 7617: Basic Authentication (if credentials provided)
        if username and password:
            proxy_url = f"http://{username}:{password}@{host}:{port}"
        else:
            proxy_url = f"http://{host}:{port}"
        
        # RFC 7230 compliant timeout (reasonable for proxy detection)
        timeout_obj = aiohttp.ClientTimeout(total=timeout, connect=2, sock_read=2)
        
        # RFC 7230 Section 5.4: Host header field (required)
        headers = {
            'User-Agent': 'RFC7230-Compliant-Client/1.0',
            'Connection': 'close',  # RFC 7230 Section 6.1
            'Cache-Control': 'no-cache'  # RFC 7234
        }
        
        try:
            # RFC 7230 Section 5.3.2: absolute-form request through proxy
            async with session.get(
                test_url,  # Must be absolute URL for proxy
                proxy=proxy_url,
                timeout=timeout_obj,
                headers=headers,
                ssl=False,
                allow_redirects=False,  # RFC compliance: don't follow redirects
                version=aiohttp.HttpVersion11  # Force HTTP/1.1
            ) as response:
                
                # RFC 7231 Status Code validation
                if response.status == 200:
                    # Successful proxy request
                    try:
                        content = await response.text()
                        # Try to extract IP from JSON response
                        if content.startswith('{'):
                            import json
                            data = json.loads(content)
                            public_ip = data.get('origin', content.strip())
                        else:
                            public_ip = content.strip()
                        
                        # Validate IP format per RFC 791
                        if self._is_valid_ipv4_rfc791(public_ip):
                            return {
                                'success': True,
                                'public_ip': public_ip,
                                'test_url': test_url,
                                'status_code': response.status,
                                'http_version': str(response.version)
                            }
                        else:
                            # Valid HTTP response but not IP format
                            return {
                                'success': True,
                                'public_ip': 'HTTP-RFC7230-OK',
                                'test_url': test_url,
                                'status_code': response.status,
                                'http_version': str(response.version)
                            }
                    except Exception:
                        # Error parsing response, but HTTP proxy works
                        return {
                            'success': True,
                            'public_ip': 'HTTP-RFC7230-RESPONSE-OK',
                            'test_url': test_url,
                            'status_code': response.status,
                            'http_version': str(response.version)
                        }
                            
                elif response.status == 407:
                    # RFC 7235: Proxy Authentication Required
                    return {'success': False, 'error': 'RFC 7235: 407 Proxy Authentication Required'}
                    
                elif response.status == 502:
                    # RFC 7231: Bad Gateway (proxy cannot reach target)
                    return {'success': False, 'error': 'RFC 7231: 502 Bad Gateway (proxy cannot reach target)'}
                    
                else:
                    # Other HTTP status codes
                    return {'success': False, 'error': f'RFC 7231: HTTP {response.status} {response.reason}'}
                    
        except aiohttp.ClientProxyConnectionError:
            return {'success': False, 'error': 'RFC 7230: Proxy connection failed'}
        except aiohttp.ClientConnectorError:
            return {'success': False, 'error': 'RFC 7230: Connection refused'}
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'RFC 7230: Connection timeout'}
        except Exception as e:
            return {'success': False, 'error': f'RFC 7230: Request error - {str(e)[:50]}'}
    
    async def _test_https_rfc7231(self, session, host: str, port: int, username: str, 
                                password: str, connect_target: str, timeout: int) -> Dict:
        """
        RFC 7231 Section 4.3.6 - CONNECT Method Implementation.
        
        RFC 7231 CONNECT method for establishing tunnel:
        Request: CONNECT target:port HTTP/1.1\r\nHost: target:port\r\n\r\n
        Success: HTTP/1.1 200 Connection established\r\n\r\n
        
        RFC 7235 Authentication (if required):
        407 Proxy Authentication Required + Proxy-Authenticate header
        
        Compliance: Exact RFC 7231 CONNECT method implementation
        """
        # RFC 7617: Basic Authentication for proxy
        if username and password:
            proxy_url = f"http://{username}:{password}@{host}:{port}"
        else:
            proxy_url = f"http://{host}:{port}"
        
        # RFC 7231 compliant timeout
        timeout_obj = aiohttp.ClientTimeout(total=timeout, connect=3, sock_read=3)
        
        # RFC 7231 Section 4.3.6: CONNECT method headers
        headers = {
            'User-Agent': 'RFC7231-CONNECT-Client/1.0',
            'Connection': 'close',
            'Proxy-Connection': 'close'  # Legacy but widely supported
        }
        
        # Test HTTPS connection through CONNECT tunnel
        test_https_url = 'https://httpbin.org/ip'
        
        try:
            # RFC 7231: CONNECT method establishes tunnel for HTTPS
            async with session.get(
                test_https_url,
                proxy=proxy_url,
                timeout=timeout_obj,
                headers=headers,
                ssl=True,  # SSL through CONNECT tunnel
                allow_redirects=False,
                version=aiohttp.HttpVersion11  # Force HTTP/1.1
            ) as response:
                
                if response.status == 200:
                    # Successful CONNECT tunnel + HTTPS request
                    try:
                        content = await response.json()
                        public_ip = content.get('origin', 'CONNECT-TUNNEL-OK')
                    except:
                        public_ip = 'RFC7231-CONNECT-VERIFIED'
                    
                    return {
                        'success': True,
                        'public_ip': public_ip,
                        'test_url': test_https_url,
                        'status_code': response.status,
                        'connect_method': True,
                        'tunnel_established': True
                    }
                    
                elif response.status == 407:
                    # RFC 7235: Proxy Authentication Required
                    return {'success': False, 'error': 'RFC 7235: 407 Proxy Authentication Required for CONNECT'}
                    
                elif response.status == 405:
                    # RFC 7231: Method Not Allowed (CONNECT not supported)
                    return {'success': False, 'error': 'RFC 7231: 405 Method Not Allowed (CONNECT not supported)'}
                    
                else:
                    return {'success': False, 'error': f'RFC 7231: CONNECT failed with {response.status} {response.reason}'}
                    
        except aiohttp.ClientProxyConnectionError:
            return {'success': False, 'error': 'RFC 7231: CONNECT proxy connection failed'}
        except aiohttp.ClientConnectorError:
            return {'success': False, 'error': 'RFC 7231: CONNECT connection refused'}
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'RFC 7231: CONNECT timeout'}
        except Exception as e:
            return {'success': False, 'error': f'RFC 7231: CONNECT error - {str(e)[:50]}'}
    

    
    def _is_valid_ip(self, ip_str: str) -> bool:
        """Kiểm tra xem string có phải là IP hợp lệ không"""
        try:
            import ipaddress
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
    
    async def _test_socks_proxy(self, host: str, port: int, username: str, password: str, 
                              proxy_type: str, timeout: int) -> Dict:
        """
        Test SOCKS proxy với RFC compliance - chỉ SOCKS5.
        """
        if proxy_type == 'socks5':
            return await self._test_socks5_rfc1928(host, port, username, password, timeout)
        else:
            # Fallback to simple connection test
            return await self._test_socks_simple(host, port, timeout)
    
    async def _test_socks5_rfc1928(self, host: str, port: int, username: str, password: str, timeout: float) -> Dict:
        """
        RFC 1928 - SOCKS Protocol Version 5 Implementation.
        
        🚀 OPTIMIZED: Uses asyncio.open_connection for non-blocking I/O
        
        Exact RFC 1928 handshake sequence:
        1. Client greeting: VER(0x05) NMETHODS(0x01-0x02) METHODS(0x00,0x02)
        2. Server selection: VER(0x05) METHOD(0x00 or 0x02)
        3. Authentication (if METHOD=0x02): RFC 1929 Username/Password
        4. Connection request: VER(0x05) CMD(0x01) RSV(0x00) ATYP DST.ADDR DST.PORT
        5. Server reply: VER(0x05) REP BND.ADDR BND.PORT
        
        Compliance: Strict RFC 1928 byte-level implementation with async I/O
        """
        reader = None
        writer = None
        
        try:
            # Non-blocking connection using asyncio (NOT blocking socket)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # RFC 1928 Section 3: Initial Handshake
            # Client greeting format: VER | NMETHODS | METHODS
            if username and password:
                # Offer both No Auth (0x00) and Username/Password (0x02)
                greeting = b'\x05\x02\x00\x02'  # VER=5, NMETHODS=2, METHOD1=0, METHOD2=2
            else:
                # Only offer No Authentication
                greeting = b'\x05\x01\x00'      # VER=5, NMETHODS=1, METHOD1=0
            
            writer.write(greeting)
            await writer.drain()
            
            # RFC 1928 Section 3: Server Method Selection
            # Server response format: VER | METHOD
            response = await asyncio.wait_for(reader.read(2), timeout=timeout/2)
            
            if len(response) != 2:
                return {'success': False, 'error': 'RFC 1928 violation: Invalid response length'}
            
            if response[0] != 0x05:
                return {'success': False, 'error': f'RFC 1928 violation: Invalid version {response[0]}, expected 5'}
            
            selected_method = response[1]
            
            # RFC 1928 Section 3: Handle authentication method selection
            if selected_method == 0x00:  # No authentication required
                auth_info = 'No Authentication (RFC 1928 Method 0x00)'
                
            elif selected_method == 0x02:  # Username/Password authentication
                if not username or not password:
                    return {'success': False, 'error': 'RFC 1928: Method 0x02 selected but no credentials provided'}
                
                # RFC 1929: Username/Password Authentication for SOCKS V5
                # Request format: VER | ULEN | UNAME | PLEN | PASSWD
                # Byte limit validation (RFC 1929 max 255 bytes per field)
                username_bytes = username.encode('utf-8')
                password_bytes = password.encode('utf-8')
                
                if len(username_bytes) > 255 or len(password_bytes) > 255:
                    return {'success': False, 'error': 'RFC 1929 violation: Username/Password too long (max 255 bytes)'}
                
                auth_request = bytes([0x01, len(username_bytes)]) + username_bytes + bytes([len(password_bytes)]) + password_bytes
                writer.write(auth_request)
                await writer.drain()
                
                # RFC 1929: Server response format: VER | STATUS
                auth_response = await asyncio.wait_for(reader.read(2), timeout=timeout/2)
                
                if len(auth_response) != 2:
                    return {'success': False, 'error': 'RFC 1929 violation: Invalid auth response length'}
                
                if auth_response[0] != 0x01:
                    return {'success': False, 'error': f'RFC 1929 violation: Invalid auth version {auth_response[0]}'}
                
                if auth_response[1] != 0x00:
                    return {'success': False, 'error': 'RFC 1929: Authentication failed (STATUS != 0x00)'}
                
                auth_info = 'Username/Password Authentication (RFC 1929)'
                
            elif selected_method == 0xFF:  # No acceptable methods
                return {'success': False, 'error': 'RFC 1928: Server returned 0xFF (no acceptable methods)'}
                
            else:
                return {'success': False, 'error': f'RFC 1928: Unsupported authentication method 0x{selected_method:02X}'}
            
            # RFC 1928 Section 4: Connection Request
            # Request format: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
            # Test connection to RFC-compliant test endpoint (Google Public DNS)
            test_ip = '8.8.8.8'
            test_port = 53
            
            # Build CONNECT request per RFC 1928
            connect_request = (
                b'\x05' +                           # VER = 5
                b'\x01' +                           # CMD = 1 (CONNECT)
                b'\x00' +                           # RSV = 0 (Reserved)
                b'\x01' +                           # ATYP = 1 (IPv4)
                socket.inet_aton(test_ip) +         # DST.ADDR (4 bytes)
                struct.pack('>H', test_port)        # DST.PORT (2 bytes, network byte order)
            )
            
            writer.write(connect_request)
            await writer.drain()
            
            # RFC 1928 Section 6: Server Reply
            # Reply format: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
            response = await asyncio.wait_for(reader.read(10), timeout=timeout/2)
            
            if len(response) < 2:
                return {'success': False, 'error': 'RFC 1928 violation: Connection response too short'}
            
            if response[0] != 0x05:
                return {'success': False, 'error': f'RFC 1928 violation: Invalid response version {response[0]}'}
            
            reply_code = response[1]
            
            if reply_code == 0x00:  # Success
                return {
                    'success': True,
                    'public_ip': 'SOCKS5-RFC1928-VERIFIED',
                    'auth_method': auth_info,
                    'protocol_verified': True,
                    'test_endpoint': f'{test_ip}:{test_port}'
                }
            else:
                # RFC 1928 Section 6: Reply field values
                rfc1928_errors = {
                    0x01: 'General SOCKS server failure',
                    0x02: 'Connection not allowed by ruleset', 
                    0x03: 'Network unreachable',
                    0x04: 'Host unreachable',
                    0x05: 'Connection refused',
                    0x06: 'TTL expired',
                    0x07: 'Command not supported',
                    0x08: 'Address type not supported'
                }
                error_msg = rfc1928_errors.get(reply_code, f'Unknown RFC 1928 error code: 0x{reply_code:02X}')
                return {'success': False, 'error': f'RFC 1928: {error_msg}'}
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'SOCKS5 handshake timeout'}
        except Exception as e:
            return {'success': False, 'error': f'SOCKS5 error: {str(e)}'}
        finally:
            # Proper async cleanup
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    

    
    async def _test_socks_simple(self, host: str, port: int, timeout: float) -> Dict:
        """
        Simple SOCKS connection test (fallback).
        
        Uses asyncio.open_connection for non-blocking I/O.
        """
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            return {
                'success': True,
                'public_ip': 'SOCKS-CONNECTED'
            }
            
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Connection timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            if writer:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
    
    async def check_proxies_batch_async(self, proxies: List[Dict], 
                                       progress_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Optimized Batch Proxy Checking with Session Management
        
        Features:
        - Session Singleton: Uses single aiohttp.ClientSession
        - Platform-aware Concurrency: Adapts limits based on OS
        - Progress Callbacks: Real-time progress reporting
        - Graceful Error Handling: Continues on individual failures
        
        Args:
            proxies: List of proxy dictionaries to check
            progress_callback: Optional callback for progress updates
            
        Returns:
            List[Dict]: Results for each proxy in same order as input
        """
        if not proxies:
            return []
        
        self.is_checking = True
        self.stop_requested = False
        results = [None] * len(proxies)
        completed_count = 0
        
        # Use platform-specific concurrency limit
        max_concurrent = min(self.max_concurrent, len(proxies))
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def check_single_proxy(index: int, proxy: Dict):
            """Check single proxy with proper error handling and progress reporting"""
            async with semaphore:
                if self.stop_requested:
                    return
                
                try:
                    # Check proxy with optimized timeout
                    result = await self.check_proxy_async(proxy, timeout=8)
                    results[index] = result
                    
                    nonlocal completed_count
                    completed_count += 1
                    
                    # Emit callbacks for UI updates (thay thế Qt signals)
                    self._emit_proxy_checked(index, result)
                    self._emit_progress_updated(completed_count, len(proxies))
                    
                    # Call progress callback if provided
                    if progress_callback:
                        try:
                            progress_callback(completed_count, len(proxies), result)
                        except Exception:
                            pass  # Don't let callback errors break the flow
                    
                except Exception as e:
                    # Create error result
                    error_result = {
                        'success': False,
                        'status': 'Error',
                        'info': f'Check failed: {str(e)[:50]}',
                        'response_time': 0,
                        'public_ip': None,
                        'resolved_ip': None,
                        'type': None,
                        'verified_protocol': None,
                        'protocols': [],
                        'error': str(e)
                    }
                    results[index] = error_result
                    
                    completed_count += 1
                    self._emit_proxy_checked(index, error_result)
                    self._emit_progress_updated(completed_count, len(proxies))
        
        # Use session singleton context manager
        async with self:
            # Create tasks for all proxies
            tasks = []
            for i, proxy in enumerate(proxies):
                if self.stop_requested:
                    break
                task = asyncio.create_task(check_single_proxy(i, proxy))
                tasks.append(task)
            
            # Wait for all tasks to complete
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
        
        self.is_checking = False
        
        # Emit completion callback
        self._emit_batch_completed(results)
        
        return results
    
    async def check_proxies_generator(self, proxies: List[Dict]) -> AsyncGenerator[Dict, None]:
        """
        Async Generator for Streaming Proxy Check Results
        
        Yields results as soon as each proxy is checked, allowing for
        real-time processing without waiting for entire batch completion.
        
        Args:
            proxies: List of proxy dictionaries to check
            
        Yields:
            Dict: Individual proxy check result with index
        """
        if not proxies:
            return
        
        self.is_checking = True
        self.stop_requested = False
        
        # Use platform-specific concurrency limit
        max_concurrent = min(self.max_concurrent, len(proxies))
        semaphore = asyncio.Semaphore(max_concurrent)
        
        # Queue for results
        result_queue = asyncio.Queue()
        completed_count = 0
        
        async def check_and_queue(index: int, proxy: Dict):
            """Check proxy and put result in queue"""
            async with semaphore:
                if self.stop_requested:
                    return
                
                try:
                    result = await self.check_proxy_async(proxy, timeout=8)
                    await result_queue.put({'index': index, 'result': result, 'proxy': proxy})
                except Exception as e:
                    error_result = {
                        'success': False,
                        'status': 'Error',
                        'info': f'Check failed: {str(e)[:50]}',
                        'response_time': 0,
                        'error': str(e)
                    }
                    await result_queue.put({'index': index, 'result': error_result, 'proxy': proxy})
        
        # Use session singleton
        async with self:
            # Start all check tasks
            tasks = []
            for i, proxy in enumerate(proxies):
                if self.stop_requested:
                    break
                task = asyncio.create_task(check_and_queue(i, proxy))
                tasks.append(task)
            
            # Yield results as they complete
            while completed_count < len(proxies) and not self.stop_requested:
                try:
                    # Wait for next result with timeout
                    result_data = await asyncio.wait_for(result_queue.get(), timeout=1.0)
                    completed_count += 1
                    yield result_data
                except asyncio.TimeoutError:
                    # Check if all tasks are done
                    if all(task.done() for task in tasks):
                        break
                    continue
            
            # Cancel remaining tasks if stopped
            if self.stop_requested:
                for task in tasks:
                    task.cancel()
        
        self.is_checking = False
    
    def check_proxies_batch(self, proxies: List[Dict], max_concurrent: int = 500, 
                           progress_callback: Optional[Callable] = None) -> List[Dict]:
        """
        Wrapper đồng bộ cho check_proxies_batch_async.
        
        Args:
            proxies: List các proxy cần check
            max_concurrent: Số kết nối đồng thời tối đa (ignored, uses platform limit)
            progress_callback: Callback để update progress
            
        Returns:
            List[Dict]: Kết quả check cho từng proxy
        """
        # Note: max_concurrent is set via self.max_concurrent in __init__
        # based on platform detection
        
        # Tạo event loop mới cho thread này
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        
        try:
            # Call with correct 2 arguments (proxies, progress_callback)
            return loop.run_until_complete(
                self.check_proxies_batch_async(proxies, progress_callback)
            )
        finally:
            # Đóng loop nếu tạo mới
            if loop.is_running():
                pass  # Không đóng loop đang chạy
            else:
                loop.close()
    
    def stop_checking(self):
        """Dừng quá trình check"""
        self.stop_requested = True
    
    def check_profiles_proxy(self, profiles: List[Dict]):
        """
        Check proxy cho danh sách profiles.
        
        Args:
            profiles: List các profile có proxy cần check
        """
        try:
            # Chuyển đổi profiles thành format proxy để check
            proxies_to_check = []
            profile_id_map = {}  # Map index -> profile_id
            
            for i, profile in enumerate(profiles):
                proxy_info = profile.get('proxy', '')
                if not proxy_info or proxy_info in ['No proxy', 'None', '', 'null']:
                    continue
                
                # Parse proxy string sử dụng cùng logic với CheckProxy dialog
                proxy_data = self._parse_proxy_string_for_profiles(proxy_info)
                if proxy_data:
                    proxies_to_check.append(proxy_data)
                    profile_id_map[len(proxies_to_check) - 1] = str(profile.get('id', 0))
            
            if not proxies_to_check:
                self._emit_error_occurred("Không có proxy hợp lệ để check")
                return
            
            # Tạo thread để check
            self.checker_thread = ProxyCheckerThread(proxies_to_check)
            
            # Connect callbacks (thay thế signal.connect())
            self.checker_thread.set_on_proxy_checked(
                lambda index, result: self._on_single_proxy_checked(index, result, profile_id_map)
            )
            self.checker_thread.set_on_batch_completed(self._on_batch_check_completed)
            
            # Start checking
            self.checker_thread.start()
            
        except Exception as e:
            self._emit_error_occurred(f"Lỗi: {str(e)}")
    
    def _parse_proxy_string_for_profiles(self, proxy_string: str) -> Optional[Dict]:
        """
        Parse proxy string từ profiles sử dụng cùng logic với CheckProxy dialog.
        
        Args:
            proxy_string: Proxy string từ profile (format: protocol://host:port:user:pass hoặc host:port:user:pass)
        
        Returns:
            Dict: Proxy data hoặc None nếu invalid
        """
        try:
            if not proxy_string or proxy_string.strip() in ['No proxy', 'None', '', 'null']:
                return None
            
            line = proxy_string.strip()
            
            # Danh sách protocol hỗ trợ
            valid_protocols = {'http', 'https', 'socks5'}
            proxy_type = None
            
            # Format 1: protocol://host:port:user:pass (chuẩn URI)
            if "://" in line:
                parts = line.split("://", 1)
                proxy_type = parts[0].lower()
                line = parts[1]
            
            # Format 2: PROTOCOL:host:port:user:pass (format ngắn gọn)
            elif ":" in line:
                first_part = line.split(":", 1)[0].upper()
                if first_part in ['HTTP', 'HTTPS', 'SOCKS5', 'SOCKS4', 'SOCKS']:
                    proxy_type = first_part.lower()
                    line = line.split(":", 1)[1]  # Bỏ protocol prefix
            
            # Nếu không có protocol - mặc định unknown để auto-detect
            if not proxy_type:
                proxy_type = 'unknown'
            
            # Normalize proxy type
            if proxy_type in ['socks', 'socks4']:
                proxy_type = 'socks5'
            elif proxy_type not in ['http', 'https', 'socks5', 'unknown']:
                return None
            
            # Split theo dấu :
            parts = line.split(":", 5)
            
            # BẮT BUỘC phải có ít nhất 2 phần: host:port
            if len(parts) < 2:
                return None
            
            host = parts[0].strip()
            port_str = parts[1].strip()
            login = parts[2].strip() if len(parts) > 2 else ''
            password = parts[3].strip() if len(parts) > 3 else ''
            
            # Validate
            if not host or not port_str.isdigit():
                return None
            
            port = int(port_str)
            if not (1 <= port <= 65535):
                return None
            
            result = {
                'host': host,
                'port': port,
                'login': login,
                'password': password,
                'type': proxy_type
            }
            
            return result
            
        except Exception:
            return None

    def _on_single_proxy_checked(self, index: int, result: Dict, profile_id_map: Dict):
        """Xử lý kết quả check của một proxy"""
        try:
            profile_id = int(profile_id_map.get(index, 0))
            
            if result.get('success', False):
                status = f"Live | {result.get('type', 'Unknown').upper()}"
                if result.get('public_ip'):
                    status += f" | {result.get('public_ip')}"
            else:
                status = "Dead"
            
            response_time = float(result.get('response_time', 0))
            
            # Emit callback để update UI
            self._emit_proxy_status_updated(profile_id, status, response_time)
            
        except Exception:
            pass  # Ignore errors in result processing
    
    def _on_batch_check_completed(self, results: List[Dict]):
        """Xử lý khi hoàn thành check tất cả proxy"""
        try:
            success_count = sum(1 for r in results if r and r.get('success', False))
            total_count = len(results)
            
            # Tạo fake results object để tương thích với callback
            class FakeResult:
                def __init__(self, success):
                    self.is_live = success
            
            fake_results = [FakeResult(r.get('success', False)) for r in results if r]
            self._emit_check_completed(fake_results)
            
        except Exception as e:
            self._emit_error_occurred(f"Lỗi hoàn thành: {str(e)}")


class ProxyCheckerThread(threading.Thread):
    """Thread để chạy proxy checker không block main thread (Pure Python - không dùng PyQt6)"""
    
    def __init__(self, proxies: List[Dict]):
        super().__init__()
        self.proxies = proxies
        self.checker = ProxyChecker()
        self.daemon = True  # Thread sẽ tự động kết thúc khi main thread kết thúc
        
        # Callbacks (thay thế pyqtSignal)
        self._on_progress_updated: Optional[Callable[[int, int], None]] = None
        self._on_proxy_checked: Optional[Callable[[int, dict], None]] = None
        self._on_batch_completed: Optional[Callable[[list], None]] = None
    
    def set_on_progress_updated(self, callback: Callable[[int, int], None]):
        """Set callback for progress updates"""
        self._on_progress_updated = callback
        self.checker.set_on_progress_updated(callback)
    
    def set_on_proxy_checked(self, callback: Callable[[int, dict], None]):
        """Set callback for proxy checked"""
        self._on_proxy_checked = callback
        self.checker.set_on_proxy_checked(callback)
    
    def set_on_batch_completed(self, callback: Callable[[list], None]):
        """Set callback for batch completed"""
        self._on_batch_completed = callback
        self.checker.set_on_batch_completed(callback)
    
    def run(self):
        """Chạy check proxy trong thread riêng với asyncio"""
        try:
            # Tạo event loop mới cho thread này
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                # Chạy async function với platform-aware concurrency
                loop.run_until_complete(
                    self.checker.check_proxies_batch_async(self.proxies)
                )
            finally:
                loop.close()
                
        except Exception:
            pass  # Ignore thread errors to prevent crashes
    
    def stop_checking(self):
        """Dừng quá trình check"""
        if self.checker:
            self.checker.stop_checking()


# Global instance và helper functions
_proxy_checker_instance = None

def get_proxy_checker():
    """
    Lấy instance của ProxyChecker (singleton pattern).
    
    Returns:
        ProxyChecker: Instance của proxy checker
    """
    global _proxy_checker_instance
    if _proxy_checker_instance is None:
        _proxy_checker_instance = ProxyChecker()
    return _proxy_checker_instance

def create_proxy_checker_thread(proxies: List[Dict]):
    """
    Tạo ProxyCheckerThread để check proxy trong background.
    
    Args:
        proxies: List các proxy cần check
        
    Returns:
        ProxyCheckerThread: Thread instance để chạy check
    """
    return ProxyCheckerThread(proxies)