import socket
import threading

def scan_port(ip, port, results):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((ip, port)) == 0:
            results.append(port)
        s.close()
    except Exception:
        pass

def scan(ip, start, end):
    threads = []
    open_ports = []
    for port in range(start, end+1):
        t = threading.Thread(target=scan_port, args=(ip, port, open_ports))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    return open_ports
