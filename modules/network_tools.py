import subprocess
import platform

def ping(target):
    cmd = ["ping", "-c", "4", target] if platform.system() != "Windows" else ["ping", "-n", "4", target]
    try:
        out = subprocess.check_output(cmd, universal_newlines=True)
        return out
    except Exception as e:
        return str(e)

def traceroute(target):
    cmd = ["traceroute", target] if platform.system() != "Windows" else ["tracert", target]
    try:
        out = subprocess.check_output(cmd, universal_newlines=True)
        return out
    except Exception as e:
        return str(e)
