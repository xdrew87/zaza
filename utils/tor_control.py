from stem import Signal
from stem.control import Controller

def rotate_tor_identity():
    try:
        with Controller.from_port(port=9051) as c:
            c.authenticate()
            c.signal(Signal.NEWNYM)
    except Exception:
        pass
