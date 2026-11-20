#!/usr/bin/env python3
"""
MouseBridge - share one mouse & keyboard between two computers on the same network
(a small, self-hosted alternative to ShareMouse).

How it works
  * Run MouseBridge on both PCs with the same password.
  * Push the cursor off the screen edge that faces the other PC. Your mouse and keyboard
    now control that PC. Push it back off the opposite edge to return.
  * The clipboard (text) follows the cursor between the two PCs.
  * All traffic is encrypted with AES-256-GCM, using a key derived from the password.
  * Emergency key: Scroll Lock brings control back to this PC at once.

Platform support
  * Windows  : can control the other PC AND be controlled by it.
  * macOS/Linux : can be controlled. Controlling from them is not built yet.
"""
import argparse
import ctypes
import hashlib
import json
import os
import queue
import socket
import struct
import sys
import threading
import time

IS_WIN = sys.platform == "win32"
if IS_WIN:  # use physical pixels on scaled (125%/150%) displays
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pynput import keyboard, mouse
from pynput.keyboard import Key, KeyCode
from pynput.mouse import Button

try:
    import pyperclip
except ImportError:  # clipboard sync is optional
    pyperclip = None

APP = "MouseBridge"
VERSION = "1.0"
DEFAULT_PORT = 24850
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".mousebridge.json")
OSNAME = "win" if IS_WIN else ("mac" if sys.platform == "darwin" else "linux")

LOCAL, REMOTE, CONTROLLED = "local", "remote", "controlled"
OPP = {"left": "right", "right": "left", "top": "bottom", "bottom": "top"}

# --------------------------------------------------------------------------- helpers
_FALLBACK_BOUNDS = [0, 0, 1919, 1079]


def screen_bounds():
    """(left, top, right, bottom) of the whole desktop, inclusive."""
    if IS_WIN:
        u = ctypes.windll.user32
        x, y = u.GetSystemMetrics(76), u.GetSystemMetrics(77)
        w, h = u.GetSystemMetrics(78), u.GetSystemMetrics(79)
        return x, y, x + w - 1, y + h - 1
    return tuple(_FALLBACK_BOUNDS)


def set_fallback_bounds(width, height):
    _FALLBACK_BOUNDS[:] = [0, 0, int(width) - 1, int(height) - 1]


def edge_point(side, ratio, inset):
    l, t, r, b = screen_bounds()
    ratio = min(max(float(ratio), 0.0), 1.0)
    if side == "left":
        return l + inset, int(t + ratio * (b - t))
    if side == "right":
        return r - inset, int(t + ratio * (b - t))
    if side == "top":
        return int(l + ratio * (r - l)), t + inset
    return int(l + ratio * (r - l)), b - inset


def edge_ratio(side, x, y):
    l, t, r, b = screen_bounds()
    if side in ("left", "right"):
        return (y - t) / max(1, b - t)
    return (x - l) / max(1, r - l)


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))  # no packet is sent
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


def clip_get():
    if not pyperclip:
        return None
    try:
        s = pyperclip.paste()
        return s if isinstance(s, str) and len(s) <= 1_000_000 else None
    except Exception:
        return None


def clip_set(s):
    if pyperclip and isinstance(s, str):
        try:
            pyperclip.copy(s)
        except Exception:
            pass


def derive_key(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"mousebridge-v1", 200_000)


# --------------------------------------------------------------------------- keys
# Windows virtual-key codes -> portable description, so a Mac/Linux peer can replay them.
OEM_CHARS = {0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
             0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'"}
VK_TO_NAME = {}
if IS_WIN:
    for _k in Key:
        try:
            if _k.value.vk is not None:
                VK_TO_NAME.setdefault(_k.value.vk, _k.name)
        except Exception:
            pass


def vk_char(vk):
    if 0x41 <= vk <= 0x5A or 0x30 <= vk <= 0x39:
        return chr(vk).lower()
    if 0x60 <= vk <= 0x69:
        return str(vk - 0x60)
    return OEM_CHARS.get(vk)


def portable_to_key(m, peer_os):
    if IS_WIN and peer_os == "win" and m.get("vk") is not None:
        return KeyCode.from_vk(m["vk"])
    name = m.get("name")
    if name:
        try:
            return Key[name]
        except KeyError:
            pass
    if m.get("char"):
        return KeyCode.from_char(m["char"])
    return None


# --------------------------------------------------------------------------- network
class Channel:
    """Length-prefixed, AES-GCM encrypted JSON messages over TCP."""

    def __init__(self, sock, key):
        self.sock = sock
        self.aes = AESGCM(key)
        self.lock = threading.Lock()

    def send(self, obj):
        data = json.dumps(obj, separators=(",", ":")).encode()
        nonce = os.urandom(12)
        body = nonce + self.aes.encrypt(nonce, data, None)
        with self.lock:
            self.sock.sendall(struct.pack("!I", len(body)) + body)

    def recv(self):
        n = struct.unpack("!I", self._exact(4))[0]
        if n > 8_000_000:
            raise ConnectionError("frame too large")
        body = self._exact(n)
        return json.loads(self.aes.decrypt(body[:12], body[12:], None))

    def _exact(self, n):
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("connection closed")
            buf += chunk
        return bytes(buf)

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- Windows hook constants
WM_MOUSEMOVE, WM_MOUSEWHEEL, WM_MOUSEHWHEEL = 0x0200, 0x020A, 0x020E
WM_BUTTONS = {0x0201: ("left", True), 0x0202: ("left", False),
              0x0204: ("right", True), 0x0205: ("right", False),
              0x0207: ("middle", True), 0x0208: ("middle", False)}
WM_XDOWN, WM_XUP = 0x020B, 0x020C
WM_KEYDOWN, WM_KEYUP, WM_SYSKEYDOWN, WM_SYSKEYUP = 0x0100, 0x0101, 0x0104, 0x0105
VK_SCROLL = 0x91
LLMHF_INJECTED = 0x01 | 0x02
LLKHF_INJECTED = 0x10


# --------------------------------------------------------------------------- core
class Bridge:
    def __init__(self, cfg, log, status):
        self.cfg = cfg
        self.log = log
        self.status = status
        self.key = derive_key(cfg["password"])
        self.lock = threading.RLock()
        self.state = LOCAL
        self.chan = None
        self.out = queue.Queue(maxsize=10000)
        self.running = False
        self.cooldown = 0.0
        self.park = (0, 0)
        self.ctrl_from = "left"
        self.peer_os = None
        self.peer_name = None
        self.held = set()        # keys we are holding down while being controlled
        self.held_btn = set()
        self.scroll_acc = [0.0, 0.0]
        self.lsock = None
        self.ml = self.kl = None
        self.mctl = mouse.Controller()
        self.kctl = keyboard.Controller()

    # ---- lifecycle
    def start(self):
        self.running = True
        threading.Thread(target=self._net_loop, daemon=True).start()
        threading.Thread(target=self._send_loop, daemon=True).start()
        if IS_WIN:
            self.ml = mouse.Listener(win32_event_filter=self._mfilter)
            self.kl = keyboard.Listener(win32_event_filter=self._kfilter)
            self.ml.start()
            self.kl.start()
            self.log(f"Move the cursor off the {self.cfg['side'].upper()} edge to control the other PC. "
                     "Scroll Lock = emergency return.")
        else:
            self.log("This PC can be controlled by a Windows PC running MouseBridge. "
                     "(Controlling others from macOS/Linux is not supported yet.)")

    def stop(self):
        self.running = False
        with self.lock:
            if self.state == CONTROLLED:
                self._release_playback()
            self.state = LOCAL
        for l in (self.ml, self.kl):
            if l:
                l.stop()
        if self.chan:
            self.chan.close()
        if self.lsock:
            try:
                self.lsock.close()
            except OSError:
                pass
        self.status("Stopped")

    def send(self, item):
        if self.chan is not None:
            try:
                self.out.put_nowait(item)
            except queue.Full:
                pass

    # ---- networking threads
    def _open_socket(self):
        port = int(self.cfg["port"])
        peer = self.cfg.get("peer", "").strip()
        if peer:
            self.status(f"Connecting to {peer}:{port} ...")
            s = socket.create_connection((peer, port), timeout=5)
        else:
            if self.lsock is None:
                ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                ls.bind(("0.0.0.0", port))
                ls.listen(1)
                ls.settimeout(1.0)
                self.lsock = ls
            self.status(f"Waiting for the other PC ... (this PC: {local_ip()}  port {port})")
            try:
                s, _ = self.lsock.accept()
            except socket.timeout:
                return None
        s.settimeout(10)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        return s

    def _net_loop(self):
        while self.running:
            sock = chan = None
            try:
                sock = self._open_socket()
                if sock is None:
                    continue
                chan = Channel(sock, self.key)
                chan.send({"t": "hello", "name": socket.gethostname(), "os": OSNAME, "v": VERSION})
                hello = chan.recv()
                if hello.get("t") != "hello":
                    raise ConnectionError("bad handshake")
                self.peer_os, self.peer_name = hello.get("os"), hello.get("name", "?")
                with self.out.mutex:
                    self.out.queue.clear()
                self.chan = chan
                self.status(f"Connected to {self.peer_name} ({self.peer_os})")
                self.log(f"Connected to {self.peer_name}")
                while self.running:
                    self._handle(chan.recv())
            except InvalidTag:
                self.log("Wrong password: the other PC uses a different password.")
            except (OSError, ConnectionError, ValueError) as e:
                if self.running:
                    self.log(f"Connection: {e}")
            finally:
                was = self.chan is not None
                self.chan = None
                with self.lock:
                    if self.state == REMOTE:
                        self._go_local(0.5)
                    elif self.state == CONTROLLED:
                        self._release_playback()
                    self.state = LOCAL
                if chan:
                    chan.close()
                elif sock:
                    sock.close()
                if was and self.running:
                    self.log("Disconnected")
            if self.running and self.cfg.get("peer", "").strip():
                time.sleep(2)

    def _send_loop(self):
        while self.running:
            try:
                item = self.out.get(timeout=2)
            except queue.Empty:
                item = {"t": "ping"}
            chan = self.chan
            if chan is None:
                continue
            try:
                if callable(item):
                    item = item()
                chan.send(item)
            except Exception as e:
                self.log(f"Send failed: {e}")
                chan.close()

    # ---- messages from the peer
    def _handle(self, m):
        t = m.get("t")
        if t == "ping":
            return
        if t == "enter":
            with self.lock:
                if self.state == REMOTE:          # both crossed at once: yield
                    self._go_local(0.5)
                self.state = CONTROLLED
                self.ctrl_from = m.get("from", "left")
                self.scroll_acc = [0.0, 0.0]
            if m.get("clip") is not None and self.cfg.get("clipboard", True):
                clip_set(m["clip"])
            self.mctl.position = edge_point(self.ctrl_from, m.get("ratio", 0.5), 2)
            self.status(f"Controlled by {self.peer_name}")
            return
        if t == "leave":
            if m.get("clip") is not None and self.cfg.get("clipboard", True):
                clip_set(m["clip"])
            with self.lock:
                if self.state == REMOTE:
                    self._go_local(m.get("ratio", 0.5))
            return
        if t == "release":
            with self.lock:
                if self.state == CONTROLLED:
                    self._release_playback()
                    self.state = LOCAL
                    self.status(f"Connected to {self.peer_name}")
            return
        if self.state != CONTROLLED:
            return
        if t == "move":
            self._play_move(int(m["dx"]), int(m["dy"]))
        elif t == "btn":
            b = getattr(Button, m["b"], None)
            if b is None:
                return
            if m["down"]:
                self.mctl.press(b)
                self.held_btn.add(b)
            else:
                self.mctl.release(b)
                self.held_btn.discard(b)
        elif t == "scroll":
            self.scroll_acc[0] += float(m.get("dx", 0))
            self.scroll_acc[1] += float(m.get("dy", 0))
            sx, sy = int(self.scroll_acc[0]), int(self.scroll_acc[1])
            if sx or sy:
                self.scroll_acc[0] -= sx
                self.scroll_acc[1] -= sy
                self.mctl.scroll(sx, sy)
        elif t == "key":
            k = portable_to_key(m, self.peer_os)
            if k is None:
                return
            try:
                if m["down"]:
                    self.kctl.press(k)
                    self.held.add(k)
                else:
                    self.kctl.release(k)
                    self.held.discard(k)
            except Exception:
                pass

    def _play_move(self, dx, dy):
        self.mctl.move(dx, dy)
        x, y = self.mctl.position
        l, t, r, b = screen_bounds()
        f = self.ctrl_from
        out = ((f == "left" and dx < 0 and x <= l + 0.5) or (f == "right" and dx > 0 and x >= r - 0.5) or
               (f == "top" and dy < 0 and y <= t + 0.5) or (f == "bottom" and dy > 0 and y >= b - 0.5))
        if out:
            ratio = edge_ratio(f, x, y)
            with self.lock:
                self._release_playback()
                self.state = LOCAL
            use_clip = self.cfg.get("clipboard", True)
            self.send(lambda: {"t": "leave", "ratio": ratio, "clip": clip_get() if use_clip else None})
            self.status(f"Connected to {self.peer_name}")

    def _release_playback(self):
        for k in list(self.held):
            try:
                self.kctl.release(k)
            except Exception:
                pass
        for b in list(self.held_btn):
            try:
                self.mctl.release(b)
            except Exception:
                pass
        self.held.clear()
        self.held_btn.clear()

    # ---- controlling the peer (Windows low-level hooks)
    def _enter_remote(self, x, y):
        with self.lock:
            if self.state != LOCAL or self.chan is None or time.time() < self.cooldown:
                return False
            side = self.cfg["side"]
            ratio = edge_ratio(side, x, y)
            l, t, r, b = screen_bounds()
            self.park = ((l + r) // 2, (t + b) // 2)
            ctypes.windll.user32.SetCursorPos(*self.park)
            self.state = REMOTE
        use_clip = self.cfg.get("clipboard", True)
        self.send(lambda: {"t": "enter", "from": OPP[side], "ratio": ratio,
                           "clip": clip_get() if use_clip else None})
        self.status(f"Controlling {self.peer_name}  (Scroll Lock = come back)")
        return True

    def _go_local(self, ratio, notify=False):
        """Call with self.lock held."""
        self.state = LOCAL
        self.cooldown = time.time() + 0.4
        x, y = edge_point(self.cfg["side"], ratio, 6)
        if IS_WIN:
            ctypes.windll.user32.SetCursorPos(x, y)
        if notify:
            self.send({"t": "release"})
        self.status(f"Connected to {self.peer_name}" if self.chan else "Not connected")

    def _hit_edge(self, x, y):
        l, t, r, b = screen_bounds()
        side = self.cfg["side"]
        return ((side == "right" and x >= r) or (side == "left" and x <= l) or
                (side == "top" and y <= t) or (side == "bottom" and y >= b))

    def _mfilter(self, msg, data):
        if data.flags & LLMHF_INJECTED:
            return False
        if self.state == REMOTE:
            self._forward_mouse(msg, data)
            self.ml.suppress_event()
        elif self.state == LOCAL and msg == WM_MOUSEMOVE and self.chan is not None:
            if self._hit_edge(data.pt.x, data.pt.y) and self._enter_remote(data.pt.x, data.pt.y):
                self.ml.suppress_event()
        return False

    def _forward_mouse(self, msg, data):
        if msg == WM_MOUSEMOVE:
            dx, dy = data.pt.x - self.park[0], data.pt.y - self.park[1]
            if dx or dy:
                self.send({"t": "move", "dx": dx, "dy": dy})
        elif msg in WM_BUTTONS:
            b, down = WM_BUTTONS[msg]
            self.send({"t": "btn", "b": b, "down": down})
        elif msg in (WM_XDOWN, WM_XUP):
            which = "x1" if (data.mouseData >> 16) & 0xFFFF == 1 else "x2"
            self.send({"t": "btn", "b": which, "down": msg == WM_XDOWN})
        elif msg in (WM_MOUSEWHEEL, WM_MOUSEHWHEEL):
            delta = ctypes.c_short((data.mouseData >> 16) & 0xFFFF).value / 120.0
            if msg == WM_MOUSEWHEEL:
                self.send({"t": "scroll", "dx": 0, "dy": delta})
            else:
                self.send({"t": "scroll", "dx": delta, "dy": 0})

    def _kfilter(self, msg, data):
        if data.flags & LLKHF_INJECTED:
            return False
        if self.state == REMOTE:
            down = msg in (WM_KEYDOWN, WM_SYSKEYDOWN)
            vk = data.vkCode
            if vk == VK_SCROLL:
                if down:
                    with self.lock:
                        if self.state == REMOTE:
                            self._go_local(0.5, notify=True)
            else:
                self.send({"t": "key", "down": down, "vk": vk,
                           "name": VK_TO_NAME.get(vk), "char": vk_char(vk)})
            self.kl.suppress_event()
        return False


# --------------------------------------------------------------------------- config
def load_config():
    cfg = {"peer": "", "port": DEFAULT_PORT, "password": "", "side": "right", "clipboard": True}
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except OSError:
        pass


# --------------------------------------------------------------------------- GUI
def run_gui():
    import tkinter as tk
    from tkinter import messagebox, scrolledtext, ttk

    cfg = load_config()
    root = tk.Tk()
    root.title(f"{APP} {VERSION}")
    root.resizable(False, False)
    set_fallback_bounds(root.winfo_screenwidth(), root.winfo_screenheight())
    events = queue.Queue()
    state = {"bridge": None}

    frm = ttk.Frame(root, padding=12)
    frm.grid()
    ttk.Label(frm, text=f"This PC: {socket.gethostname()}   IP: {local_ip()}",
              font=("Segoe UI", 10, "bold")).grid(column=0, row=0, columnspan=4, sticky="w", pady=(0, 8))

    ttk.Label(frm, text="Other PC's IP:").grid(column=0, row=1, sticky="w")
    peer_v = tk.StringVar(value=cfg["peer"])
    ttk.Entry(frm, textvariable=peer_v, width=22).grid(column=1, row=1, sticky="w")
    ttk.Label(frm, text="(leave blank on ONE PC; it waits)", foreground="#666").grid(
        column=2, row=1, columnspan=2, sticky="w", padx=6)

    ttk.Label(frm, text="Port:").grid(column=0, row=2, sticky="w")
    port_v = tk.StringVar(value=str(cfg["port"]))
    ttk.Entry(frm, textvariable=port_v, width=8).grid(column=1, row=2, sticky="w")

    ttk.Label(frm, text="Password:").grid(column=0, row=3, sticky="w")
    pw_v = tk.StringVar(value=cfg["password"])
    ttk.Entry(frm, textvariable=pw_v, width=22, show="*").grid(column=1, row=3, sticky="w")

    ttk.Label(frm, text="Other PC is on my:").grid(column=0, row=4, sticky="w", pady=(6, 0))
    side_v = tk.StringVar(value=cfg["side"])
    sf = ttk.Frame(frm)
    sf.grid(column=1, row=4, columnspan=3, sticky="w", pady=(6, 0))
    for s in ("left", "right", "top", "bottom"):
        ttk.Radiobutton(sf, text=s.capitalize(), value=s, variable=side_v).pack(side="left", padx=2)

    clip_v = tk.BooleanVar(value=cfg.get("clipboard", True))
    ttk.Checkbutton(frm, text="Share clipboard (text)", variable=clip_v).grid(
        column=0, row=5, columnspan=2, sticky="w", pady=4)

    status_v = tk.StringVar(value="Stopped")
    ttk.Label(frm, textvariable=status_v, foreground="#0a5").grid(column=0, row=7, columnspan=4, sticky="w", pady=4)

    logbox = scrolledtext.ScrolledText(frm, width=70, height=10, state="disabled", font=("Consolas", 9))
    logbox.grid(column=0, row=8, columnspan=4, pady=(4, 0))

    def log(s):
        events.put(("log", time.strftime("%H:%M:%S ") + s))

    def status(s):
        events.put(("status", s))

    def toggle():
        if state["bridge"]:
            state["bridge"].stop()
            state["bridge"] = None
            btn.config(text="Start")
            return
        if not pw_v.get():
            messagebox.showwarning(APP, "Set a password (same on both PCs).")
            return
        try:
            port = int(port_v.get())
        except ValueError:
            messagebox.showwarning(APP, "Port must be a number.")
            return
        new = {"peer": peer_v.get().strip(), "port": port, "password": pw_v.get(),
               "side": side_v.get(), "clipboard": clip_v.get()}
        cfg.update(new)
        save_config(cfg)
        b = Bridge(dict(cfg), log, status)
        b.start()
        state["bridge"] = b
        btn.config(text="Stop")

    btn = ttk.Button(frm, text="Start", command=toggle)
    btn.grid(column=0, row=6, sticky="w", pady=4)

    def pump():
        while True:
            try:
                kind, s = events.get_nowait()
            except queue.Empty:
                break
            if kind == "status":
                status_v.set(s)
            else:
                logbox.config(state="normal")
                logbox.insert("end", s + "\n")
                logbox.see("end")
                logbox.config(state="disabled")
        root.after(100, pump)

    def on_close():
        if state["bridge"]:
            state["bridge"].stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    pump()
    if cfg["password"] and "--autostart" in sys.argv:
        toggle()
    root.mainloop()


# --------------------------------------------------------------------------- CLI
def run_cli(args):
    cfg = load_config()
    for k in ("peer", "port", "password", "side"):
        v = getattr(args, k)
        if v is not None:
            cfg[k] = v
    if args.no_clipboard:
        cfg["clipboard"] = False
    if not cfg["password"]:
        sys.exit("A password is required (--password).")
    if not IS_WIN:
        try:
            import tkinter as tk
            r = tk.Tk()
            set_fallback_bounds(r.winfo_screenwidth(), r.winfo_screenheight())
            r.destroy()
        except Exception:
            pass
    b = Bridge(cfg, lambda s: print(time.strftime("%H:%M:%S"), s, flush=True),
               lambda s: print(time.strftime("%H:%M:%S"), "[status]", s, flush=True))
    b.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        b.stop()


def main():
    p = argparse.ArgumentParser(description=f"{APP}: share one mouse/keyboard between two PCs")
    p.add_argument("--nogui", action="store_true", help="run in the terminal")
    p.add_argument("--autostart", action="store_true", help="GUI: start with saved settings")
    p.add_argument("--peer", help="IP of the other PC (omit on the PC that waits)")
    p.add_argument("--port", type=int)
    p.add_argument("--password")
    p.add_argument("--side", choices=["left", "right", "top", "bottom"], help="where the other PC sits")
    p.add_argument("--no-clipboard", action="store_true")
    args = p.parse_args()
    if args.nogui:
        run_cli(args)
    else:
        run_gui()


if __name__ == "__main__":
    main()
