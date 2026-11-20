#!/usr/bin/env python3
"""
Mousync - share one mouse & keyboard between two computers on the same network
(a small, self-hosted alternative to ShareMouse).

How it works
  * Run Mousync on both PCs with the same pairing code. They find each other on the
    local network automatically (UDP broadcast); no IP address needed.
  * Push the cursor off the screen edge that faces the other PC. Your mouse and keyboard
    now control that PC. Push it back off the opposite edge to return.
  * The text clipboard is synced both ways: copy on one PC, paste on the other.
  * All traffic is encrypted with AES-256-GCM, using a key derived from the pairing code.
    Discovery beacons carry only an HMAC proof of the code, never the code itself.
  * Emergency return: press Esc three times quickly (or Scroll Lock on Windows).

Platform support
  * Windows and macOS : can control the other PC AND be controlled by it.
  * Linux             : can be controlled.
  * Tick "Primary controller" on one PC to make it the only one that can control.
"""
import argparse
import ctypes
import hashlib
import hmac
import json
import os
import queue
import secrets
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"
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

Quartz = AppKit = None
if IS_MAC:  # pyobjc ships with pynput / pystray on macOS
    try:
        import Quartz
    except ImportError:
        pass
    try:
        import AppKit
    except ImportError:
        pass
CAN_CONTROL = IS_WIN or (IS_MAC and Quartz is not None)  # can capture this PC's mouse/keyboard

APP = "Mousync"
VERSION = "1.1"
DEFAULT_PORT = 24850
DISCOVERY_PORT = 24851      # UDP, LAN broadcast beacons
CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L
FILE_CHUNK = 64 * 1024                 # small pieces so mouse/keyboard messages can slip in between
CLIP_FILE_LIMIT_MB = 2048              # copied files above this are not sent automatically
RECEIVE_DIR = os.path.join(os.path.expanduser("~"), "Downloads", "Mousync")   # "Send files..." lands here
CLIP_CACHE = os.path.join(tempfile.gettempdir(), "Mousync-clipboard")        # copied files land here
CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".mousync.json")
OLD_CONFIG_PATH = os.path.join(os.path.expanduser("~"), ".mousebridge.json")  # pre-rename settings
ASSET_DIR = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), "assets")
OSNAME = "win" if IS_WIN else ("mac" if IS_MAC else "linux")

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
    if IS_MAC and Quartz is not None:
        try:
            _, ids, n = Quartz.CGGetActiveDisplayList(16, None, None)
            rs = [Quartz.CGDisplayBounds(d) for d in ids[:n]]
            if rs:
                return (int(min(r.origin.x for r in rs)), int(min(r.origin.y for r in rs)),
                        int(max(r.origin.x + r.size.width for r in rs)) - 1,
                        int(max(r.origin.y + r.size.height for r in rs)) - 1)
        except Exception:
            pass
    return tuple(_FALLBACK_BOUNDS)


def warp_cursor(x, y):
    if IS_WIN:
        ctypes.windll.user32.SetCursorPos(int(x), int(y))
    elif IS_MAC and Quartz is not None:
        Quartz.CGWarpMouseCursorPosition((float(x), float(y)))


def mac_lock_cursor(locked):
    """While controlling the other PC, freeze the Mac cursor but keep receiving mouse deltas."""
    if IS_MAC and Quartz is not None:
        Quartz.CGAssociateMouseAndMouseCursorPosition(not locked)


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


def _mac_pb():
    return AppKit.NSPasteboard.generalPasteboard()


def clip_seq():
    """Cheap 'has the clipboard changed?' counter, or None to always re-read."""
    try:
        if IS_WIN:
            return ctypes.windll.user32.GetClipboardSequenceNumber()
        if IS_MAC and AppKit is not None:
            return _mac_pb().changeCount()
    except Exception:
        pass
    return None


def clip_set(s):
    if pyperclip and isinstance(s, str):
        try:
            pyperclip.copy(s)
        except Exception:
            pass


def derive_key(password):
    # Salt kept from the app's original name: changing it would break pairing with older builds.
    return hashlib.pbkdf2_hmac("sha256", password.encode(), b"mousebridge-v1", 200_000)


def new_pairing_code():
    c = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return c[:4] + "-" + c[4:]


def normalize_code(code):
    """Pairing codes are case/space/dash-insensitive, so 'k7mq 2pxh' == 'K7MQ-2PXH'."""
    c = "".join(ch for ch in code.upper() if ch.isalnum())
    if len(c) == 8 and all(ch in CODE_ALPHABET for ch in c):
        return c[:4] + "-" + c[4:]
    return code  # a free-form password from 1.0: use as-is


def beacon_tag(key, node_id, port):
    return hmac.new(key, f"mb-discover|{node_id}|{port}".encode(), hashlib.sha256).hexdigest()[:32]


def broadcast_addrs():
    addrs = {"255.255.255.255"}
    ip = local_ip()
    if not ip.startswith("127."):
        addrs.add(ip.rsplit(".", 1)[0] + ".255")  # directed /24 broadcast: picks the right adapter
    return addrs


# ---- files on the clipboard (copied in Explorer / Finder)
if IS_WIN:
    from ctypes import wintypes
    _u32 = ctypes.WinDLL("user32")      # private handles: don't disturb pyperclip's/pynput's argtypes
    _k32 = ctypes.WinDLL("kernel32")
    _sh32 = ctypes.WinDLL("shell32")
    _u32.OpenClipboard.argtypes = [wintypes.HWND]
    _u32.GetClipboardData.argtypes = [wintypes.UINT]
    _u32.GetClipboardData.restype = wintypes.HANDLE
    _u32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    _u32.SetClipboardData.restype = wintypes.HANDLE
    _u32.IsClipboardFormatAvailable.argtypes = [wintypes.UINT]
    _u32.RegisterClipboardFormatW.argtypes = [wintypes.LPCWSTR]
    _u32.RegisterClipboardFormatW.restype = wintypes.UINT
    _u32.CreateWindowExW.argtypes = [wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD,
                                     ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                     wintypes.HWND, wintypes.HMENU, wintypes.HINSTANCE, wintypes.LPVOID]
    _u32.CreateWindowExW.restype = wintypes.HWND
    _u32.DestroyWindow.argtypes = [wintypes.HWND]
    _k32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    _k32.GlobalAlloc.restype = wintypes.HANDLE
    _k32.GlobalLock.argtypes = [wintypes.HANDLE]
    _k32.GlobalLock.restype = ctypes.c_void_p
    _k32.GlobalUnlock.argtypes = [wintypes.HANDLE]
    _k32.GlobalFree.argtypes = [wintypes.HANDLE]
    _sh32.DragQueryFileW.argtypes = [wintypes.HANDLE, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
    _sh32.DragQueryFileW.restype = wintypes.UINT
CF_HDROP = 15


def _win_open_clipboard(hwnd=None):
    for _ in range(10):                 # another app may be holding it for a moment
        if _u32.OpenClipboard(hwnd):
            return True
        time.sleep(0.02)
    return False


def _win_global(blob):
    h = _k32.GlobalAlloc(0x0042, len(blob))  # GMEM_MOVEABLE | GMEM_ZEROINIT
    ptr = _k32.GlobalLock(h)
    ctypes.memmove(ptr, blob, len(blob))
    _k32.GlobalUnlock(h)
    return h


def clip_files():
    """Paths of files/folders currently copied in Explorer/Finder, or None."""
    try:
        if IS_WIN:
            if not _u32.IsClipboardFormatAvailable(CF_HDROP) or not _win_open_clipboard():
                return None
            try:
                h = _u32.GetClipboardData(CF_HDROP)
                if not h:
                    return None
                out = []
                for i in range(_sh32.DragQueryFileW(h, 0xFFFFFFFF, None, 0)):
                    n = _sh32.DragQueryFileW(h, i, None, 0)
                    buf = ctypes.create_unicode_buffer(n + 1)
                    _sh32.DragQueryFileW(h, i, buf, n + 1)
                    out.append(buf.value)
                return out or None
            finally:
                _u32.CloseClipboard()
        if IS_MAC and AppKit is not None:
            pb = _mac_pb()
            urls = pb.readObjectsForClasses_options_(
                [AppKit.NSURL], {AppKit.NSPasteboardURLReadingFileURLsOnlyKey: True})
            return [str(u.path()) for u in urls] if urls else None
    except Exception:
        pass
    return None


def clip_set_files(paths):
    """Put files on the clipboard so Paste in Explorer/Finder copies them."""
    try:
        if IS_WIN:
            # DROPFILES header (pFiles=20, pt=0,0, fNC=0, fWide=1) + double-NUL-terminated UTF-16 list
            blob = struct.pack("<IiiiI", 20, 0, 0, 0, 1) + ("\0".join(paths) + "\0\0").encode("utf-16-le")
            # SetClipboardData fails when the clipboard has no owner window, so make a throwaway one
            hwnd = _u32.CreateWindowExW(0, "STATIC", None, 0, 0, 0, 0, 0, None, None, None, None)
            try:
                if not _win_open_clipboard(hwnd):
                    return False
                try:
                    _u32.EmptyClipboard()
                    h = _win_global(blob)
                    if not _u32.SetClipboardData(CF_HDROP, h):
                        _k32.GlobalFree(h)
                        return False
                    effect = _u32.RegisterClipboardFormatW("Preferred DropEffect")
                    h2 = _win_global(struct.pack("<I", 1))  # DROPEFFECT_COPY: paste copies, never moves
                    if not _u32.SetClipboardData(effect, h2):
                        _k32.GlobalFree(h2)
                    return True
                finally:
                    _u32.CloseClipboard()
            finally:
                _u32.DestroyWindow(hwnd)
        if IS_MAC and AppKit is not None:
            pb = _mac_pb()
            pb.clearContents()
            return bool(pb.writeObjects_([AppKit.NSURL.fileURLWithPath_(p) for p in paths]))
    except Exception:
        pass
    return False


def gather_files(paths):
    """Expand copied files/folders into (source, relative/posix/path, size) plus folder list."""
    files, dirs, total = [], [], 0
    for p in paths:
        p = os.path.abspath(p).rstrip("/\\")
        base = os.path.basename(p) or "item"
        if os.path.isdir(p):
            dirs.append(base)
            for root, dns, fns in os.walk(p):
                rel_root = os.path.relpath(root, os.path.dirname(p)).replace(os.sep, "/")
                dirs.extend(f"{rel_root}/{d}" for d in dns)
                for fn in fns:
                    if fn in (".DS_Store", "Thumbs.db", "desktop.ini"):
                        continue
                    full = os.path.join(root, fn)
                    size = os.path.getsize(full)
                    files.append((full, f"{rel_root}/{fn}", size))
                    total += size
        elif os.path.isfile(p):
            size = os.path.getsize(p)
            files.append((p, base, size))
            total += size
    return files, dirs, total


_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"COM{i}" for i in range(1, 10)} | {f"LPT{i}" for i in range(1, 10)}


def safe_rel(rel):
    """A path from the other PC, made safe: no '..', no absolute paths, legal names on this OS."""
    parts = [x for x in str(rel).replace("\\", "/").split("/") if x not in ("", ".", "..")]
    clean = []
    for x in parts:
        if IS_WIN:
            x = "".join("_" if c in '<>:"|?*' or ord(c) < 32 else c for c in x).rstrip(" .") or "_"
            if x.split(".")[0].upper() in _WIN_RESERVED:
                x = "_" + x
        else:
            x = x.replace("\0", "")
        clean.append(x)
    return os.path.join(*clean) if clean else None


def unique_path(path):
    if not os.path.exists(path):
        return path
    stem, ext = os.path.splitext(path)
    i = 2
    while os.path.exists(f"{stem} ({i}){ext}"):
        i += 1
    return f"{stem} ({i}){ext}"


def fmt_size(n):
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "bytes" else f"{n:.1f} {unit}"
        n /= 1024


def describe(files, dirs):
    tops = {rel.split("/")[0] for _, rel, _ in files} | {d.split("/")[0] for d in dirs}
    if len(tops) == 1:
        return f'"{next(iter(tops))}"'
    return f"{len(tops)} items"


# --------------------------------------------------------------------------- keys
# Windows virtual-key codes -> portable description, so a Mac/Linux peer can replay them.
OEM_CHARS = {0xBA: ";", 0xBB: "=", 0xBC: ",", 0xBD: "-", 0xBE: ".", 0xBF: "/",
             0xC0: "`", 0xDB: "[", 0xDC: "\\", 0xDD: "]", 0xDE: "'"}
VK_TO_NAME = {}
if IS_WIN or IS_MAC:
    for _k in Key:
        if _k.name.startswith("media_"):  # on macOS these reuse normal key codes (0x10 = Y!)
            continue
        try:
            if _k.value.vk is not None:
                VK_TO_NAME.setdefault(_k.value.vk, _k.name)
        except Exception:
            pass

# macOS virtual key code -> unshifted character (ANSI layout), so Windows gets 'c', not a Mac-only code
MAC_CHARS = {
    0x00: "a", 0x01: "s", 0x02: "d", 0x03: "f", 0x04: "h", 0x05: "g", 0x06: "z", 0x07: "x",
    0x08: "c", 0x09: "v", 0x0B: "b", 0x0C: "q", 0x0D: "w", 0x0E: "e", 0x0F: "r", 0x10: "y",
    0x11: "t", 0x12: "1", 0x13: "2", 0x14: "3", 0x15: "4", 0x16: "6", 0x17: "5", 0x18: "=",
    0x19: "9", 0x1A: "7", 0x1B: "-", 0x1C: "8", 0x1D: "0", 0x1E: "]", 0x1F: "o", 0x20: "u",
    0x21: "[", 0x22: "i", 0x23: "p", 0x25: "l", 0x26: "j", 0x27: "'", 0x28: "k", 0x29: ";",
    0x2A: "\\", 0x2B: ",", 0x2C: "/", 0x2D: "n", 0x2E: "m", 0x2F: ".", 0x32: "`",
    0x41: ".", 0x43: "*", 0x45: "+", 0x4B: "/", 0x4E: "-", 0x52: "0", 0x53: "1", 0x54: "2",
    0x55: "3", 0x56: "4", 0x57: "5", 0x58: "6", 0x59: "7", 0x5B: "8", 0x5C: "9",
}
# modifier key code -> device-dependent flag bit (tells left/right press vs release apart)
MAC_MOD_BITS = {0x3B: 0x01, 0x38: 0x02, 0x3C: 0x04, 0x37: 0x08, 0x36: 0x10,
                0x3A: 0x20, 0x3D: 0x40, 0x3E: 0x2000}
MAC_CAPS = 0x39
MAC_ESC, VK_ESCAPE = 0x35, 0x1B
# Between a Mac and a PC, Cmd and Ctrl trade places so Cmd+C on a Mac keyboard is Ctrl+C on Windows.
CMD_CTRL_SWAP = {"cmd": "ctrl", "cmd_l": "ctrl_l", "cmd_r": "ctrl_r",
                 "ctrl": "cmd", "ctrl_l": "cmd_l", "ctrl_r": "cmd_r"}


def vk_char(vk):
    if 0x41 <= vk <= 0x5A or 0x30 <= vk <= 0x39:
        return chr(vk).lower()
    if 0x60 <= vk <= 0x69:
        return str(vk - 0x60)
    return OEM_CHARS.get(vk)


def portable_to_key(m, peer_os):
    if peer_os == OSNAME and OSNAME in ("win", "mac") and m.get("vk") is not None:
        return KeyCode.from_vk(m["vk"])  # same OS: replay the exact key
    name = m.get("name")
    if name:
        if (OSNAME == "mac") != (peer_os == "mac"):
            name = CMD_CTRL_SWAP.get(name, name)
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
        self.send_raw(json.dumps(obj, separators=(",", ":")).encode())

    def send_raw(self, data):
        """Frames whose plaintext starts with 0x01 are file chunks: 0x01 + 8-byte transfer id + bytes."""
        nonce = os.urandom(12)
        body = nonce + self.aes.encrypt(nonce, data, None)
        with self.lock:
            self.sock.sendall(struct.pack("!I", len(body)) + body)

    def recv(self):
        n = struct.unpack("!I", self._exact(4))[0]
        if n > 8_000_000:
            raise ConnectionError("frame too large")
        body = self._exact(n)
        plain = self.aes.decrypt(body[:12], body[12:], None)
        if plain[:1] == b"\x01":
            return {"t": "chunk", "id": plain[1:9].hex(), "data": plain[9:]}
        return json.loads(plain)

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
        self._status, self._last_status = status, None
        self.key = derive_key(normalize_code(cfg["password"]))
        self.auto = not cfg.get("peer", "").strip()
        self.node_id = secrets.token_hex(8)
        self.found = None        # (ip, port, node_id, name, last_seen) of a matching peer
        self.mismatch = set()    # peers seen with a different code (logged once)
        self.dsock = None
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
        self.peer_primary = False
        self.last_clip = None    # last clipboard text sent or received (prevents echo loops)
        self.clip_mark = None
        self.last_files = ()     # last file list copied here or received (prevents echo loops)
        self.peer_files = False  # does the other PC understand file transfers?
        self.tx_id = None        # id of the transfer we are sending (a newer copy cancels it)
        self.rx = None           # transfer we are receiving
        self.last_input = 0.0
        self.esc_times = []
        self.held = set()        # keys we are holding down while being controlled
        self.held_btn = set()
        self.scroll_acc = [0.0, 0.0]
        self.lsock = None
        self.ml = self.kl = None
        self.mctl = mouse.Controller()
        self.kctl = keyboard.Controller()

    def status(self, s):
        if s != self._last_status:   # the search loop re-reports every second
            self._last_status = s
            self._status(s)

    # ---- lifecycle
    def start(self):
        self.running = True
        threading.Thread(target=self._net_loop, daemon=True).start()
        threading.Thread(target=self._send_loop, daemon=True).start()
        if self.auto:
            threading.Thread(target=self._disc_loop, daemon=True).start()
        threading.Thread(target=self._clip_loop, daemon=True).start()
        if IS_WIN:
            self.ml = mouse.Listener(win32_event_filter=self._mfilter)
            self.kl = keyboard.Listener(win32_event_filter=self._kfilter)
        elif CAN_CONTROL:  # macOS
            self.ml = mouse.Listener(darwin_intercept=self._mac_mouse)
            self.kl = keyboard.Listener(darwin_intercept=self._mac_key)
        if self.ml:
            self.ml.start()
            self.kl.start()
            if IS_MAC and not getattr(self.ml, "IS_TRUSTED", True):
                self.log("macOS has not allowed Mousync to use the mouse and keyboard yet. Allow it under "
                         "System Settings > Privacy & Security > Accessibility and Input Monitoring, then restart it.")
            esc = "Esc x3 or Scroll Lock" if IS_WIN else "Esc x3"
            self.log(f"Move the cursor off the {self.cfg['side'].upper()} edge to control the other PC. "
                     f"Emergency return: {esc}.")
        else:
            self.log("This PC can be controlled by the other PC (controlling from Linux is not supported).")

    def stop(self):
        self.running = False
        with self.lock:
            if self.state == CONTROLLED:
                self._release_playback()
            elif self.state == REMOTE:
                self._go_local(0.5)      # also gives the Mac its cursor back
            self.state = LOCAL
        self.tx_id = None
        self._rx_abort()
        for l in (self.ml, self.kl):
            if l:
                l.stop()
        if self.chan:
            self.chan.close()
        for s in (self.lsock, self.dsock):
            if s:
                try:
                    s.close()
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
            f = self.found
            if f and time.time() - f[4] > 5:     # peer stopped beaconing
                f = self.found = None
            if f and self.node_id < f[2]:          # tie-break: lower id dials, higher id waits
                self.status(f"Found {f[3]} at {f[0]}, connecting ...")
                try:
                    s = socket.create_connection((f[0], f[1]), timeout=3)
                except OSError:
                    time.sleep(1)
                    raise
            else:
                if f:
                    self.status(f"Found {f[3]} at {f[0]}, waiting for it to connect ...")
                else:
                    self.status(f"Searching the network for the other PC ... (this PC: {local_ip()})")
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
                chan.send({"t": "hello", "name": socket.gethostname(), "os": OSNAME, "v": VERSION,
                           "primary": bool(self.cfg.get("primary")), "can_control": CAN_CONTROL,
                           "files": True})
                hello = chan.recv()
                if hello.get("t") != "hello":
                    raise ConnectionError("bad handshake")
                self.peer_os, self.peer_name = hello.get("os"), hello.get("name", "?")
                self.peer_primary = bool(hello.get("primary"))
                self.peer_files = bool(hello.get("files"))
                # sync new copies only, not whatever was already on the clipboard
                self.last_clip, self.clip_mark = clip_get(), clip_seq()
                self.last_files = tuple(clip_files() or ())
                with self.out.mutex:
                    self.out.queue.clear()
                self.chan = chan
                self.status(f"Connected to {self.peer_name} ({self.peer_os})")
                self.log(f"Connected to {self.peer_name}. {self.role_text()}")
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
                self.tx_id = None
                self._rx_abort()
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

    def _disc_loop(self):
        """Broadcast a beacon every second and listen for the other PC's beacon."""
        port = int(self.cfg["port"])
        try:
            ds = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ds.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    ds.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            ds.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            ds.bind(("", DISCOVERY_PORT))
            ds.settimeout(0.5)
            self.dsock = ds
        except OSError as e:
            self.log(f"Auto-discovery unavailable ({e}). Enter the other PC's IP instead.")
            return
        beacon = json.dumps({"app": APP, "v": 1, "id": self.node_id, "port": port,
                             "name": socket.gethostname(),
                             "tag": beacon_tag(self.key, self.node_id, port)}).encode()
        next_tx = 0.0
        while self.running:
            if time.time() >= next_tx:
                next_tx = time.time() + 1.0
                for a in broadcast_addrs():
                    try:
                        ds.sendto(beacon, (a, DISCOVERY_PORT))
                    except OSError:
                        pass
            try:
                data, addr = ds.recvfrom(2048)
                m = json.loads(data)
                if m.get("app") != APP or m.get("id") == self.node_id:
                    continue
                pid, pport = str(m["id"]), int(m["port"])
            except socket.timeout:
                continue
            except (OSError, ValueError, KeyError, TypeError):
                if not self.running:
                    break
                continue
            name = str(m.get("name", addr[0]))[:64]
            if hmac.compare_digest(str(m.get("tag", "")), beacon_tag(self.key, pid, pport)):
                if not self.found or self.found[2] != pid:
                    self.log(f"Found {name} ({addr[0]}) with the same pairing code")
                self.found = (addr[0], pport, pid, name, time.time())
            elif pid not in self.mismatch:
                self.mismatch.add(pid)
                self.log(f"Saw Mousync on {name} ({addr[0]}), but it uses a different pairing code")

    # ---- who may control whom
    def can_control(self):
        return CAN_CONTROL and (bool(self.cfg.get("primary")) or not self.peer_primary)

    def role_text(self):
        me, peer, name = bool(self.cfg.get("primary")), self.peer_primary, self.peer_name or "the other PC"
        if me and peer:
            return "Both PCs are ticked as primary, so either can control the other."
        if me:
            return f"This PC is the primary controller: {name} can't control it."
        if peer:
            return f"{name} is the primary controller: this PC can't control it."
        return "Either PC can control the other."

    def set_primary(self, primary):
        self.cfg["primary"] = bool(primary)
        self.send({"t": "role", "primary": bool(primary)})
        self._apply_role()

    def _apply_role(self):
        if self.chan is not None:
            self.log(self.role_text())
        with self.lock:
            if self.state == REMOTE and not self.can_control():
                self._go_local(0.5, notify=True)

    # ---- clipboard: sync every new copy, both ways
    def _clip_loop(self):
        while self.running:
            time.sleep(0.4)
            if self.chan is None or not self.cfg.get("clipboard", True):
                continue
            mark = clip_seq()
            if mark is not None and mark == self.clip_mark:
                continue          # unchanged: skip reading it
            self.clip_mark = mark
            files = clip_files()
            if files:                 # files copied in Explorer/Finder
                if tuple(files) != self.last_files:
                    self.last_files = tuple(files)
                    self.last_clip = clip_get()  # Finder also puts the names as text: don't send those
                    if self.peer_files:
                        self.send_files(files, "clip")
                continue
            text = clip_get()
            if not text or text == self.last_clip:
                continue
            self.last_clip = text
            self.send({"t": "clip", "text": text})

    def base_status(self):
        peer = self.peer_name
        if self.chan is None:
            return "Not connected"
        if self.state == REMOTE:
            return f"Controlling {peer}  (Esc x3 = come back)"
        if self.state == CONTROLLED:
            return f"Controlled by {peer}"
        return f"Connected to {peer} ({self.peer_os})"

    # ---- files: sending
    def send_files(self, paths, mode="send"):
        """mode 'clip': files copied here, pasteable there. mode 'send': saved to Downloads/Mousync there."""
        threading.Thread(target=self._tx_files, args=(list(paths), mode), daemon=True).start()

    def _tx_files(self, paths, mode):
        chan = self.chan
        if chan is None:
            self.log("Not connected, so the files were not sent.")
            return
        if not self.peer_files:
            self.log(f"{self.peer_name} runs an older Mousync without file sharing. Update it to share files.")
            return
        try:
            files, dirs, total = gather_files(paths)
        except OSError as e:
            self.log(f"Can't read the files: {e}")
            return
        if not files and not dirs:
            return
        what = describe(files, dirs)
        limit = int(self.cfg.get("file_limit_mb", CLIP_FILE_LIMIT_MB)) * 1024 * 1024
        if mode == "clip" and total > limit:
            self.log(f"Copied {what} ({fmt_size(total)}): over the {fmt_size(limit)} limit for automatic sharing, "
                     "so it was not sent. Use Send files... to send it anyway.")
            return
        tid = secrets.token_hex(8)
        self.tx_id = tid  # a newer copy replaces this transfer
        raw = b"\x01" + bytes.fromhex(tid)
        sent, shown, start = 0, 0.0, time.time()
        try:
            chan.send({"t": "fstart", "id": tid, "mode": mode, "total": total, "dirs": dirs,
                       "files": [{"p": rel, "n": n} for _, rel, n in files]})
            for src, rel, n in files:
                with open(src, "rb") as f:
                    left = n
                    while left > 0:
                        if self.tx_id != tid or self.chan is not chan:
                            raise InterruptedError
                        # input first: wait for queued mouse/keyboard messages, and pace while they flow
                        while not self.out.empty() and self.chan is chan:
                            time.sleep(0.001)
                        if time.time() - self.last_input < 0.1:
                            time.sleep(0.004)
                        data = f.read(min(FILE_CHUNK, left))
                        if not data:
                            raise OSError(f"{rel} got shorter while it was being sent")
                        chan.send_raw(raw + data)
                        left -= len(data)
                        sent += len(data)
                        if time.time() - shown > 0.5:
                            shown = time.time()
                            self.status(f"Sending {what}: {100 * sent // max(total, 1)}%")
            chan.send({"t": "fend", "id": tid})
            secs = max(time.time() - start, 0.001)
            self.log(f"Sent {what} ({fmt_size(total)}) to {self.peer_name}"
                     + (f" at {fmt_size(total / secs)}/s" if total > 5_000_000 else "")
                     + (". Paste it there." if mode == "clip" else "."))
        except InterruptedError:
            try:
                chan.send({"t": "fabort", "id": tid})
            except Exception:
                pass
        except (OSError, ConnectionError) as e:
            self.log(f"Sending {what} failed: {e}")
            try:
                chan.send({"t": "fabort", "id": tid})
            except Exception:
                pass
        finally:
            if self.tx_id == tid:
                self.tx_id = None
            self.status(self.base_status())

    # ---- files: receiving
    def _rx_start(self, m):
        self._rx_abort()                      # a newer transfer replaces an unfinished one
        mode = "send" if m.get("mode") == "send" else "clip"
        base = RECEIVE_DIR if mode == "send" else CLIP_CACHE
        tid = str(m.get("id", ""))[:16]
        tmp = os.path.join(base, ".incoming-" + tid)
        try:
            os.makedirs(tmp, exist_ok=True)
            tops = []
            for d in m.get("dirs", []):
                rel = safe_rel(d)
                if rel:
                    os.makedirs(os.path.join(tmp, rel), exist_ok=True)
                    tops.append(rel.split(os.sep)[0])
            entries = []
            for f in m.get("files", []):
                rel = safe_rel(f["p"])
                if not rel:
                    raise ValueError("bad file name")
                entries.append((os.path.join(tmp, rel), int(f["n"])))
                tops.append(rel.split(os.sep)[0])
        except (OSError, ValueError, KeyError, TypeError) as e:
            self.log(f"Can't receive files: {e}")
            shutil.rmtree(tmp, ignore_errors=True)
            return
        self.rx = {"id": tid, "mode": mode, "tmp": tmp, "files": entries, "idx": 0, "fh": None,
                   "left": 0, "got": 0, "total": int(m.get("total", 0)), "shown": 0.0,
                   "tops": list(dict.fromkeys(tops)), "start": time.time()}
        try:
            self._rx_next()
        except OSError as e:
            self.log(f"Can't save received files: {e}")
            self._rx_abort()

    def _rx_next(self):
        rx = self.rx
        while rx["idx"] < len(rx["files"]):
            path, n = rx["files"][rx["idx"]]
            os.makedirs(os.path.dirname(path), exist_ok=True)
            fh = open(path, "wb")
            if n > 0:
                rx["fh"], rx["left"] = fh, n
                return
            fh.close()                        # empty file: nothing to wait for
            rx["idx"] += 1
        rx["fh"] = None

    def _rx_chunk(self, m):
        rx = self.rx
        if not rx or m["id"] != rx["id"] or rx["fh"] is None:
            return                            # leftover piece of a cancelled transfer
        data = m["data"]
        try:
            if len(data) > rx["left"]:
                raise OSError("the other PC sent more data than announced")
            rx["fh"].write(data)
            rx["left"] -= len(data)
            rx["got"] += len(data)
            if rx["left"] == 0:
                rx["fh"].close()
                rx["idx"] += 1
                self._rx_next()
        except OSError as e:
            self.log(f"Receiving files failed: {e}")
            self._rx_abort()
            return
        if time.time() - rx["shown"] > 0.5:
            rx["shown"] = time.time()
            self.status(f"Receiving from {self.peer_name}: {100 * rx['got'] // max(rx['total'], 1)}%")

    def _rx_end(self, m):
        rx = self.rx
        if not rx or m.get("id") != rx["id"]:
            return
        if rx["fh"] is not None or rx["idx"] < len(rx["files"]) or rx["got"] != rx["total"]:
            self.log("Received files were incomplete, so they were discarded.")
            self._rx_abort()
            return
        self.rx = None
        what = rx["tops"][0] if len(rx["tops"]) == 1 else f"{len(rx['tops'])} items"
        try:
            if rx["mode"] == "send":          # move each item into Downloads/Mousync, never overwriting
                final = [shutil.move(os.path.join(rx["tmp"], t), unique_path(os.path.join(RECEIVE_DIR, t)))
                         for t in rx["tops"]]
                shutil.rmtree(rx["tmp"], ignore_errors=True)
                where = RECEIVE_DIR
            else:                             # keep in the clipboard cache, ready to paste
                batch = os.path.join(CLIP_CACHE, time.strftime("%Y%m%d-%H%M%S-") + rx["id"][:6])
                os.rename(rx["tmp"], batch)
                final = [os.path.join(batch, t) for t in rx["tops"]]
                self._prune_clip_cache(keep=batch)
                where = None
        except OSError as e:
            self.log(f"Can't save received files: {e}")
            shutil.rmtree(rx["tmp"], ignore_errors=True)
            return
        if self.cfg.get("clipboard", True) and clip_set_files(final):
            self.last_files = tuple(final)
            self.clip_mark = clip_seq()
        paste = "Cmd+V" if IS_MAC else "Ctrl+V"
        msg = f"Received {what} ({fmt_size(rx['total'])}) from {self.peer_name}."
        msg += f" Saved in {where}." if where else f" Paste it with {paste} in a folder."
        self.log(msg)
        self.status(self.base_status())

    def _rx_abort(self):
        rx, self.rx = self.rx, None
        if rx:
            try:
                if rx["fh"]:
                    rx["fh"].close()
            except OSError:
                pass
            shutil.rmtree(rx["tmp"], ignore_errors=True)

    @staticmethod
    def _prune_clip_cache(keep, n=3):
        """Copied files are kept only for the last few copies; older ones are deleted."""
        try:
            batches = sorted(d for d in os.listdir(CLIP_CACHE) if not d.startswith("."))
            for d in batches[:-n]:
                if os.path.join(CLIP_CACHE, d) != keep:
                    shutil.rmtree(os.path.join(CLIP_CACHE, d), ignore_errors=True)
        except OSError:
            pass

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
                if item.get("t") != "ping":
                    self.last_input = time.time()
                chan.send(item)
            except Exception as e:
                self.log(f"Send failed: {e}")
                chan.close()

    # ---- messages from the peer
    def _handle(self, m):
        t = m.get("t")
        if t == "ping":
            return
        if t == "clip":
            text = m.get("text")
            if isinstance(text, str) and self.cfg.get("clipboard", True):
                self.last_clip = text
                clip_set(text)
                self.clip_mark = clip_seq()
            return
        if t == "chunk":
            self._rx_chunk(m)
            return
        if t == "fstart":
            self._rx_start(m)
            return
        if t == "fend":
            self._rx_end(m)
            return
        if t == "fabort":
            if self.rx and self.rx["id"] == m.get("id"):
                self._rx_abort()
                self.status(self.base_status())
            return
        if t == "role":
            self.peer_primary = bool(m.get("primary"))
            self._apply_role()
            return
        if t == "enter":
            if self.cfg.get("primary") and not self.peer_primary:   # we are the only controller
                self.send({"t": "leave", "ratio": m.get("ratio", 0.5)})
                return
            with self.lock:
                if self.state == REMOTE:          # both crossed at once: yield
                    self._go_local(0.5)
                self.state = CONTROLLED
                self.ctrl_from = m.get("from", "left")
                self.scroll_acc = [0.0, 0.0]
            if m.get("clip") is not None and self.cfg.get("clipboard", True):  # from 1.0 peers
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
                    self.status(self.base_status())
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
            self.send({"t": "leave", "ratio": ratio})
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
            if (self.state != LOCAL or self.chan is None or time.time() < self.cooldown
                    or not self.can_control()):
                return False
            side = self.cfg["side"]
            ratio = edge_ratio(side, x, y)
            l, t, r, b = screen_bounds()
            self.park = ((l + r) // 2, (t + b) // 2)
            warp_cursor(*self.park)
            mac_lock_cursor(True)
            self.esc_times = []
            self.state = REMOTE
        self.send({"t": "enter", "from": OPP[side], "ratio": ratio})
        self.status(f"Controlling {self.peer_name}  (Esc x3 = come back)")
        return True

    def _go_local(self, ratio, notify=False):
        """Call with self.lock held."""
        self.state = LOCAL
        self.cooldown = time.time() + 0.4
        mac_lock_cursor(False)
        warp_cursor(*edge_point(self.cfg["side"], ratio, 6))
        if notify:
            self.send({"t": "release"})
        self.status(f"Connected to {self.peer_name}" if self.chan else "Not connected")

    def _hit_edge(self, x, y):
        l, t, r, b = screen_bounds()
        side = self.cfg["side"]
        return ((side == "right" and x >= r - 0.5) or (side == "left" and x <= l + 0.5) or
                (side == "top" and y <= t + 0.5) or (side == "bottom" and y >= b - 0.5))

    def _esc_pressed(self):
        """Three Esc presses within a second while controlling = come back. True if it fired."""
        now = time.time()
        self.esc_times = [t for t in self.esc_times if now - t < 1.0] + [now]
        if len(self.esc_times) < 3:
            return False
        self.esc_times = []
        with self.lock:
            if self.state == REMOTE:
                self._go_local(0.5, notify=True)
        return True

    def _mfilter(self, msg, data):
        if data.flags & LLMHF_INJECTED:
            return False
        if self.state == REMOTE:
            self._forward_mouse(msg, data)
            self.ml.suppress_event()
        elif self.state == LOCAL and msg == WM_MOUSEMOVE and self.chan is not None and self.can_control():
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
            elif down and vk == VK_ESCAPE and self._esc_pressed():
                pass
            else:
                self.send({"t": "key", "down": down, "vk": vk,
                           "name": VK_TO_NAME.get(vk), "char": vk_char(vk)})
            self.kl.suppress_event()
        return False


    # ---- controlling the peer (macOS event taps)
    def _mac_mouse(self, etype, event):
        Q = Quartz
        if Q.CGEventGetIntegerValueField(event, Q.kCGEventSourceUnixProcessID) != 0:
            return event                      # injected by a program (e.g. us, while being controlled)
        if self.state == REMOTE:
            self._mac_forward_mouse(etype, event)
            return None                       # swallow it: this input belongs to the other PC
        if (self.state == LOCAL and etype == Q.kCGEventMouseMoved and self.chan is not None
                and self.can_control()):
            p = Q.CGEventGetLocation(event)
            if self._hit_edge(p.x, p.y) and self._enter_remote(p.x, p.y):
                return None
        return event

    def _mac_forward_mouse(self, etype, event):
        Q = Quartz
        if etype in (Q.kCGEventMouseMoved, Q.kCGEventLeftMouseDragged,
                     Q.kCGEventRightMouseDragged, Q.kCGEventOtherMouseDragged):
            dx = Q.CGEventGetIntegerValueField(event, Q.kCGMouseEventDeltaX)
            dy = Q.CGEventGetIntegerValueField(event, Q.kCGMouseEventDeltaY)
            if dx or dy:
                self.send({"t": "move", "dx": int(dx), "dy": int(dy)})
        elif etype in (Q.kCGEventLeftMouseDown, Q.kCGEventLeftMouseUp):
            self.send({"t": "btn", "b": "left", "down": etype == Q.kCGEventLeftMouseDown})
        elif etype in (Q.kCGEventRightMouseDown, Q.kCGEventRightMouseUp):
            self.send({"t": "btn", "b": "right", "down": etype == Q.kCGEventRightMouseDown})
        elif etype in (Q.kCGEventOtherMouseDown, Q.kCGEventOtherMouseUp):
            n = Q.CGEventGetIntegerValueField(event, Q.kCGMouseEventButtonNumber)
            b = {2: "middle", 3: "x1", 4: "x2"}.get(int(n))
            if b:
                self.send({"t": "btn", "b": b, "down": etype == Q.kCGEventOtherMouseDown})
        elif etype == Q.kCGEventScrollWheel:
            # macOS reports lines; a wheel notch on Windows is ~3 lines
            dy = Q.CGEventGetDoubleValueField(event, Q.kCGScrollWheelEventFixedPtDeltaAxis1) / 3.0
            dx = -Q.CGEventGetDoubleValueField(event, Q.kCGScrollWheelEventFixedPtDeltaAxis2) / 3.0
            if dx or dy:
                self.send({"t": "scroll", "dx": dx, "dy": dy})

    def _mac_key(self, etype, event):
        Q = Quartz
        if self.state != REMOTE:
            return event
        if etype not in (Q.kCGEventKeyDown, Q.kCGEventKeyUp, Q.kCGEventFlagsChanged):
            return None                       # media/system keys: don't act on this Mac either
        if Q.CGEventGetIntegerValueField(event, Q.kCGEventSourceUnixProcessID) != 0:
            return event
        vk = int(Q.CGEventGetIntegerValueField(event, Q.kCGKeyboardEventKeycode))
        if etype == Q.kCGEventFlagsChanged:
            if vk == MAC_CAPS:                # caps lock toggles: tap it on the other side
                for down in (True, False):
                    self.send({"t": "key", "down": down, "vk": vk, "name": "caps_lock", "char": None})
                return None
            bit = MAC_MOD_BITS.get(vk)
            if bit is None:
                return None
            down = bool(Q.CGEventGetFlags(event) & bit)
        else:
            down = etype == Q.kCGEventKeyDown
            if down and vk == MAC_ESC and self._esc_pressed():
                return None
        self.send({"t": "key", "down": down, "vk": vk,
                   "name": VK_TO_NAME.get(vk), "char": MAC_CHARS.get(vk)})
        return None


# --------------------------------------------------------------------------- config
def load_config():
    cfg = {"peer": "", "port": DEFAULT_PORT, "password": "", "side": "right", "clipboard": True,
           "primary": False}
    for path in (CONFIG_PATH, OLD_CONFIG_PATH):  # first one found wins
        try:
            with open(path, encoding="utf-8") as f:
                cfg.update(json.load(f))
            break
        except (OSError, ValueError):
            pass
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except OSError:
        pass


# --------------------------------------------------------------------------- tray / menu bar
def windows_light_taskbar():
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return winreg.QueryValueEx(k, "SystemUsesLightTheme")[0] == 1
    except OSError:
        return False  # Windows default: dark taskbar


def make_tray(menu_items, title):
    """Return a started tray / menu-bar icon, or None if this system has no tray."""
    import pystray
    from PIL import Image

    if sys.platform == "darwin":
        import AppKit
        import Foundation

        class MacIcon(pystray.Icon):
            def _assert_image(self):
                # Sharp @2x template image: macOS tints it for light and dark menu bars.
                if self._icon_image is not None:
                    return
                with open(os.path.join(ASSET_DIR, "tray_mac.png"), "rb") as f:
                    data = f.read()
                img = AppKit.NSImage.alloc().initWithData_(Foundation.NSData.dataWithBytes_length_(data, len(data)))
                h = 16.0
                img.setSize_((h * self._icon.width / self._icon.height, h))
                img.setTemplate_(True)
                self._icon_image = img
                self._status_item.button().setImage_(img)

        img = Image.open(os.path.join(ASSET_DIR, "tray_mac.png"))
        icon = MacIcon(APP, img, title, pystray.Menu(*menu_items))
        icon.run_detached()          # Tk's main loop drives the Cocoa event loop
    else:
        name = "tray_black.png" if (IS_WIN and windows_light_taskbar()) else "tray_white.png"
        img = Image.open(os.path.join(ASSET_DIR, name))
        icon = pystray.Icon(APP, img, title, pystray.Menu(*menu_items))
        threading.Thread(target=icon.run, daemon=True).start()
    return icon


# --------------------------------------------------------------------------- GUI
def run_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    cfg = load_config()
    root = tk.Tk()
    root.title(f"{APP} {VERSION}")
    root.resizable(False, False)
    try:
        root.iconphoto(True, tk.PhotoImage(file=os.path.join(ASSET_DIR, "icon.png")))
    except Exception:
        pass  # running without the assets folder: keep the default icon
    set_fallback_bounds(root.winfo_screenwidth(), root.winfo_screenheight())
    events = queue.Queue()
    state = {"bridge": None}

    frm = ttk.Frame(root, padding=12)
    frm.grid()
    ttk.Label(frm, text=f"This PC: {socket.gethostname()}   IP: {local_ip()}",
              font=("Segoe UI", 10, "bold")).grid(column=0, row=0, columnspan=4, sticky="w", pady=(0, 8))

    ttk.Label(frm, text="Pairing code:").grid(column=0, row=1, sticky="w")
    pw_v = tk.StringVar(value=cfg["password"] or new_pairing_code())
    ttk.Entry(frm, textvariable=pw_v, width=22, font=("Consolas", 11)).grid(column=1, row=1, sticky="w")
    ttk.Button(frm, text="New code", command=lambda: pw_v.set(new_pairing_code())).grid(
        column=2, row=1, sticky="w", padx=6)
    ttk.Label(frm, text="Type the same code on the other PC. It is found automatically.",
              foreground="#666").grid(column=0, row=2, columnspan=4, sticky="w")

    ttk.Label(frm, text="Other PC's IP:").grid(column=0, row=3, sticky="w", pady=(6, 0))
    peer_v = tk.StringVar(value=cfg["peer"])
    ttk.Entry(frm, textvariable=peer_v, width=22).grid(column=1, row=3, sticky="w", pady=(6, 0))
    ttk.Label(frm, text="(optional: only if auto-find fails)", foreground="#666").grid(
        column=2, row=3, columnspan=2, sticky="w", padx=6, pady=(6, 0))

    ttk.Label(frm, text="Port:").grid(column=0, row=4, sticky="w")
    port_v = tk.StringVar(value=str(cfg["port"]))
    ttk.Entry(frm, textvariable=port_v, width=8).grid(column=1, row=4, sticky="w")

    ttk.Label(frm, text="Other PC is on my:").grid(column=0, row=5, sticky="w", pady=(6, 0))
    side_v = tk.StringVar(value=cfg["side"])
    sf = ttk.Frame(frm)
    sf.grid(column=1, row=5, columnspan=3, sticky="w", pady=(6, 0))
    for s in ("left", "right", "top", "bottom"):
        ttk.Radiobutton(sf, text=s.capitalize(), value=s, variable=side_v).pack(side="left", padx=2)

    clip_v = tk.BooleanVar(value=cfg.get("clipboard", True))
    ttk.Checkbutton(frm, text="Share clipboard both ways (text and copied files)", variable=clip_v).grid(
        column=0, row=6, columnspan=4, sticky="w", pady=(4, 0))

    prim_v = tk.BooleanVar(value=cfg.get("primary", False))

    def on_primary():  # applies at once, even while connected
        cfg["primary"] = prim_v.get()
        save_config(cfg)
        if state["bridge"]:
            state["bridge"].set_primary(prim_v.get())

    prim_cb = ttk.Checkbutton(frm, text="Primary controller (only this PC controls the other)",
                              variable=prim_v, command=on_primary)
    prim_cb.grid(column=0, row=7, columnspan=4, sticky="w", pady=(2, 4))
    if not CAN_CONTROL:
        prim_cb.state(["disabled"])

    # status line with a disclosure arrow that shows/hides the log
    status_v = tk.StringVar(value="Stopped")
    srow = ttk.Frame(frm)
    srow.grid(column=0, row=9, columnspan=4, sticky="w", pady=4)
    arrow = ttk.Label(srow, text="\u25b8", width=2, cursor="hand2")
    arrow.pack(side="left")
    status_lbl = ttk.Label(srow, textvariable=status_v, foreground="#0a5", cursor="hand2")
    status_lbl.pack(side="left")

    logbox = tk.Text(frm, width=72, height=10, state="disabled", wrap="word", font="TkFixedFont",
                     borderwidth=0, highlightthickness=0, padx=6, pady=4)  # no scrollbar: wheel scrolls

    def toggle_log(_=None):
        state["log_open"] = not state.get("log_open")
        if state["log_open"]:
            logbox.grid(column=0, row=10, columnspan=4, pady=(2, 0))
            logbox.see("end")
            arrow.config(text="\u25be")
        else:
            logbox.grid_remove()
            arrow.config(text="\u25b8")

    for w in (arrow, status_lbl):
        w.bind("<Button-1>", toggle_log)

    def log(s):
        events.put(("log", time.strftime("%H:%M:%S ") + s))

    def status(s):
        events.put(("status", s))

    def toggle():
        if state["bridge"]:
            state["bridge"].stop()
            state["bridge"] = None
            btn.config(text="Start")
            refresh_tray_menu()
            return
        if not pw_v.get().strip():
            messagebox.showwarning(APP, "Set a pairing code (the same on both PCs).")
            return
        pw_v.set(normalize_code(pw_v.get().strip()))
        try:
            port = int(port_v.get())
        except ValueError:
            messagebox.showwarning(APP, "Port must be a number.")
            return
        new = {"peer": peer_v.get().strip(), "port": port, "password": pw_v.get(),
               "side": side_v.get(), "clipboard": clip_v.get(), "primary": prim_v.get()}
        cfg.update(new)
        save_config(cfg)
        b = Bridge(dict(cfg), log, status)
        b.start()
        state["bridge"] = b
        btn.config(text="Stop")
        refresh_tray_menu()

    def refresh_tray_menu():
        if state.get("tray"):
            try:
                state["tray"].update_menu()
            except Exception:
                pass

    btn = ttk.Button(frm, text="Start", command=toggle)
    btn.grid(column=0, row=8, sticky="w", pady=4)

    def send_files_dialog():
        b = state["bridge"]
        if not b or b.chan is None:
            messagebox.showinfo(APP, "Connect to the other PC first.")
            return
        paths = filedialog.askopenfilenames(parent=root, title=f"Send files to {b.peer_name}")
        if paths:
            b.send_files(paths, "send")

    ttk.Button(frm, text="Send files...", command=send_files_dialog).grid(column=1, row=8, sticky="w", pady=4)

    def pump():
        while True:
            try:
                kind, s = events.get_nowait()
            except queue.Empty:
                break
            if kind == "call":
                s()
            elif kind == "status":
                status_v.set(s)
                if state.get("tray"):
                    state["tray"].title = f"{APP}: {s}"[:127]
            else:
                logbox.config(state="normal")
                logbox.insert("end", s + "\n")
                logbox.see("end")
                logbox.config(state="disabled")
        root.after(100, pump)

    # ---- background mode: closing the window hides it; the tray icon keeps the app alive
    def ui(fn):  # tray callbacks arrive on the tray's thread; run them on Tk's thread
        return lambda *_: events.put(("call", fn))

    def show_window():
        root.deiconify()
        root.lift()
        root.focus_force()

    def hide_window():
        root.withdraw()
        if not state.get("hinted"):
            state["hinted"] = True
            where = "menu bar" if sys.platform == "darwin" else "system tray"
            log(f"Still running in the background. Use the {where} icon to show or quit {APP}.")

    def quit_app():
        if state["bridge"]:
            state["bridge"].stop()
            state["bridge"] = None
        if state.get("tray"):
            try:
                state["tray"].stop()
            except Exception:
                pass
        root.destroy()

    try:
        import pystray
        state["tray"] = make_tray([
            pystray.MenuItem(f"Show {APP}", ui(show_window), default=True),
            pystray.MenuItem(lambda _: "Stop sharing" if state["bridge"] else "Start sharing", ui(toggle)),
            pystray.MenuItem("Send files...", ui(lambda: (show_window(), send_files_dialog()))),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(f"Quit {APP}", ui(quit_app)),
        ], f"{APP}: Stopped")
    except Exception as e:  # no tray available (e.g. some Linux desktops): closing quits
        state["tray"] = None
        log(f"No tray icon ({e}); closing the window will quit.")

    root.protocol("WM_DELETE_WINDOW", hide_window if state["tray"] else quit_app)
    if sys.platform == "darwin":
        root.createcommand("tk::mac::ReopenApplication", show_window)  # click on the Dock icon
        root.createcommand("tk::mac::Quit", quit_app)                  # Cmd+Q / Dock > Quit
    pump()
    if cfg["password"] and "--autostart" in sys.argv:
        toggle()
        if state["tray"]:
            root.withdraw()  # started with the computer: go straight to the tray
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
    if args.primary:
        cfg["primary"] = True
    if args.code:
        cfg["password"] = args.code
    if not cfg["password"]:
        cfg["password"] = new_pairing_code()
        print(f"Pairing code: {cfg['password']}   (run the other PC with --code {cfg['password']})")
    save_config(cfg)
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
    p.add_argument("--peer", help="IP of the other PC (omit to find it automatically)")
    p.add_argument("--port", type=int)
    p.add_argument("--code", help="pairing code (same on both PCs)")
    p.add_argument("--password", help=argparse.SUPPRESS)  # 1.0 name for --code
    p.add_argument("--side", choices=["left", "right", "top", "bottom"], help="where the other PC sits")
    p.add_argument("--no-clipboard", action="store_true")
    p.add_argument("--primary", action="store_true", help="only this PC may control the other")
    args = p.parse_args()
    if args.nogui:
        run_cli(args)
    else:
        run_gui()


if __name__ == "__main__":
    main()
