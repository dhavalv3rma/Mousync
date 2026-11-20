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

Quartz = AppKit = HIServices = None
if IS_MAC:  # pyobjc ships with pynput / pystray on macOS
    try:
        import Quartz
        import HIServices
        # pyobjc resolves functions lazily, and that isn't safe when two threads race to do it first.
        # Touch everything the background threads use now, on the main thread.
        for _name in ("CGEventTapCreate", "CGEventTapEnable", "CGEventMaskBit", "CFMachPortCreateRunLoopSource",
                      "CFRunLoopGetCurrent", "CFRunLoopAddSource", "CFRunLoopRun", "CFRunLoopStop",
                      "CGEventGetIntegerValueField", "CGEventGetDoubleValueField", "CGEventGetLocation",
                      "CGEventGetFlags", "CGWarpMouseCursorPosition", "CGAssociateMouseAndMouseCursorPosition",
                      "CGGetActiveDisplayList", "CGDisplayBounds"):
            getattr(Quartz, _name)
        for _name in ("AXIsProcessTrusted", "AXIsProcessTrustedWithOptions"):
            getattr(HIServices, _name)
    except (ImportError, AttributeError, KeyError):
        Quartz = None
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
OS_LABEL = {"win": "Windows", "mac": "macOS", "linux": "Linux"}


def device_label(os_code, name):
    """How a computer is shown everywhere: 'macOS (XD.local)'."""
    osn = OS_LABEL.get(os_code)
    return f"{osn} ({name})" if osn else str(name)
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
    """While controlling the other PC, freeze the Mac cursor where it is but keep receiving mouse deltas.
    Unlocking also cancels the ~0.25 s pause macOS puts on real mouse input after a cursor warp."""
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


# --------------------------------------------------------------------------- macOS input capture
class MacEventTap:
    """One Quartz event tap for mouse + keyboard, on its own thread.

    We don't use pynput's macOS listeners: its keyboard listener asks the system for the keyboard
    layout from a background thread, and recent macOS kills the app for that (dispatch_assert_queue).
    We only need raw key codes, so a plain tap is enough. handler(type, event) returns the event to
    let it through or None to swallow it.
    """
    MOUSE_TYPES = ("kCGEventMouseMoved", "kCGEventLeftMouseDown", "kCGEventLeftMouseUp",
                   "kCGEventRightMouseDown", "kCGEventRightMouseUp", "kCGEventOtherMouseDown",
                   "kCGEventOtherMouseUp", "kCGEventLeftMouseDragged", "kCGEventRightMouseDragged",
                   "kCGEventOtherMouseDragged", "kCGEventScrollWheel")
    KEY_TYPES = ("kCGEventKeyDown", "kCGEventKeyUp", "kCGEventFlagsChanged")
    NX_SYSDEFINED = 14  # media / brightness keys

    def __init__(self, on_mouse, on_key):
        Q = Quartz
        self.on_mouse, self.on_key = on_mouse, on_key
        self.key_types = {getattr(Q, n) for n in self.KEY_TYPES} | {self.NX_SYSDEFINED}
        self.mask = 0
        for n in self.MOUSE_TYPES + self.KEY_TYPES:
            self.mask |= Q.CGEventMaskBit(getattr(Q, n))
        self.mask |= Q.CGEventMaskBit(self.NX_SYSDEFINED)
        self.tap = self.loop = None
        self.ok = False
        self.ready = threading.Event()

    def start(self):
        threading.Thread(target=self._run, daemon=True).start()
        self.ready.wait(3)
        return self.ok

    def _callback(self, proxy, etype, event, refcon):
        Q = Quartz
        if etype in (Q.kCGEventTapDisabledByTimeout, Q.kCGEventTapDisabledByUserInput):
            Q.CGEventTapEnable(self.tap, True)  # macOS switched us off (slow callback): switch back on
            return event
        try:
            return (self.on_key if etype in self.key_types else self.on_mouse)(etype, event)
        except Exception:
            return event                         # never eat input because of a bug in a handler

    def _run(self):
        Q = Quartz
        try:
            self.tap = Q.CGEventTapCreate(Q.kCGSessionEventTap, Q.kCGHeadInsertEventTap,
                                          Q.kCGEventTapOptionDefault, self.mask, self._callback, None)
            if self.tap is None:                 # no Accessibility permission
                return
            src = Q.CFMachPortCreateRunLoopSource(None, self.tap, 0)
            self.loop = Q.CFRunLoopGetCurrent()
            Q.CFRunLoopAddSource(self.loop, src, Q.kCFRunLoopCommonModes)
            Q.CGEventTapEnable(self.tap, True)
            self.ok = True
        finally:
            self.ready.set()
        Q.CFRunLoopRun()

    def stop(self):
        if self.tap is not None:
            Quartz.CGEventTapEnable(self.tap, False)
        if self.loop is not None:
            Quartz.CFRunLoopStop(self.loop)


def mac_trusted(prompt=False):
    """Has the user allowed Mousync under Accessibility? prompt=True shows macOS's own dialog."""
    try:
        if prompt:
            return bool(HIServices.AXIsProcessTrustedWithOptions({HIServices.kAXTrustedCheckOptionPrompt: True}))
        return bool(HIServices.AXIsProcessTrusted())
    except Exception:
        return True


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
        self.enter_t = 0.0
        self.warned_refused = False
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
        self.ml = self.kl = self.tap = None
        # Create these on the main thread: on macOS the keyboard controller reads the keyboard layout,
        # which must not happen on a background thread.
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
        capturing = False
        if IS_WIN:
            self.ml = mouse.Listener(win32_event_filter=self._mfilter)
            self.kl = keyboard.Listener(win32_event_filter=self._kfilter)
            self.ml.start()
            self.kl.start()
            capturing = True
        elif CAN_CONTROL:  # macOS
            trusted = mac_trusted(prompt=True)   # first run: macOS shows its "allow" dialog
            self.tap = MacEventTap(self._mac_mouse, self._mac_key)
            capturing = self.tap.start()
            if not capturing:
                self.tap = None
                self.log("macOS hasn't allowed Mousync to use the mouse and keyboard"
                         + (" yet" if not trusted else "") + ", so this Mac can't control or be controlled. "
                         "Allow Mousync under System Settings > Privacy & Security > Accessibility "
                         "(and Input Monitoring), then press Stop and Start.")
        if capturing:
            esc = "Esc x3 or Scroll Lock" if IS_WIN else "Esc x3"
            self.log(f"Move the cursor off the {self.cfg['side'].upper()} edge to control the other PC. "
                     f"Emergency return: {esc}.")
        elif not IS_MAC:
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
        for l in (self.ml, self.kl, self.tap):
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
                           "can_control": CAN_CONTROL, "files": True})
                hello = chan.recv()
                if hello.get("t") != "hello":
                    raise ConnectionError("bad handshake")
                self.peer_os, self.peer_name = hello.get("os"), hello.get("name", "?")
                self.peer_files = bool(hello.get("files"))
                # sync new copies only, not whatever was already on the clipboard
                self.last_clip, self.clip_mark = clip_get(), clip_seq()
                self.last_files = tuple(clip_files() or ())
                with self.out.mutex:
                    self.out.queue.clear()
                self.chan = chan
                self.status(f"Connected to {self.peer_label}")
                both = CAN_CONTROL and hello.get("can_control", True)
                self.log(f"Connected to {self.peer_label}."
                         + (" Either PC can control the other." if both else ""))
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
                             "name": socket.gethostname(), "os": OSNAME,
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
            name = device_label(str(m.get("os", ""))[:8], str(m.get("name", addr[0]))[:64])
            if hmac.compare_digest(str(m.get("tag", "")), beacon_tag(self.key, pid, pport)):
                if not self.found or self.found[2] != pid:
                    self.log(f"Found {name} at {addr[0]} with the same pairing code")
                self.found = (addr[0], pport, pid, name, time.time())
            elif pid not in self.mismatch:
                self.mismatch.add(pid)
                self.log(f"Saw Mousync on {name} at {addr[0]}, but it uses a different pairing code")

    # ---- clipboard: sync every new copy, both ways
    def _clip_loop(self):
        while self.running:
            time.sleep(0.4)
            share_text, share_files = self.cfg.get("clipboard", True), self.cfg.get("share_files", True)
            if self.chan is None or not (share_text or share_files):
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
                    if self.peer_files and share_files:
                        self.send_files(files, "clip")
                continue
            if not share_text:
                continue
            text = clip_get()
            if not text or text == self.last_clip:
                continue
            self.last_clip = text
            self.send({"t": "clip", "text": text})

    @property
    def peer_label(self):
        return device_label(self.peer_os, self.peer_name) if self.peer_name else "the other PC"

    def base_status(self):
        peer = self.peer_label
        if self.chan is None:
            return "Not connected"
        if self.state == REMOTE:
            return f"Controlling {peer}  (Esc x3 = come back)"
        if self.state == CONTROLLED:
            return f"Controlled by {peer}"
        return f"Connected to {peer}"

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
            self.log(f"{self.peer_label} runs an older Mousync without file sharing. Update it to share files.")
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
            self.log(f"Sent {what} ({fmt_size(total)}) to {self.peer_label}"
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
        if not self.cfg.get("share_files", True):
            self.send({"t": "fabort", "id": m.get("id")})
            self.log(f"Declined files from {self.peer_label}: file sharing is off on this computer.")
            return
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
            self.status(f"Receiving from {self.peer_label}: {100 * rx['got'] // max(rx['total'], 1)}%")

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
        msg = f"Received {what} ({fmt_size(rx['total'])}) from {self.peer_label}."
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
            if self.rx and self.rx["id"] == m.get("id"):      # sender cancelled
                self._rx_abort()
                self.status(self.base_status())
            elif self.tx_id and self.tx_id == m.get("id"):    # receiver declined
                self.tx_id = None
                self.log(f"{self.peer_label} has file sharing turned off, so the files were not sent.")
            return
        if t == "role":           # from builds that had "Primary controller": no longer used
            return
        if t == "enter":
            with self.lock:
                if self.state == REMOTE:          # both crossed at once: yield
                    self._go_local(0.5)
                self.state = CONTROLLED
                self.ctrl_from = m.get("from", "left")
                self.scroll_acc = [0.0, 0.0]
            if m.get("clip") is not None and self.cfg.get("clipboard", True):  # from 1.0 peers
                clip_set(m["clip"])
            self.mctl.position = edge_point(self.ctrl_from, m.get("ratio", 0.5), 2)
            self.status(f"Controlled by {self.peer_label}")
            return
        if t == "leave":
            if (self.state == REMOTE and time.time() - self.enter_t < 0.3
                    and not self.warned_refused):  # sent straight back: an older build refusing control
                self.warned_refused = True
                self.log(f"{self.peer_label} sent control straight back. If it runs an older Mousync with "
                         "'Primary controller' ticked, untick it there or update it to this version.")
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
            self.status(self.base_status())

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
            if self.state != LOCAL or self.chan is None or time.time() < self.cooldown or not CAN_CONTROL:
                return False
            side = self.cfg["side"]
            ratio = edge_ratio(side, x, y)
            if IS_MAC:
                # Freeze the cursor right where it crossed. No warp: a warp makes macOS ignore
                # real trackpad/mouse input for ~0.25 s, and the Mac still reports movement anyway.
                self.park = (x, y)
                mac_lock_cursor(True)
            else:
                # Windows: park in the middle and measure how far each move pushes away from it.
                l, t, r, b = screen_bounds()
                self.park = ((l + r) // 2, (t + b) // 2)
                warp_cursor(*self.park)
            self.esc_times = []
            self.enter_t = time.time()
            self.state = REMOTE
        self.send({"t": "enter", "from": OPP[side], "ratio": ratio})
        self.status(f"Controlling {self.peer_label}  (Esc x3 = come back)")
        return True

    def _go_local(self, ratio, notify=False):
        """Call with self.lock held."""
        self.state = LOCAL
        self.cooldown = time.time() + 0.4
        warp_cursor(*edge_point(self.cfg["side"], ratio, 6))
        mac_lock_cursor(False)   # after the warp: also lifts macOS's post-warp input pause
        if notify:
            self.send({"t": "release"})
        self.status(self.base_status())

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
        if self.state == LOCAL and etype == Q.kCGEventMouseMoved and self.chan is not None:
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
           "share_files": True, "theme": "system"}
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
# The window is drawn entirely by Mousync (rounded cards, switches, icons) instead of using each
# OS's native widgets, so it looks the same on Windows and macOS, in dark and light mode.
THEMES = {
    "dark": dict(bg="#111117", card="#1A1A23", tile="#24242F", border="#2B2B38", text="#F3F3F8",
                 muted="#9B9BAF", accent="#7B5CFF", accent_hover="#8C70FF", accent_soft="#2A2350",
                 on_accent="#FFFFFF", green="#3DDC84", green_bg="#14301F", blue="#5AA9FF",
                 blue_bg="#152639", amber="#F5B544", grey="#6E6E80", switch_off="#3A3A4A",
                 knob="#FFFFFF", field="#14141B", log="#14141B"),
    "light": dict(bg="#F3F3F8", card="#FFFFFF", tile="#F0EFF7", border="#E1E0EB", text="#16161E",
                  muted="#6B6B7F", accent="#6A47FF", accent_hover="#7A5BFF", accent_soft="#EEE9FF",
                  on_accent="#FFFFFF", green="#15A256", green_bg="#E2F5E9", blue="#2F7DE1",
                  blue_bg="#E3EEFB", amber="#C98000", grey="#A3A3B3", switch_off="#D4D3DF",
                  knob="#FFFFFF", field="#F7F7FB", log="#F7F7FB"),
}


def system_theme():
    try:
        if IS_MAC and AppKit is not None:
            style = AppKit.NSUserDefaults.standardUserDefaults().stringForKey_("AppleInterfaceStyle")
            return "dark" if style and str(style).lower() == "dark" else "light"
        if IS_WIN:
            import winreg
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
                return "light" if winreg.QueryValueEx(k, "AppsUseLightTheme")[0] == 1 else "dark"
    except Exception:
        pass
    return "dark"


def match_title_bar(root, theme):
    """Make the OS title bar follow the app theme."""
    try:
        if IS_MAC and AppKit is not None:
            name = AppKit.NSAppearanceNameDarkAqua if theme == "dark" else AppKit.NSAppearanceNameAqua
            AppKit.NSApplication.sharedApplication().setAppearance_(AppKit.NSAppearance.appearanceNamed_(name))
        elif IS_WIN:
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            on = ctypes.c_int(1 if theme == "dark" else 0)
            for attr in (20, 19):  # DWMWA_USE_IMMERSIVE_DARK_MODE (newer, older Windows 10)
                if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attr, ctypes.byref(on), 4) == 0:
                    break
    except Exception:
        pass


def status_view(s):
    """Status text from the bridge -> (dot colour key, title, subtitle)."""
    if s.startswith("Controlling "):
        return "accent", "Controlling", s[len("Controlling "):].split("  (")[0] + "  ·  Esc ×3 to come back"
    if s.startswith("Controlled by "):
        return "accent", "Being controlled", "by " + s[len("Controlled by "):]
    if s.startswith("Connected to "):
        return "green", "Connected", s[len("Connected to "):]
    if s.startswith(("Sending", "Receiving")):
        return "blue", s.split(":")[0], s.split(":", 1)[1].strip() if ":" in s else ""
    if s.startswith("Searching"):
        return "amber", "Searching…", "Looking for the other computer on your network"
    if s.startswith(("Found", "Connecting")):
        return "amber", "Connecting…", s.split(",")[0]
    if s.startswith("Not connected"):
        return "grey", "Not connected", "Waiting for the other computer"
    if s.startswith("Stopped"):
        return "grey", "Stopped", "Not sharing yet"
    return "grey", s, ""


def run_gui():
    import tkinter as tk
    import tkinter.font as tkfont
    from tkinter import filedialog, messagebox

    cfg = load_config()
    root = tk.Tk()
    root.title(f"{APP} {VERSION}")
    root.resizable(False, False)
    try:
        app_icon = tk.PhotoImage(file=os.path.join(ASSET_DIR, "icon.png"))
        root.iconphoto(True, app_icon)
    except Exception:
        app_icon = None  # running without the assets folder: keep the default icon
    set_fallback_bounds(root.winfo_screenwidth(), root.winfo_screenheight())
    events = queue.Queue()

    # Same physical size everywhere: Tk on Windows works in real pixels (the app is DPI-aware),
    # on macOS in points. S scales every size; fonts use pixel sizes so they scale identically.
    scale = {"S": 1.0 if IS_MAC else max(1.0, root.winfo_fpixels("1i") / 96.0)}

    def px(n):
        return int(round(n * scale["S"]))

    family = tkfont.nametofont("TkDefaultFont").actual("family") if IS_MAC else "Segoe UI"
    mono = "Menlo" if IS_MAC else "Consolas"

    def F(size, weight="normal", fam=None):
        return (fam or family, -px(size), weight)

    saved = normalize_code(cfg.get("password") or "")
    state = {
        "bridge": None, "status": "Stopped", "log_lines": [], "log_open": False,
        "theme": cfg.get("theme") if cfg.get("theme") in THEMES else system_theme(),
        "code": saved if len(saved) == 9 and saved[4] == "-" else new_pairing_code(),
    }
    peer_v = tk.StringVar(value=cfg.get("peer", ""))
    port_v = tk.StringVar(value=str(cfg.get("port", DEFAULT_PORT)))
    side_v = tk.StringVar(value=cfg.get("side", "right"))
    clip_v = tk.BooleanVar(value=cfg.get("clipboard", True))
    files_v = tk.BooleanVar(value=cfg.get("share_files", True))
    w = {}  # widgets of the current build, rebuilt on theme change

    # ---------------------------------------------------------------- drawing kit
    def rrect(c, x1, y1, x2, y2, r, **kw):
        r = max(0, min(r, (x2 - x1) / 2, (y2 - y1) / 2))
        pts = [x1 + r, y1, x2 - r, y1, x2, y1, x2, y1 + r, x2, y2 - r, x2, y2, x2 - r, y2,
               x1 + r, y2, x1, y2, x1, y2 - r, x1, y1 + r, x1, y1]
        return c.create_polygon(pts, smooth=True, splinesteps=16, **kw)

    def icon(c, kind, cx, cy, s, col, bg):
        lw = max(1.5, s / 11)
        L = dict(fill=col, width=lw, capstyle="round", joinstyle="round")
        O = dict(outline=col, width=lw, fill="")
        h = s / 2
        if kind == "monitor":
            rrect(c, cx - h, cy - s * .38, cx + h, cy + s * .2, s * .12, **O)
            c.create_line(cx, cy + s * .2, cx, cy + s * .36, **L)
            c.create_line(cx - s * .22, cy + s * .38, cx + s * .22, cy + s * .38, **L)
        elif kind == "laptop":
            rrect(c, cx - s * .38, cy - s * .32, cx + s * .38, cy + s * .14, s * .08, **O)
            c.create_line(cx - h, cy + s * .3, cx + h, cy + s * .3, **L)
        elif kind == "key":
            r = s * .2
            c.create_oval(cx - s * .38, cy - s * .38, cx - s * .38 + 2 * r, cy - s * .38 + 2 * r, **O)
            c.create_line(cx - s * .1, cy - s * .1, cx + s * .38, cy + s * .38, **L)
            c.create_line(cx + s * .2, cy + s * .2, cx + s * .08, cy + s * .32, **L)
            c.create_line(cx + s * .3, cy + s * .3, cx + s * .2, cy + s * .4, **L)
        elif kind == "copy":
            rrect(c, cx - s * .16, cy - s * .38, cx + s * .36, cy + s * .2, s * .08, **O)
            rrect(c, cx - s * .36, cy - s * .18, cx + s * .16, cy + s * .4, s * .08, outline=col, width=lw, fill=bg)
        elif kind == "refresh":
            c.create_arc(cx - s * .36, cy - s * .36, cx + s * .36, cy + s * .36, start=60, extent=290,
                         style="arc", outline=col, width=lw)
            ax, ay = cx + s * .18, cy - s * .31
            c.create_polygon(ax - s * .02, ay - s * .16, ax + s * .2, ay + s * .02, ax - s * .06, ay + s * .12,
                             fill=col, outline=col)
        elif kind == "check":
            c.create_line(cx - s * .32, cy, cx - s * .08, cy + s * .24, cx + s * .34, cy - s * .24, **L)
        elif kind == "clipboard":
            rrect(c, cx - s * .32, cy - s * .32, cx + s * .32, cy + s * .42, s * .08, **O)
            rrect(c, cx - s * .14, cy - s * .44, cx + s * .14, cy - s * .24, s * .05, outline=col, width=lw, fill=bg)
        elif kind == "folder":
            c.create_polygon(cx - s * .42, cy - s * .3, cx - s * .1, cy - s * .3, cx, cy - s * .18,
                             cx + s * .42, cy - s * .18, cx + s * .42, cy + s * .34, cx - s * .42, cy + s * .34,
                             **O, joinstyle="round")
        elif kind == "layers":
            c.create_polygon(cx, cy - s * .42, cx + s * .44, cy - s * .2, cx, cy + s * .02, cx - s * .44, cy - s * .2,
                             **O, joinstyle="round")
            c.create_line(cx - s * .44, cy + s * .02, cx, cy + s * .24, cx + s * .44, cy + s * .02, **L)
            c.create_line(cx - s * .44, cy + s * .22, cx, cy + s * .44, cx + s * .44, cy + s * .22, **L)
        elif kind == "send":
            c.create_polygon(cx - s * .42, cy - s * .06, cx + s * .42, cy - s * .38, cx + s * .1, cy + s * .42,
                             cx - s * .04, cy + s * .06, **O, joinstyle="round")
            c.create_line(cx - s * .04, cy + s * .06, cx + s * .42, cy - s * .38, **L)
        elif kind == "wifi":
            for i, r in enumerate((s * .46, s * .3)):
                c.create_arc(cx - r, cy - r + s * .2, cx + r, cy + r + s * .2, start=45, extent=90,
                             style="arc", outline=col, width=lw)
            c.create_oval(cx - lw, cy + s * .2 - lw, cx + lw, cy + s * .2 + lw, fill=col, outline=col)
        elif kind == "help":
            c.create_oval(cx - h * .9, cy - h * .9, cx + h * .9, cy + h * .9, **O)
            c.create_text(cx, cy + s * .02, text="?", fill=col, font=F(s * .62 / scale["S"], "bold"))
        elif kind == "sun":
            r = s * .2
            c.create_oval(cx - r, cy - r, cx + r, cy + r, **O)
            import math
            for i in range(8):
                a = i * math.pi / 4
                c.create_line(cx + math.cos(a) * s * .32, cy + math.sin(a) * s * .32,
                              cx + math.cos(a) * s * .45, cy + math.sin(a) * s * .45, **L)
        elif kind == "moon":
            r = s * .38
            c.create_oval(cx - r, cy - r, cx + r, cy + r, fill=col, outline=col)
            c.create_oval(cx - r + s * .24, cy - r - s * .12, cx + r + s * .24, cy + r - s * .12, fill=bg, outline=bg)
        elif kind == "play":
            c.create_polygon(cx - s * .28, cy - s * .36, cx + s * .38, cy, cx - s * .28, cy + s * .36,
                             fill=col, outline=col, joinstyle="round", width=lw)
        elif kind == "stop":
            rrect(c, cx - s * .3, cy - s * .3, cx + s * .3, cy + s * .3, s * .08, fill=col, outline=col)
        elif kind in ("left", "right", "up", "down"):
            d = {"left": (h * .8, 0, -h * .8, 0), "right": (-h * .8, 0, h * .8, 0),
                 "up": (0, h * .8, 0, -h * .8), "down": (0, -h * .8, 0, h * .8)}[kind]
            c.create_line(cx + d[0], cy + d[1], cx + d[2], cy + d[3], arrow="last",
                          arrowshape=(s * .4, s * .4, s * .22), **L)
        elif kind in ("chev_right", "chev_down"):
            if kind == "chev_right":
                c.create_line(cx - s * .12, cy - s * .26, cx + s * .14, cy, cx - s * .12, cy + s * .26, **L)
            else:
                c.create_line(cx - s * .26, cy - s * .12, cx, cy + s * .14, cx + s * .26, cy - s * .12, **L)

    class Card(tk.Canvas):
        """Rounded card; put content in .body."""
        def __init__(self, parent, P, pad=18, highlight=False):
            super().__init__(parent, bg=P["bg"], highlightthickness=0, bd=0, height=px(60))
            self.P, self.pad, self.hl = P, px(pad), highlight
            self.body = tk.Frame(self, bg=P["card"])
            self.win = self.create_window(self.pad, self.pad, window=self.body, anchor="nw")
            self.bind("<Configure>", self._layout)
            self.body.bind("<Configure>", self._fit)

        def _layout(self, e):
            self.delete("bgr")
            col = self.P["accent"] if self.hl else self.P["border"]
            rrect(self, 1, 1, e.width - 2, e.height - 2, px(16), fill=self.P["card"], outline=col,
                  width=px(2) if self.hl else 1, tags="bgr")
            self.tag_lower("bgr")
            self.itemconfigure(self.win, width=max(1, e.width - 2 * self.pad))

        def _fit(self, e):
            hgt = self.body.winfo_reqheight() + 2 * self.pad
            if int(self.cget("height")) != hgt:
                self.configure(height=hgt)

    class Clickable(tk.Canvas):
        """A canvas button: draw(c, hover) paints it."""
        def __init__(self, parent, width, height, draw, command, bg):
            super().__init__(parent, width=width, height=height, bg=bg, highlightthickness=0, bd=0,
                             cursor="hand2")
            self.draw_fn, self.command, self.enabled, self.hover = draw, command, True, False
            self.bind("<Enter>", lambda e: self._set(True))
            self.bind("<Leave>", lambda e: self._set(False))
            self.bind("<ButtonRelease-1>", lambda e: self.enabled and self.command and self.command())
            self.redraw()

        def _set(self, hover):
            self.hover = hover
            self.redraw()

        def set_enabled(self, on):
            self.enabled = on
            self.configure(cursor="hand2" if on else "arrow")
            self.redraw()

        def redraw(self):
            self.delete("all")
            self.draw_fn(self, self.hover and self.enabled)

    def tile(parent, kind, P, size=44, bg=None):
        c = tk.Canvas(parent, width=px(size), height=px(size), bg=bg or P["card"], highlightthickness=0, bd=0)
        rrect(c, 0, 0, px(size), px(size), px(11), fill=P["tile"], outline="")
        icon(c, kind, px(size) / 2, px(size) / 2, px(size * .48), P["text"], P["tile"])
        return c

    def icon_button(parent, kind, P, command, size=40, bg=None):
        def draw(c, hover):
            fill = P["border"] if hover else P["tile"]
            rrect(c, 1, 1, px(size) - 1, px(size) - 1, px(10), fill=fill, outline=P["border"])
            col = P["text"] if c.enabled else P["grey"]
            icon(c, c.kind, px(size) / 2, px(size) / 2, px(size * .46), col, fill)
        b = Clickable.__new__(Clickable)
        b.kind = kind
        Clickable.__init__(b, parent, px(size), px(size), draw, command, bg or P["card"])
        return b

    def badge(parent, text, fg, bgc, P, kind=None):
        f = tkfont.Font(font=F(13, "bold"))
        iw = px(18) if kind else 0
        wd, ht = f.measure(text) + px(26) + iw, px(30)
        c = tk.Canvas(parent, width=wd, height=ht, bg=P["card"], highlightthickness=0, bd=0)
        rrect(c, 0, 0, wd, ht, ht / 2, fill=bgc, outline="")
        if kind:
            icon(c, kind, px(13) + iw / 2 - px(2), ht / 2, px(15), fg, bgc)
        c.create_text(px(13) + iw, ht / 2, text=text, fill=fg, font=f, anchor="w")
        return c

    def switch(parent, var, P, command):
        W_, H_ = px(46), px(26)

        def draw(c, hover):
            on = var.get()
            rrect(c, 0, 0, W_, H_, H_ / 2, fill=P["accent"] if on else P["switch_off"], outline="")
            x = W_ - H_ / 2 if on else H_ / 2
            r = H_ / 2 - px(3)
            c.create_oval(x - r, H_ / 2 - r, x + r, H_ / 2 + r, fill=P["knob"], outline="")

        def flip():
            var.set(not var.get())
            sw.redraw()
            command()
        sw = Clickable(parent, W_, H_, draw, flip, P["card"])
        return sw

    def label(parent, text, P, size=13, weight="normal", color="text", **kw):
        return tk.Label(parent, text=text, bg=kw.pop("bg", P["card"]), fg=P[color], font=F(size, weight),
                        anchor="w", justify="left", **kw)

    def field(parent, var, P, placeholder="", width=20, font=None):
        """Rounded text field with a placeholder."""
        hgt = px(42)
        c = tk.Canvas(parent, height=hgt, bg=P["card"], highlightthickness=0, bd=0)
        e = tk.Entry(c, textvariable=var, bg=P["field"], fg=P["text"], insertbackground=P["text"],
                     relief="flat", bd=0, highlightthickness=0, font=font or F(14), width=width,
                     disabledbackground=P["field"], disabledforeground=P["muted"],
                     readonlybackground=P["field"])
        ph = tk.Label(c, text=placeholder, bg=P["field"], fg=P["muted"], font=font or F(14), anchor="w")
        win = c.create_window(px(14), hgt / 2, window=e, anchor="w")
        phw = c.create_window(px(16), hgt / 2, window=ph, anchor="w")

        def layout(ev):
            c.delete("bgr")
            rrect(c, 1, 1, ev.width - 2, ev.height - 2, px(10), fill=P["field"], outline=P["border"], tags="bgr")
            c.tag_lower("bgr")
            c.itemconfigure(win, width=ev.width - px(28))

        def sync(*_):
            c.itemconfigure(phw, state="hidden" if (var.get() or c.focus_get() is e) else "normal")
        c.bind("<Configure>", layout)
        e.bind("<FocusIn>", sync)
        e.bind("<FocusOut>", sync)
        ph.bind("<Button-1>", lambda ev: e.focus_set())
        var.trace_add("write", sync)
        sync()
        c.entry = e
        return c

    # ---------------------------------------------------------------- actions
    def log(s):
        events.put(("log", time.strftime("%H:%M:%S  ") + s))

    def status(s):
        events.put(("status", s))

    def bridge_cfg(**kv):  # settings that apply instantly, even while sharing
        cfg.update(kv)
        save_config(cfg)
        if state["bridge"]:
            state["bridge"].cfg.update(kv)

    def get_code():
        return "".join(e.get() for e in w.get("code", [])) if w.get("code") else state["code"].replace("-", "")

    def set_code(text):
        chars = [ch for ch in text.upper() if ch in CODE_ALPHABET][:8]
        for i, e in enumerate(w["code"]):
            e.delete(0, "end")
            if i < len(chars):
                e.insert(0, chars[i])
        state["code"] = "".join(chars)

    def toggle():
        if state["bridge"]:
            state["bridge"].stop()
            state["bridge"] = None
            refresh_controls()
            return
        code = get_code()
        if len(code) != 8:
            messagebox.showwarning(APP, "Enter the full 8-character pairing code (the same on both computers).")
            return
        try:
            port = int(port_v.get())
        except ValueError:
            messagebox.showwarning(APP, "Port must be a number.")
            return
        state["code"] = code[:4] + "-" + code[4:]
        cfg.update({"peer": peer_v.get().strip(), "port": port, "password": state["code"],
                    "side": side_v.get(), "clipboard": clip_v.get(), "share_files": files_v.get()})
        save_config(cfg)
        b = Bridge(dict(cfg), log, status)
        b.start()
        state["bridge"] = b
        refresh_controls()

    def refresh_tray_menu():
        if state.get("tray"):
            try:
                state["tray"].update_menu()
            except Exception:
                pass

    def send_files_dialog():
        b = state["bridge"]
        if not files_v.get():
            messagebox.showinfo(APP, "Turn on “Share files” first.")
            return
        if not b or b.chan is None:
            messagebox.showinfo(APP, "Connect to the other computer first.")
            return
        paths = filedialog.askopenfilenames(parent=root, title=f"Send files to {b.peer_label}")
        if paths:
            b.send_files(paths, "send")

    def copy_code():
        code = get_code()
        root.clipboard_clear()
        root.clipboard_append(code[:4] + "-" + code[4:] if len(code) == 8 else code)
        btn = w["copy_btn"]
        btn.kind = "check"
        btn.redraw()
        root.after(1200, lambda: (setattr(btn, "kind", "copy"), btn.redraw()) if btn.winfo_exists() else None)

    def new_code():
        set_code(new_pairing_code())

    def set_side(side):
        side_v.set(side)
        bridge_cfg(side=side)
        for t in w["dir_tiles"]:
            t.redraw()
        w["arrange"].event_generate("<Configure>")

    def switch_theme():
        state["theme"] = "light" if state["theme"] == "dark" else "dark"
        cfg["theme"] = state["theme"]
        save_config(cfg)
        state["code"] = get_code()
        build()

    def show_help():
        messagebox.showinfo(f"{APP} help", (
            "1. Run Mousync on both computers.\n"
            "2. Type the same pairing code on both. They find each other on your network.\n"
            "3. Under Screen Arrangement, pick where the other computer sits.\n"
            "4. Click Start Sharing on both.\n\n"
            "Push the cursor off that edge to control the other computer; push it back to return. "
            "Either computer can control the other.\n\n"
            "Emergency return: press Esc three times quickly.\n"
            "Copy text or files on one computer and paste on the other.\n"
            "Closing the window keeps Mousync running in the "
            + ("menu bar." if IS_MAC else "system tray.")))

    def toggle_log():
        state["log_open"] = not state["log_open"]
        if state["log_open"]:
            w["log_card"].grid()
            w["log"].see("end")
        else:
            w["log_card"].grid_remove()
        w["log_btn"].redraw()

    # ---------------------------------------------------------------- layout
    def build():
        P = THEMES[state["theme"]]
        if w.get("main"):
            w["main"].destroy()
        w.clear()
        root.configure(bg=P["bg"])
        match_title_bar(root, state["theme"])
        main = tk.Frame(root, bg=P["bg"], padx=px(22), pady=px(16))
        main.pack(fill="both", expand=True)
        w["main"] = main
        gap = px(14)
        main.grid_columnconfigure(0, minsize=px(500), weight=1)
        main.grid_columnconfigure(1, minsize=px(430), weight=1)

        # header
        hdr = tk.Frame(main, bg=P["bg"])
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, px(10)))
        if app_icon is not None:
            k = max(1, round(app_icon.width() / px(30)))
            w["hdr_img"] = app_icon.subsample(k, k)
            tk.Label(hdr, image=w["hdr_img"], bg=P["bg"]).pack(side="left")
        tk.Label(hdr, text=APP, bg=P["bg"], fg=P["text"], font=F(20, "bold")).pack(side="left", padx=(px(10), px(6)))
        tk.Label(hdr, text=VERSION, bg=P["bg"], fg=P["muted"], font=F(17)).pack(side="left", pady=(px(2), 0))
        icon_button(hdr, "sun" if state["theme"] == "dark" else "moon", P, switch_theme, 38, P["bg"]).pack(
            side="right")
        icon_button(hdr, "help", P, show_help, 38, P["bg"]).pack(side="right", padx=(0, px(8)))

        # ---- left column
        left = tk.Frame(main, bg=P["bg"])
        left.grid(row=1, column=0, sticky="nsew", padx=(0, gap))
        tk.Label(left, text="Share your mouse & keyboard", bg=P["bg"], fg=P["text"], font=F(27, "bold"),
                 anchor="w").pack(fill="x")
        tk.Label(left, text="Control two computers as one.", bg=P["bg"], fg=P["muted"], font=F(15),
                 anchor="w").pack(fill="x", pady=(px(2), px(14)))

        # this computer
        c1 = Card(left, P)
        c1.pack(fill="x", pady=(0, gap))
        b = c1.body
        b.grid_columnconfigure(1, weight=1)
        tile(b, "laptop" if IS_MAC else "monitor", P, 48).grid(row=0, column=0, rowspan=2, padx=(0, px(14)))
        label(b, "This Computer", P, 16, "bold").grid(row=0, column=1, sticky="sw")
        label(b, f"{device_label(OSNAME, socket.gethostname())}   •   {local_ip()}", P, 13,
              color="muted").grid(row=1, column=1, sticky="nw")
        badge(b, "This Device", P["green"], P["green_bg"], P).grid(row=0, column=2, rowspan=2, sticky="e")

        # pairing code
        c2 = Card(left, P, highlight=True)
        c2.pack(fill="x", pady=(0, gap))
        b = c2.body
        b.grid_columnconfigure(1, weight=1)
        tile(b, "key", P, 48).grid(row=0, column=0, rowspan=2, padx=(0, px(14)), sticky="n")
        label(b, "Pairing Code", P, 16, "bold").grid(row=0, column=1, sticky="sw")
        label(b, "Type this same code on the other computer.", P, 13, color="muted").grid(row=1, column=1, sticky="nw")
        row = tk.Frame(b, bg=P["card"])
        row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(px(14), 0))
        boxes = []
        bw, bh = px(36), px(50)
        for i in range(8):
            if i == 4:
                tk.Label(row, text="–", bg=P["card"], fg=P["muted"], font=F(20, "bold")).pack(side="left", padx=px(3))
            cv = tk.Canvas(row, width=bw, height=bh, bg=P["card"], highlightthickness=0, bd=0)
            rrect(cv, 1, 1, bw - 1, bh - 1, px(9), fill=P["tile"], outline=P["border"])
            e = tk.Entry(cv, width=2, justify="center", bg=P["tile"], fg=P["text"], insertbackground=P["accent"],
                         relief="flat", bd=0, highlightthickness=0, font=F(22, "bold", mono),
                         readonlybackground=P["tile"], disabledbackground=P["tile"])
            cv.create_window(bw / 2, bh / 2, window=e, width=bw - px(8))
            cv.pack(side="left", padx=(0, px(5)))
            boxes.append(e)
        w["code"] = boxes

        def on_key(ev, i):
            e = boxes[i]
            if str(e.cget("state")) != "normal":
                return "break"
            k = ev.keysym
            if k in ("Tab", "ISO_Left_Tab"):
                return None
            if (ev.state & 0x4 or (IS_MAC and ev.state & 0x8)) and k.lower() == "v":
                return on_paste(None)
            if k == "BackSpace":
                if e.get():
                    e.delete(0, "end")
                elif i > 0:
                    boxes[i - 1].delete(0, "end")
                    boxes[i - 1].focus_set()
                return "break"
            if k == "Left" and i > 0:
                boxes[i - 1].focus_set()
            elif k == "Right" and i < 7:
                boxes[i + 1].focus_set()
            ch = (ev.char or "").upper()
            if ch and ch in CODE_ALPHABET:
                e.delete(0, "end")
                e.insert(0, ch)
                if i < 7:
                    boxes[i + 1].focus_set()
            return "break"

        def on_paste(_):
            try:
                text = root.clipboard_get()
            except tk.TclError:
                return "break"
            if str(boxes[0].cget("state")) == "normal":
                set_code(text)
            return "break"

        for i, e in enumerate(boxes):
            e.bind("<KeyPress>", lambda ev, i=i: on_key(ev, i))
            e.bind("<<Paste>>", on_paste)
            e.bind("<FocusIn>", lambda ev: ev.widget.select_range(0, "end"))
        set_code(state["code"])
        w["refresh_btn"] = icon_button(row, "refresh", P, new_code)
        w["refresh_btn"].pack(side="right")
        w["copy_btn"] = icon_button(row, "copy", P, copy_code)
        w["copy_btn"].pack(side="right", padx=(px(6), px(8)))

        # other computer
        c3 = Card(left, P)
        c3.pack(fill="x")
        b = c3.body
        b.grid_columnconfigure(1, weight=1)
        tile(b, "monitor", P, 48).grid(row=0, column=0, rowspan=2, padx=(0, px(14)), sticky="n")
        label(b, "Other Computer", P, 16, "bold").grid(row=0, column=1, sticky="sw")
        w["other_sub"] = label(b, "", P, 13, color="muted")
        w["other_sub"].grid(row=1, column=1, sticky="nw")
        w["badge_slot"] = tk.Frame(b, bg=P["card"])
        w["badge_slot"].grid(row=0, column=2, rowspan=2, sticky="e")
        frow = tk.Frame(b, bg=P["card"])
        frow.grid(row=2, column=0, columnspan=3, sticky="ew", pady=(px(14), 0))
        frow.grid_columnconfigure(0, weight=1)
        w["ip"] = field(frow, peer_v, P, "Other computer's IP (optional)")
        w["ip"].grid(row=0, column=0, sticky="ew")
        label(frow, "Port", P, 14).grid(row=0, column=1, padx=(px(14), px(10)))
        w["port"] = field(frow, port_v, P, "", 6)
        w["port"].configure(width=px(96))
        w["port"].grid(row=0, column=2)

        # ---- right column
        right = tk.Frame(main, bg=P["bg"])
        right.grid(row=1, column=1, sticky="nsew")
        c4 = Card(right, P)
        c4.pack(fill="x", pady=(0, gap))
        b = c4.body
        b.grid_columnconfigure(1, weight=1)
        hc = tk.Canvas(b, width=px(30), height=px(30), bg=P["card"], highlightthickness=0)
        icon(hc, "monitor", px(15), px(15), px(24), P["text"], P["card"])
        hc.grid(row=0, column=0, rowspan=2, sticky="n", padx=(0, px(12)), pady=(px(2), 0))
        label(b, "Screen Arrangement", P, 16, "bold").grid(row=0, column=1, sticky="w")
        label(b, "Where is the other computer relative to this one?", P, 13, color="muted").grid(
            row=1, column=1, sticky="w")
        arr = tk.Canvas(b, height=px(128), bg=P["card"], highlightthickness=0, bd=0)
        arr.grid(row=2, column=0, columnspan=2, sticky="ew", pady=px(8))
        w["arrange"] = arr

        def draw_arrangement(ev=None):
            arr.delete("all")
            W_, H_ = arr.winfo_width(), arr.winfo_height()
            side = side_v.get()
            vertical = side in ("top", "bottom")
            bw_, bh_ = (px(92), px(52)) if vertical else (px(104), px(66))
            gap_ = px(40) if not vertical else px(16)
            if vertical:
                tot = 2 * bh_ + gap_
                me = (W_ / 2 - bw_ / 2, (H_ - tot) / 2 + (bh_ + gap_ if side == "top" else 0))
                ot = (W_ / 2 - bw_ / 2, (H_ - tot) / 2 + (0 if side == "top" else bh_ + gap_))
            else:
                tot = 2 * bw_ + gap_
                y = (H_ - bh_) / 2 - px(8)
                me = ((W_ - tot) / 2 + (bw_ + gap_ if side == "left" else 0), y)
                ot = ((W_ - tot) / 2 + (0 if side == "left" else bw_ + gap_), y)
            br = state["bridge"]
            connected = br is not None and br.chan is not None
            for (x, y), mine in ((me, True), (ot, False)):
                kind = ("laptop" if IS_MAC else "monitor") if mine else (
                    "laptop" if connected and br.peer_os == "mac" else "monitor")
                rrect(arr, x, y, x + bw_, y + bh_, px(12), fill=P["accent_soft"] if mine else P["tile"],
                      outline=P["accent"] if mine else P["grey"], width=px(3) if mine else px(2))
                icon(arr, kind, x + bw_ / 2, y + bh_ / 2, px(30), P["text"], P["accent_soft"] if mine else P["tile"])
                if not vertical:
                    txt = "This computer" if mine else (br.peer_label if connected else "Other computer")
                    arr.create_text(x + bw_ / 2, y + bh_ + px(14), text=txt, fill=P["muted"], font=F(11),
                                    width=bw_ + gap_ - px(4))
            # dots between
            if vertical:
                cx_, cy_ = W_ / 2, min(me[1], ot[1]) + bh_ + gap_ / 2
                pts = [(cx_, cy_ - px(5)), (cx_, cy_), (cx_, cy_ + px(5))] if False else [(cx_ - px(8), cy_), (cx_, cy_), (cx_ + px(8), cy_)]
            else:
                cx_, cy_ = min(me[0], ot[0]) + bw_ + gap_ / 2, me[1] + bh_ / 2
                pts = [(cx_ - px(8), cy_), (cx_, cy_), (cx_ + px(8), cy_)]
            for (x, y) in pts:
                arr.create_oval(x - px(2.5), y - px(2.5), x + px(2.5), y + px(2.5), fill=P["accent"], outline="")
        arr.bind("<Configure>", draw_arrangement)

        drow = tk.Frame(b, bg=P["card"])
        drow.grid(row=3, column=0, columnspan=2, sticky="ew")
        w["dir_tiles"] = []
        for i, (sd, kind) in enumerate((("left", "left"), ("right", "right"), ("top", "up"), ("bottom", "down"))):
            drow.grid_columnconfigure(i, weight=1, uniform="d")

            def draw(c, hover, sd=sd, kind=kind):
                W_, H_ = c.winfo_width(), c.winfo_height()
                if W_ < 4:
                    W_ = int(c.cget("width"))
                sel = side_v.get() == sd
                fill = P["accent_soft"] if sel else (P["border"] if hover else P["tile"])
                rrect(c, 1, 1, W_ - 2, H_ - 2, px(11), fill=fill, outline=P["accent"] if sel else P["border"],
                      width=px(2) if sel else 1)
                icon(c, kind, W_ / 2, H_ * .36, px(18), P["text"], fill)
                c.create_text(W_ / 2, H_ * .72, text=sd.capitalize(), fill=P["text"], font=F(13))
            t = Clickable(drow, px(90), px(58), draw, lambda sd=sd: set_side(sd), P["card"])
            t.bind("<Configure>", lambda e, t=t: t.redraw(), add="+")
            t.grid(row=0, column=i, sticky="ew", padx=(0 if i == 0 else px(4), 0 if i == 3 else px(4)))
            w["dir_tiles"].append(t)

        # sharing
        c5 = Card(right, P)
        c5.pack(fill="x")
        b = c5.body
        b.grid_columnconfigure(1, weight=1)
        hc = tk.Canvas(b, width=px(30), height=px(30), bg=P["card"], highlightthickness=0)
        icon(hc, "layers", px(15), px(15), px(24), P["text"], P["card"])
        hc.grid(row=0, column=0, padx=(0, px(12)), sticky="w")
        label(b, "Sharing", P, 16, "bold").grid(row=0, column=1, sticky="w")

        def share_row(r, kind, title, sub, right_widget_fn, command=None):
            fr = tk.Frame(b, bg=P["card"])
            fr.grid(row=r, column=0, columnspan=2, sticky="ew", pady=(px(10), 0))
            fr.grid_columnconfigure(1, weight=1)
            tile(fr, kind, P, 44).grid(row=0, column=0, rowspan=2, padx=(0, px(12)))
            t1 = label(fr, title, P, 14, "bold")
            t1.grid(row=0, column=1, sticky="sw")
            t2 = label(fr, sub, P, 12, color="muted")
            t2.grid(row=1, column=1, sticky="nw")
            right_widget_fn(fr).grid(row=0, column=2, rowspan=2, sticky="e")
            if command:
                for wd in (fr, t1, t2):
                    wd.configure(cursor="hand2")
                    wd.bind("<ButtonRelease-1>", lambda e: command())
            return fr

        def sep(r):
            tk.Frame(b, bg=P["border"], height=1).grid(row=r, column=0, columnspan=2, sticky="ew", pady=(px(10), 0))

        share_row(1, "clipboard", "Share clipboard (text)", "Copy text on one computer, paste on the other",
                  lambda fr: switch(fr, clip_v, P, lambda: bridge_cfg(clipboard=clip_v.get())))
        sep(2)
        share_row(3, "folder", "Share files", "Copy files on one computer, paste on the other",
                  lambda fr: switch(fr, files_v, P, lambda: bridge_cfg(share_files=files_v.get())))
        sep(4)

        def chevron(fr):
            c = tk.Canvas(fr, width=px(26), height=px(26), bg=P["card"], highlightthickness=0, cursor="hand2")
            icon(c, "chev_right", px(13), px(13), px(18), P["muted"], P["card"])
            c.bind("<ButtonRelease-1>", lambda e: send_files_dialog())
            return c
        share_row(5, "send", "Send files…", "Into Downloads/Mousync on the other computer", chevron,
                  send_files_dialog)

        # ---- bottom bar
        bar = Card(main, P, pad=14)
        bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(gap, 0))
        b = bar.body
        b.grid_columnconfigure(3, weight=1)

        def draw_start(c, hover):
            W_, H_ = c.winfo_width(), c.winfo_height()
            if W_ < 4:
                W_ = int(c.cget("width"))
            on = state["bridge"] is not None
            fill = P["accent_hover"] if hover else P["accent"]
            rrect(c, 0, 0, W_, H_, px(12), fill=fill, outline="")
            txt = "Stop Sharing" if on else "Start Sharing"
            f = tkfont.Font(font=F(17, "bold"))
            tw = f.measure(txt) + px(30)
            x0 = (W_ - tw) / 2
            icon(c, "stop" if on else "play", x0 + px(9), H_ / 2, px(20), P["on_accent"], fill)
            c.create_text(x0 + px(30), H_ / 2, text=txt, fill=P["on_accent"], font=f, anchor="w")
        start = Clickable(b, px(430), px(54), draw_start, toggle, P["card"])
        start.bind("<Configure>", lambda e: start.redraw(), add="+")
        start.grid(row=0, column=0, sticky="w")
        w["start"] = start
        tk.Frame(b, bg=P["border"], width=1, height=px(40)).grid(row=0, column=1, padx=px(18))
        dot = tk.Canvas(b, width=px(14), height=px(14), bg=P["card"], highlightthickness=0)
        dot.grid(row=0, column=2, padx=(0, px(10)))
        w["dot"] = dot
        st = tk.Frame(b, bg=P["card"])
        st.grid(row=0, column=3, sticky="w")
        w["st_title"] = label(st, "", P, 15, "bold")
        w["st_title"].pack(anchor="w")
        w["st_sub"] = label(st, "", P, 12, color="muted")
        w["st_sub"].pack(anchor="w")

        def draw_log_btn(c, hover):
            col = P["text"] if hover else P["muted"]
            c.create_text(px(4), px(17), text="Activity", fill=col, font=F(13), anchor="w")
            icon(c, "chev_down" if state["log_open"] else "chev_right", px(84), px(17), px(16), col, P["card"])
        w["log_btn"] = Clickable(b, px(96), px(34), draw_log_btn, toggle_log, P["card"])
        w["log_btn"].grid(row=0, column=4, sticky="e")

        # activity log (hidden until opened)
        lc = Card(main, P, pad=12)
        lc.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(gap, 0))
        txt = tk.Text(lc.body, height=9, wrap="word", bg=P["card"], fg=P["muted"], font=F(12, fam=mono),
                      relief="flat", bd=0, highlightthickness=0, padx=px(4), pady=px(2),
                      insertbackground=P["text"])  # no scrollbar: the mouse wheel scrolls
        txt.pack(fill="both", expand=True)
        txt.insert("end", "\n".join(state["log_lines"]) + ("\n" if state["log_lines"] else ""))
        txt.configure(state="disabled")
        txt.see("end")
        w["log"], w["log_card"] = txt, lc
        if not state["log_open"]:
            lc.grid_remove()

        refresh_controls()
        show_status(state["status"])

    def refresh_controls():
        """Reflect running / stopped: lock fields that need a restart, update the button."""
        if not w:
            return
        running = state["bridge"] is not None
        for e in w["code"]:
            e.configure(state="readonly" if running else "normal")
        for f_ in (w["ip"], w["port"]):
            f_.entry.configure(state="readonly" if running else "normal")
        w["refresh_btn"].set_enabled(not running)
        w["start"].redraw()
        refresh_other()
        refresh_tray_menu()

    def refresh_other():
        P = THEMES[state["theme"]]
        br = state["bridge"]
        connected = br is not None and br.chan is not None
        manual = bool(peer_v.get().strip())
        if connected:
            w["other_sub"].configure(text=f"Connected:  {br.peer_label}")
        elif manual:
            w["other_sub"].configure(text="Connects straight to this IP.")
        else:
            w["other_sub"].configure(text="Found automatically on your network.")
        for ch in w["badge_slot"].winfo_children():
            ch.destroy()
        if manual:
            badge(w["badge_slot"], "Manual IP", P["blue"], P["blue_bg"], P).pack()
        else:
            badge(w["badge_slot"], "Auto Discovery", P["green"], P["green_bg"], P, "wifi").pack()
        w["arrange"].event_generate("<Configure>")

    def show_status(s):
        state["status"] = s
        if not w:
            return
        P = THEMES[state["theme"]]
        colour, title, sub = status_view(s)
        dot = w["dot"]
        dot.delete("all")
        dot.create_oval(px(1), px(1), px(13), px(13), fill=P[colour], outline="")
        w["st_title"].configure(text=title)
        w["st_sub"].configure(text=sub)
        refresh_other()

    peer_v.trace_add("write", lambda *_: w and refresh_other())

    def pump():
        while True:
            try:
                kind, s = events.get_nowait()
            except queue.Empty:
                break
            if kind == "call":
                s()
            elif kind == "status":
                show_status(s)
                if state.get("tray"):
                    state["tray"].title = f"{APP}: {s}"[:127]
            else:
                state["log_lines"] = (state["log_lines"] + [s])[-500:]
                if w.get("log"):
                    t = w["log"]
                    t.configure(state="normal")
                    t.insert("end", s + "\n")
                    t.see("end")
                    t.configure(state="disabled")
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
            where = "menu bar" if IS_MAC else "system tray"
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

    build()
    root.update_idletasks()
    room = root.winfo_screenheight() - px(90)          # leave space for taskbar / menu bar + title bar
    if root.winfo_reqheight() > room:
        scale["S"] = max(0.7, scale["S"] * room / root.winfo_reqheight())
        build()
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
    if IS_MAC:
        root.createcommand("tk::mac::ReopenApplication", show_window)  # click on the Dock icon
        root.createcommand("tk::mac::Quit", quit_app)                  # Cmd+Q / Dock > Quit
    pump()
    if cfg.get("password") and "--autostart" in sys.argv:
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
    args = p.parse_args()
    if args.nogui:
        run_cli(args)
    else:
        run_gui()


if __name__ == "__main__":
    main()
