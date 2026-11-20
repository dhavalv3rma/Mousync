# Mousync: share one mouse & keyboard between two PCs

A small ShareMouse-style app for your local network.

## Features
- Move the cursor off the screen edge that faces the other PC, and your mouse and keyboard now control that PC.
- Move it back off the opposite edge to return.
- **Shared clipboard, both ways**: copy text on either PC and paste it on the other, straight away.
- **File sharing**: copy files or folders in Explorer/Finder on one PC, then paste them in a folder on the other (Ctrl+V / Cmd+V). Or click **Send files...** (also in the tray menu) to drop files into `Downloads/Mousync` on the other PC.
- Mouse buttons (left, right, middle, back and forward), scroll wheel, and the full keyboard, including shortcuts like Ctrl+C or Alt+Tab.
- **Both directions**: Windows and Mac PCs can each control the other. Push off the edge on whichever PC you're using and you're on the other one. No setup needed.
- **Finds the other PC automatically**: type the same pairing code on both PCs and they connect. No IP address needed.
- AES-256-GCM encryption keyed from the pairing code. A PC with a different code is ignored.
- Reconnects automatically, and sends a heartbeat every 2 s. If the link drops, control returns to your PC.
- **Runs in the background**: closing the window hides it to the system tray (Windows) or the menu bar (Mac). Use the tray icon to show the window, start or stop sharing, or quit. When started with Windows, it goes straight to the tray.
- **Emergency return**: press **Esc three times** quickly (or Scroll Lock on Windows) and control comes straight back to your PC.
- **Same look on Windows and Mac**, with a **dark/light switch** (sun/moon button, top right). The other computer is shown as `OS (name)`, for example `macOS (XD.local)`.
- The activity log is tucked away: click **Activity** next to the status to show or hide it.
- Multi-monitor support (it uses the edge of the whole desktop) and correct handling of DPI scaling.

## Setup (2 minutes)
1. Install Python 3.9+ from python.org on both PCs. Tick "Add Python to PATH".
2. Copy this folder to both PCs and double-click `run_windows.bat`.
3. **PC 1**: the window shows a pairing code (for example `K7MQ-2PXH`). Choose the side the other PC sits on and click **Start**.
4. **PC 2**: type the same code (case, spaces and dashes don't matter), choose the side PC 1 sits on, and click **Start**.
5. When Windows Firewall asks, click **Allow** on both PCs (TCP 24850 and UDP 24851, private network). The two PCs find each other within a second or two.

**If they don't find each other** (some routers block broadcast between Wi-Fi and wired, or "client isolation" is on), type the other PC's IP into *Other PC's IP* on one PC. That PC then connects directly. Also check that Windows lists the network as **Private**, not Public.

Want a single `.exe` with no Python? Run `build_exe.bat` once, then copy `dist\Mousync.exe` to both PCs. Or download **Mousync-Windows-Portable** from any GitHub Actions run (every push to `main` builds one): it's a single `Mousync-Portable.exe` you just double-click, no install.

Terminal mode: `python mousync.py --nogui --code K7MQ-2PXH --side right [--peer 192.168.1.20]` (omit `--code` to have one generated)

## Notes
- **How auto-connect works:** each PC broadcasts a small beacon on UDP 24851 every second. The beacon has an HMAC proof made from the pairing code, never the code itself. A PC that sees a beacon with a matching proof connects to it.
- **Admin windows:** to control windows running as administrator (Task Manager, installers), run Mousync as administrator. Windows blocks input into elevated apps otherwise.
- **Ctrl+Alt+Del** can't be forwarded. Windows reserves it.
- **macOS:** allow Mousync under System Settings → Privacy & Security → **Accessibility** and **Input Monitoring**, then restart it. Without these it can't control or be controlled.
- **Linux:** can be controlled, but can't control the other PC.
- **Mac ↔ Windows keys:** Cmd and Ctrl swap places, so the usual shortcuts just work. Cmd+C on a Mac keyboard is Ctrl+C on Windows, and Ctrl+C on a Windows keyboard is Cmd+C on a Mac. Option = Alt.
- **While controlling:** on a Mac, the local cursor stays frozen at the edge where it crossed; on Windows it's parked in the middle of the screen.
- **Clipboard:** text and files. Images copied from apps (screenshots, "Copy image") are not shared yet.
- **How file sharing works, and its limits:**
  - Copied files are sent **as soon as you copy**, before you paste, so they're ready when you do. That uses network bandwidth even if you never paste. Copies over **2 GB** are not sent automatically (set `"file_limit_mb"` in `~/.mousync.json` to change this); use **Send files...** for those.
  - Paste only works **once the transfer has finished**. Watch the status line ("Receiving...: 45%"). Pasting earlier pastes whatever was on that PC's clipboard before.
  - Copying something new cancels a transfer that hasn't finished.
  - Copied files are kept in a temporary folder on the receiving PC, and only the last 3 copies are kept. If you paste later than that, the files are gone; use **Send files...** for anything you want to keep. Files sent with **Send files...** stay in `Downloads/Mousync` and are never overwritten (a second `report.pdf` becomes `report (2).pdf`).
  - Files go over the same encrypted link as the mouse and keyboard. Mouse and keyboard messages always go first, and the transfer slows down while you're controlling, but a big transfer **in the same direction** you're controlling can still make the pointer feel a little sluggish on Wi-Fi.
  - No drag-and-drop between screens.
  - Speed is whatever your network gives (wired gigabit: about 100 MB/s; Wi-Fi: often 10 to 50 MB/s).
  - File dates and permissions aren't kept (received files get the current time), and Mac-only extras (tags, resource forks) are dropped. Names Windows can't use (like `a:b.txt`) are renamed (`a_b.txt`).
- Settings are saved to `~/.mousync.json`.

## Building the installers (Mousync-Setup.exe + Mousync.dmg)
GitHub Actions builds both installers for you, on GitHub's Windows and Mac machines:

```sh
cd mousync
git init && git add . && git commit -m "Mousync 1.0"
gh repo create mousync --private --source . --push
git tag v1.0 && git push origin v1.0
```
After about 5 minutes, both files appear under the repo's **Releases** page. You can also start a build by hand from **Actions → Build installers → Run workflow**; the files then appear under that run's *Artifacts*.

- **Windows installer:** installs to Program Files and adds Start-menu and desktop shortcuts. It can optionally start Mousync with Windows, and it opens firewall ports TCP 24850 and UDP 24851 (discovery) for private networks. Uninstalling removes everything, including the firewall rule.
- **Mac DMG:** drag Mousync to Applications. The app is unsigned, so the first time, right-click it and choose **Open**. Then allow it under System Settings → Privacy & Security → **Accessibility** and **Input Monitoring**. This build is for Apple Silicon (M1/M2/M3/M4) Macs.
- **Windows SmartScreen** may say "Windows protected your PC" because the exe is unsigned. Click **More info → Run anyway**.
