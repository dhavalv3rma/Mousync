# MouseBridge: share one mouse & keyboard between two PCs

A small ShareMouse-style app for your local network.

## Features
- Move the cursor off the screen edge that faces the other PC, and your mouse and keyboard now control that PC.
- Move it back off the opposite edge to return.
- Text clipboard follows the cursor (copy on one PC, paste on the other).
- Mouse buttons (left, right, middle, back and forward), scroll wheel, and the full keyboard, including shortcuts like Ctrl+C or Alt+Tab.
- Both directions: either Windows PC can control the other.
- **Finds the other PC automatically**: type the same pairing code on both PCs and they connect. No IP address needed.
- AES-256-GCM encryption keyed from the pairing code. A PC with a different code is ignored.
- Reconnects automatically, and sends a heartbeat every 2 s. If the link drops, control returns to your PC.
- **Runs in the background**: closing the window hides it to the system tray (Windows) or the menu bar (Mac). Use the tray icon to show the window, start or stop sharing, or quit. When started with Windows, it goes straight to the tray.
- **Scroll Lock = emergency button**: control comes straight back to your PC.
- Multi-monitor support (it uses the edge of the whole desktop) and correct handling of DPI scaling.

## Setup (2 minutes)
1. Install Python 3.9+ from python.org on both PCs. Tick "Add Python to PATH".
2. Copy this folder to both PCs and double-click `run_windows.bat`.
3. **PC 1**: the window shows a pairing code (for example `K7MQ-2PXH`). Choose the side the other PC sits on and click **Start**.
4. **PC 2**: type the same code (case, spaces and dashes don't matter), choose the side PC 1 sits on, and click **Start**.
5. When Windows Firewall asks, click **Allow** on both PCs (TCP 24850 and UDP 24851, private network). The two PCs find each other within a second or two.

**If they don't find each other** (some routers block broadcast between Wi-Fi and wired, or "client isolation" is on), type the other PC's IP into *Other PC's IP* on one PC. That PC then connects directly. Also check that Windows lists the network as **Private**, not Public.

Want a single `.exe` with no Python? Run `build_exe.bat` once, then copy `dist\MouseBridge.exe` to both PCs.

Terminal mode: `python mousebridge.py --nogui --code K7MQ-2PXH --side right [--peer 192.168.1.20]` (omit `--code` to have one generated)

## Notes
- **How auto-connect works:** each PC broadcasts a small beacon on UDP 24851 every second. The beacon has an HMAC proof made from the pairing code, never the code itself. A PC that sees a beacon with a matching proof connects to it.
- **Admin windows:** to control windows running as administrator (Task Manager, installers), run MouseBridge as administrator. Windows blocks input into elevated apps otherwise.
- **Ctrl+Alt+Del** can't be forwarded. Windows reserves it.
- **macOS/Linux:** these can be *controlled* by a Windows PC. On macOS, allow the app under System Settings → Privacy & Security → Accessibility (and Input Monitoring). Controlling from a Mac is not built yet.
- **Mac keyboard mapping:** the Windows key acts as Cmd on a Mac.
- **While controlling:** the local cursor sits parked in the middle of your screen.
- Settings are saved to `~/.mousebridge.json`.

## Building the installers (MouseBridge-Setup.exe + MouseBridge.dmg)
GitHub Actions builds both installers for you, on GitHub's Windows and Mac machines:

```sh
cd mousebridge
git init && git add . && git commit -m "MouseBridge 1.0"
gh repo create mousebridge --private --source . --push
git tag v1.0 && git push origin v1.0
```
After about 5 minutes, both files appear under the repo's **Releases** page. You can also start a build by hand from **Actions → Build installers → Run workflow**; the files then appear under that run's *Artifacts*.

- **Windows installer:** installs to Program Files and adds Start-menu and desktop shortcuts. It can optionally start MouseBridge with Windows, and it opens firewall ports TCP 24850 and UDP 24851 (discovery) for private networks. Uninstalling removes everything, including the firewall rule.
- **Mac DMG:** drag MouseBridge to Applications. The app is unsigned, so the first time, right-click it and choose **Open**. Then allow it under System Settings → Privacy & Security → **Accessibility** and **Input Monitoring**. This build is for Apple Silicon (M1/M2/M3/M4) Macs.
- **Windows SmartScreen** may say "Windows protected your PC" because the exe is unsigned. Click **More info → Run anyway**.
