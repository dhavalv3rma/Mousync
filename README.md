# MouseBridge: share one mouse & keyboard between two PCs

A small ShareMouse-style app for your local network.

## Features
- Move the cursor off the screen edge that faces the other PC, and your mouse and keyboard now control that PC.
- Move it back off the opposite edge to return.
- Text clipboard follows the cursor (copy on one PC, paste on the other).
- Mouse buttons (left, right, middle, back and forward), scroll wheel, and the full keyboard, including shortcuts like Ctrl+C or Alt+Tab.
- Both directions: either Windows PC can control the other.
- AES-256-GCM encryption with a shared password. A wrong password is rejected.
- Reconnects automatically, and sends a heartbeat every 2 s. If the link drops, control returns to your PC.
- **Scroll Lock = emergency button**: control comes straight back to your PC.
- Multi-monitor support (it uses the edge of the whole desktop) and correct handling of DPI scaling.

## Setup (2 minutes)
1. Install Python 3.9+ from python.org on both PCs. Tick "Add Python to PATH".
2. Copy this folder to both PCs and double-click `run_windows.bat`.
3. **PC 1** (for example, the desktop): leave *Other PC's IP* blank. Set a password and choose the side the laptop sits on. Click **Start**. The window shows its IP.
4. **PC 2**: enter PC 1's IP, the same password, and the side PC 1 sits on. Click **Start**.
5. When Windows Firewall asks, click **Allow** on both PCs (TCP port 24850, private network).

Want a single `.exe` with no Python? Run `build_exe.bat` once, then copy `dist\MouseBridge.exe` to both PCs.

Terminal mode: `python mousebridge.py --nogui --password secret --side right [--peer 192.168.1.20]`

## Notes
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

- **Windows installer:** installs to Program Files and adds Start-menu and desktop shortcuts. It can optionally start MouseBridge with Windows, and it opens firewall port 24850 for private networks. Uninstalling removes everything, including the firewall rule.
- **Mac DMG:** drag MouseBridge to Applications. The app is unsigned, so the first time, right-click it and choose **Open**. Then allow it under System Settings → Privacy & Security → **Accessibility** and **Input Monitoring**. This build is for Apple Silicon (M1/M2/M3/M4) Macs.
- **Windows SmartScreen** may say "Windows protected your PC" because the exe is unsigned. Click **More info → Run anyway**.
