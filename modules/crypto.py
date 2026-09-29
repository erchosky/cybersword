"""
CyberSword - Cryptography & Analysis Module
AES-256, hashing, encoding, hash ID, steganography detection, password analysis.
"""

import re
import math
import base64
import hashlib
import hmac
import secrets
import string
from pathlib import Path

from rich.console import Console

try:
    # These imports come from maintained PyCryptodome, not obsolete PyCrypto.
    from Crypto.Cipher import AES  # nosec B413
    from Crypto.Util.Padding import pad, unpad  # nosec B413
    from Crypto.Random import get_random_bytes  # nosec B413
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    from PIL import Image
    import numpy as np
    STEG_AVAILABLE = True
except ImportError:
    STEG_AVAILABLE = False

from utils.output import (
    print_section, print_result_table, print_error,
    print_warning, print_success
)

console = Console()

HASH_SIGNATURES = {
    32: [("MD5", r"^[a-f0-9]{32}$"), ("NTLM", r"^[A-F0-9]{32}$")],
    40: [("SHA1", r"^[a-f0-9]{40}$"), ("SHA1-crypt", r"^\{SHA\}")],
    56: [("SHA224", r"^[a-f0-9]{56}$")],
    64: [("SHA256", r"^[a-f0-9]{64}$"), ("Blake2-256", r"^[a-f0-9]{64}$")],
    96: [("SHA384", r"^[a-f0-9]{96}$")],
    128: [("SHA512", r"^[a-f0-9]{128}$"), ("Whirlpool", r"^[a-f0-9]{128}$")],
    60: [("Bcrypt", r"^\$2[ayb]\$.{56}$")],
}

SPECIAL_HASH_PATTERNS = [
    (r"^\$2[ayb]\$\d{2}\$.{53}$", "Bcrypt"),
    (r"^\$argon2", "Argon2"),
    (r"^\$scrypt\$", "scrypt"),
    (r"^\$pbkdf2", "PBKDF2"),
    (r"^\$1\$", "MD5-crypt"),
    (r"^\$5\$", "SHA256-crypt"),
    (r"^\$6\$", "SHA512-crypt"),
    (r"^[a-zA-Z0-9./]{13}$", "DES-crypt"),
    (r"^\{SHA\}[A-Za-z0-9+/=]{28}$", "SHA1-Base64"),
    (r"^\{SSHA\}", "SSHA"),
]


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

def hash_text(text: str) -> dict:
    """Hash text with multiple algorithms."""
    data = text.encode("utf-8")
    result = {
        "input": text,
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha224": hashlib.sha224(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha384": hashlib.sha384(data).hexdigest(),
        "sha512": hashlib.sha512(data).hexdigest(),
        "blake2b": hashlib.blake2b(data).hexdigest(),
        "blake2s": hashlib.blake2s(data).hexdigest(),
    }
    return result


def hash_file(file_path: str) -> dict:
    """Hash a file with multiple algorithms."""
    p = Path(file_path)
    if not p.exists():
        print_error(f"File not found: {file_path}")
        return {}

    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    sha512 = hashlib.sha512()

    size = 0
    with open(p, "rb") as f:
        while chunk := f.read(65536):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            sha512.update(chunk)

    return {
        "file": str(p),
        "size": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
        "sha512": sha512.hexdigest(),
    }


def identify_hash(hash_str: str) -> list:
    """Identify the type of a hash string."""
    h = hash_str.strip()
    candidates = []

    # Check special patterns first
    for pattern, name in SPECIAL_HASH_PATTERNS:
        if re.match(pattern, h):
            candidates.append(name)

    # Check by length
    length_candidates = HASH_SIGNATURES.get(len(h), [])
    for name, pattern in length_candidates:
        if re.match(pattern, h, re.IGNORECASE):
            if name not in candidates:
                candidates.append(name)

    return candidates if candidates else ["Unknown"]


# ---------------------------------------------------------------------------
# AES Encryption
# ---------------------------------------------------------------------------

def aes_encrypt(data: str, password: str, mode: str = "GCM") -> dict:
    """Encrypt text using AES-256 in GCM or CBC mode."""
    if not CRYPTO_AVAILABLE:
        return {"error": "pycryptodome not available — pip install pycryptodome"}

    if not password:
        return {"error": "Password must not be empty"}

    salt = get_random_bytes(16)
    key_material = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, 600_000, dklen=64
    )
    encryption_key, mac_key = key_material[:32], key_material[32:]

    try:
        if mode.upper() == "GCM":
            cipher = AES.new(encryption_key, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(data.encode("utf-8"))
            envelope = b"CS2G" + salt + cipher.nonce + tag + ciphertext
            result = {
                "mode": "AES-256-GCM-PBKDF2",
                "version": 2,
                "salt": base64.b64encode(salt).decode(),
                "nonce": base64.b64encode(cipher.nonce).decode(),
                "tag": base64.b64encode(tag).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "combined": base64.b64encode(envelope).decode(),
            }
        elif mode.upper() == "CBC":
            iv = get_random_bytes(16)
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            padded = pad(data.encode("utf-8"), AES.block_size)
            ciphertext = cipher.encrypt(padded)
            envelope = b"CS2C" + salt + iv + ciphertext
            auth_tag = hmac.new(mac_key, envelope, hashlib.sha256).digest()
            result = {
                "mode": "AES-256-CBC-PBKDF2-HMAC",
                "version": 2,
                "salt": base64.b64encode(salt).decode(),
                "iv": base64.b64encode(iv).decode(),
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "combined": base64.b64encode(envelope + auth_tag).decode(),
            }
        else:
            return {"error": f"Unknown mode: {mode}. Use GCM or CBC"}
        return result
    except Exception as e:
        return {"error": str(e)}


def aes_decrypt(combined_b64: str, password: str, mode: str = "GCM") -> dict:
    """Decrypt AES-256 encrypted data."""
    if not CRYPTO_AVAILABLE:
        return {"error": "pycryptodome not available"}

    try:
        combined = base64.b64decode(combined_b64, validate=True)

        if combined.startswith((b"CS2G", b"CS2C")):
            envelope_mode = combined[3:4]
            salt = combined[4:20]
            key_material = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, 600_000, dklen=64
            )
            encryption_key, mac_key = key_material[:32], key_material[32:]

            if envelope_mode == b"G":
                nonce = combined[20:36]
                tag = combined[36:52]
                ciphertext = combined[52:]
                cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=nonce)
                plaintext = cipher.decrypt_and_verify(ciphertext, tag)
                return {"mode": "AES-256-GCM-PBKDF2", "version": 2,
                        "plaintext": plaintext.decode("utf-8")}

            if len(combined) < 84:
                return {"error": "Decryption failed: invalid CBC envelope"}
            envelope, auth_tag = combined[:-32], combined[-32:]
            expected_tag = hmac.new(mac_key, envelope, hashlib.sha256).digest()
            if not hmac.compare_digest(auth_tag, expected_tag):
                return {"error": "Decryption failed: authentication check failed"}
            iv = combined[20:36]
            ciphertext = combined[36:-32]
            cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return {"mode": "AES-256-CBC-PBKDF2-HMAC", "version": 2,
                    "plaintext": plaintext.decode("utf-8")}

        # Backward compatibility with CyberSword v1 envelopes.
        key = hashlib.sha256(password.encode()).digest()

        if mode.upper() == "GCM":
            nonce = combined[:16]
            tag = combined[16:32]
            ciphertext = combined[32:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return {"mode": "AES-256-GCM", "plaintext": plaintext.decode("utf-8")}

        elif mode.upper() == "CBC":
            iv = combined[:16]
            ciphertext = combined[16:]
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded = cipher.decrypt(ciphertext)
            plaintext = unpad(padded, AES.block_size)
            return {"mode": "AES-256-CBC", "plaintext": plaintext.decode("utf-8")}

        else:
            return {"error": f"Unknown mode: {mode}"}
    except Exception as e:
        return {"error": f"Decryption failed: {e}"}


# ---------------------------------------------------------------------------
# Encoding / Decoding
# ---------------------------------------------------------------------------

def encode_decode(text: str, operation: str) -> dict:
    """Encode or decode using various schemes."""
    from urllib.parse import quote, unquote

    ops = {
        "base64_encode": lambda t: base64.b64encode(t.encode()).decode(),
        "base64_decode": lambda t: base64.b64decode(t).decode("utf-8", errors="replace"),
        "base32_encode": lambda t: base64.b32encode(t.encode()).decode(),
        "base32_decode": lambda t: base64.b32decode(t.upper()).decode("utf-8", errors="replace"),
        "hex_encode": lambda t: t.encode().hex(),
        "hex_decode": lambda t: bytes.fromhex(t).decode("utf-8", errors="replace"),
        "rot13": lambda t: t.translate(
            str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
            )
        ),
        "url_encode": lambda t: quote(t),
        "url_decode": lambda t: unquote(t),
        "html_encode": lambda t: t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                                  .replace('"', "&quot;").replace("'", "&#39;"),
        "html_decode": lambda t: t.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
                                  .replace("&quot;", '"').replace("&#39;", "'"),
        "binary_encode": lambda t: " ".join(format(ord(c), "08b") for c in t),
        "binary_decode": lambda t: "".join(chr(int(b, 2)) for b in t.split()),
        "morse_encode": lambda t: _to_morse(t),
        "morse_decode": lambda t: _from_morse(t),
    }

    op = operation.lower().replace(" ", "_")
    if op not in ops:
        return {"error": f"Unknown operation: {operation}", "available": list(ops.keys())}

    try:
        result_text = ops[op](text)
        return {
            "operation": operation,
            "input": text,
            "output": result_text,
        }
    except Exception as e:
        return {"error": str(e), "operation": operation}


def auto_decode(text: str) -> dict:
    """Try to auto-detect and decode encoded text."""
    results = []

    # Base64
    try:
        if re.match(r"^[A-Za-z0-9+/=]+$", text.strip()) and len(text) % 4 == 0:
            decoded = base64.b64decode(text).decode("utf-8")
            results.append({"encoding": "Base64", "decoded": decoded})
    except Exception:
        pass

    # Hex
    try:
        clean = text.replace(" ", "").replace("0x", "")
        if re.match(r"^[0-9a-fA-F]+$", clean) and len(clean) % 2 == 0:
            decoded = bytes.fromhex(clean).decode("utf-8", errors="replace")
            results.append({"encoding": "Hex", "decoded": decoded})
    except Exception:
        pass

    # URL encoded
    from urllib.parse import unquote
    if "%" in text:
        decoded = unquote(text)
        if decoded != text:
            results.append({"encoding": "URL", "decoded": decoded})

    # ROT13
    rot = text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
    ))
    if rot != text and any(c.isalpha() for c in rot):
        results.append({"encoding": "ROT13", "decoded": rot})

    return {"input": text, "candidates": results}


# ---------------------------------------------------------------------------
# Password Analysis
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> dict:
    """Analyze password strength and entropy."""
    result = {
        "password": "*" * len(password),
        "length": len(password),
        "entropy_bits": 0.0,
        "score": 0,
        "feedback": [],
        "checks": {},
    }

    checks = result["checks"]
    checks["has_lower"] = bool(re.search(r"[a-z]", password))
    checks["has_upper"] = bool(re.search(r"[A-Z]", password))
    checks["has_digit"] = bool(re.search(r"\d", password))
    checks["has_special"] = bool(re.search(r"[^a-zA-Z0-9]", password))
    checks["no_spaces"] = " " not in password
    checks["length_ok"] = len(password) >= 12
    checks["length_good"] = len(password) >= 16
    checks["length_excellent"] = len(password) >= 20

    # Charset size for entropy
    charset = 0
    if checks["has_lower"]:
        charset += 26
    if checks["has_upper"]:
        charset += 26
    if checks["has_digit"]:
        charset += 10
    if checks["has_special"]:
        charset += 32

    if charset > 0 and len(password) > 0:
        result["entropy_bits"] = round(len(password) * math.log2(charset), 1)

    # Common patterns
    checks["no_common_patterns"] = not bool(re.search(
        r"(password|123456|qwerty|abc123|admin|letmein|monkey|dragon|master|login)",
        password.lower()
    ))
    checks["no_repeating"] = not bool(re.search(r"(.)\1{3,}", password))
    checks["no_sequential"] = not bool(re.search(
        r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg)", password.lower()
    ))

    # Score
    score = 0
    if len(password) >= 8:
        score += 10
    if len(password) >= 12:
        score += 10
    if len(password) >= 16:
        score += 10
    if len(password) >= 20:
        score += 10
    if checks["has_lower"]:
        score += 10
    if checks["has_upper"]:
        score += 10
    if checks["has_digit"]:
        score += 10
    if checks["has_special"]:
        score += 15
    if checks["no_common_patterns"]:
        score += 10
    if checks["no_repeating"]:
        score += 5
    if checks["no_sequential"]:
        score += 5
    if result["entropy_bits"] >= 60:
        score += 5

    result["score"] = min(score, 100)

    # Strength label
    if result["entropy_bits"] >= 80:
        result["strength"] = "VERY STRONG"
        result["strength_color"] = "green"
    elif result["entropy_bits"] >= 60:
        result["strength"] = "STRONG"
        result["strength_color"] = "green"
    elif result["entropy_bits"] >= 40:
        result["strength"] = "MODERATE"
        result["strength_color"] = "yellow"
    elif result["entropy_bits"] >= 28:
        result["strength"] = "WEAK"
        result["strength_color"] = "red"
    else:
        result["strength"] = "VERY WEAK"
        result["strength_color"] = "red"

    # Time to crack (approximate)
    result["crack_time"] = _estimate_crack_time(result["entropy_bits"])

    # Feedback
    if not checks["has_lower"]:
        result["feedback"].append("Add lowercase letters")
    if not checks["has_upper"]:
        result["feedback"].append("Add uppercase letters")
    if not checks["has_digit"]:
        result["feedback"].append("Add numbers")
    if not checks["has_special"]:
        result["feedback"].append("Add special characters (!@#$...)")
    if len(password) < 12:
        result["feedback"].append("Use at least 12 characters")
    if not checks["no_common_patterns"]:
        result["feedback"].append("Avoid common words and patterns")
    if not checks["no_repeating"]:
        result["feedback"].append("Avoid repeating characters")
    if not checks["no_sequential"]:
        result["feedback"].append("Avoid sequential characters (1234, abcd)")

    return result


def generate_password(length: int = 20, use_special: bool = True,
                      use_upper: bool = True, use_digits: bool = True,
                      exclude_ambiguous: bool = False) -> dict:
    """Generate a cryptographically secure password (mínimo 8 caracteres)."""
    length = max(8, min(int(length), 256))
    chars = string.ascii_lowercase
    if use_upper:
        chars += string.ascii_uppercase
    if use_digits:
        chars += string.digits
    if use_special:
        chars += "!@#$%^&*()-_=+[]{}|;:,.<>?"

    if exclude_ambiguous:
        chars = chars.translate(str.maketrans("", "", "Il1O0oB8"))

    if not chars:
        chars = string.ascii_lowercase + string.digits

    password = "".join(secrets.choice(chars) for _ in range(length))
    analysis = analyze_password(password)

    return {
        "password": password,
        "length": length,
        "entropy_bits": analysis["entropy_bits"],
        "strength": analysis["strength"],
    }


# ---------------------------------------------------------------------------
# Hex Viewer
# ---------------------------------------------------------------------------

def hex_view(file_path: str, offset: int = 0, length: int = 512) -> dict:
    """Display file in hex format with string extraction."""
    p = Path(file_path)
    if not p.exists():
        print_error(f"File not found: {file_path}")
        return {}

    with open(p, "rb") as f:
        f.seek(offset)
        data = f.read(length)

    # Hex dump
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{offset + i:08x}  {hex_part:<47}  |{ascii_part}|")

    # Strings
    strings = re.findall(rb"[ -~]{6,}", data)
    extracted_strings = [s.decode("ascii", errors="replace") for s in strings[:30]]

    # Check for IOCs
    iocs = {
        "urls": re.findall(rb"https?://[^\x00-\x1f\x7f-\xff]{8,}", data),
        "ips": re.findall(rb"\b(?:\d{1,3}\.){3}\d{1,3}\b", data),
        "emails": re.findall(rb"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", data),
    }
    for key in iocs:
        iocs[key] = [x.decode("ascii", errors="replace") for x in iocs[key]]

    return {
        "file": str(p),
        "offset": offset,
        "length": len(data),
        "hex_dump": "\n".join(lines),
        "strings": extracted_strings,
        "iocs": iocs,
    }


# ---------------------------------------------------------------------------
# Steganography Detection
# ---------------------------------------------------------------------------

def detect_steganography(image_path: str) -> dict:
    """Basic steganography detection in images."""
    result = {"file": image_path, "suspicious": False, "indicators": []}

    p = Path(image_path)
    if not p.exists():
        print_error(f"File not found: {image_path}")
        return result

    if not STEG_AVAILABLE:
        result["error"] = "Pillow/numpy not available for steg analysis"
        return result

    try:
        img = Image.open(p).convert("RGB")
        arr = np.array(img)

        # LSB analysis — check least significant bit distribution
        lsb_r = arr[:, :, 0] & 1
        lsb_g = arr[:, :, 1] & 1
        lsb_b = arr[:, :, 2] & 1

        for channel, name in [(lsb_r, "Red"), (lsb_g, "Green"), (lsb_b, "Blue")]:
            ratio = channel.sum() / channel.size
            # Natural images: LSB ratio ~0.5 but with spatial correlation
            # Steganography: ratio very close to 0.5 with low variance
            variance = float(np.var(channel.astype(float)))
            if abs(ratio - 0.5) < 0.01 and variance < 0.26:
                result["suspicious"] = True
                result["indicators"].append(
                    f"{name} channel LSB suspiciously uniform (ratio={ratio:.4f}, var={variance:.4f})"
                )

        # Check for appended data after image end
        with open(p, "rb") as f:
            raw = f.read()

        ext = p.suffix.lower()
        markers = {
            ".jpg": b"\xff\xd9",
            ".jpeg": b"\xff\xd9",
            ".png": b"\x49\x45\x4e\x44\xae\x42\x60\x82",
            ".gif": b"\x00\x3b",
        }
        end_marker = markers.get(ext)
        if end_marker:
            pos = raw.rfind(end_marker)
            if pos != -1 and pos < len(raw) - len(end_marker) - 10:
                trailing = raw[pos + len(end_marker):]
                printable = [c for c in trailing if 32 <= c < 127]
                if len(printable) > 20:
                    result["suspicious"] = True
                    result["indicators"].append(
                        f"{len(trailing)} bytes appended after image end marker"
                    )
                    result["trailing_data_sample"] = bytes(printable[:80]).decode("ascii", errors="replace")

        # File size vs resolution ratio
        file_size = p.stat().st_size
        pixels = arr.shape[0] * arr.shape[1]
        bytes_per_pixel = file_size / pixels
        result["file_size"] = file_size
        result["pixels"] = pixels
        result["bytes_per_pixel"] = round(bytes_per_pixel, 4)
        result["image_size"] = f"{arr.shape[1]}x{arr.shape[0]}"

        if ext in (".png",) and bytes_per_pixel > 4.0:
            result["indicators"].append(
                f"File size/pixel ratio unusually high ({bytes_per_pixel:.2f} B/px)"
            )

    except Exception as e:
        result["error"] = str(e)

    if result["suspicious"]:
        result["verdict"] = "POSSIBLE STEGANOGRAPHY DETECTED"
    else:
        result["verdict"] = "No clear steganography indicators"

    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _estimate_crack_time(entropy_bits: float) -> str:
    """Rough estimate of crack time at 1 billion hashes/second."""
    combos = 2 ** entropy_bits
    rate = 1e9  # 1 GH/s
    seconds = combos / (2 * rate)  # avg 50% keyspace

    if seconds < 1:
        return "Instant"
    elif seconds < 60:
        return f"{seconds:.0f} seconds"
    elif seconds < 3600:
        return f"{seconds/60:.0f} minutes"
    elif seconds < 86400:
        return f"{seconds/3600:.0f} hours"
    elif seconds < 31536000:
        return f"{seconds/86400:.0f} days"
    elif seconds < 3.154e10:
        return f"{seconds/31536000:.0f} years"
    else:
        return f"{seconds/3.154e10:.2e} centuries"


MORSE_CODE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.", " ": "/",
}
MORSE_REVERSE = {v: k for k, v in MORSE_CODE.items()}


def _to_morse(text: str) -> str:
    return " ".join(MORSE_CODE.get(c.upper(), "?") for c in text)


def _from_morse(text: str) -> str:
    return "".join(MORSE_REVERSE.get(w, "?") for w in text.split(" "))


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _display_hash_result(result: dict) -> None:
    rows = [
        ("MD5", result.get("md5", "")),
        ("SHA1", result.get("sha1", "")),
        ("SHA224", result.get("sha224", "")),
        ("SHA256", result.get("sha256", "")),
        ("SHA384", result.get("sha384", "")),
        ("SHA512", result.get("sha512", "")),
        ("Blake2b", result.get("blake2b", "")),
        ("Blake2s", result.get("blake2s", "")),
    ]
    print_result_table("Hash Results", [(r[0], r[1]) for r in rows if r[1]])


def _display_password_result(result: dict) -> None:
    color = result.get("strength_color", "white")
    console.print(f"\n[bold]Strength:[/] [{color}]{result.get('strength')}[/]")
    console.print(f"[bold]Entropy:[/] {result.get('entropy_bits')} bits")
    console.print(f"[bold]Crack Time:[/] {result.get('crack_time')} (1 GH/s)")
    console.print(f"[bold]Score:[/] {result.get('score')}/100")

    checks = result.get("checks", {})
    check_rows = [
        ("Length ≥ 12", "[green]✓[/]" if checks.get("length_ok") else "[red]✗[/]"),
        ("Lowercase", "[green]✓[/]" if checks.get("has_lower") else "[red]✗[/]"),
        ("Uppercase", "[green]✓[/]" if checks.get("has_upper") else "[red]✗[/]"),
        ("Digits", "[green]✓[/]" if checks.get("has_digit") else "[red]✗[/]"),
        ("Special chars", "[green]✓[/]" if checks.get("has_special") else "[red]✗[/]"),
        ("No common patterns", "[green]✓[/]" if checks.get("no_common_patterns") else "[red]✗[/]"),
        ("No repeating", "[green]✓[/]" if checks.get("no_repeating") else "[red]✗[/]"),
        ("No sequential", "[green]✓[/]" if checks.get("no_sequential") else "[red]✗[/]"),
    ]
    print_result_table("Password Checks", check_rows)

    if result.get("feedback"):
        console.print("\n[bold]Recommendations:[/]")
        for tip in result["feedback"]:
            console.print(f"  [yellow]•[/] {tip}")


def run():
    print_section("Cryptography & Analysis", "🔐")
    console.print("\nOptions:")
    console.print("1.  Hash text")
    console.print("2.  Hash file")
    console.print("3.  Identify hash type")
    console.print("4.  AES-256 encrypt")
    console.print("5.  AES-256 decrypt")
    console.print("6.  Encode/Decode (Base64, Hex, ROT13, URL, Morse...)")
    console.print("7.  Auto-detect encoding")
    console.print("8.  Hex viewer (file)")
    console.print("9.  Steganography detection")
    console.print("10. Password strength analyzer")
    console.print("11. Generate secure password")
    choice = console.input("\n[bold]>[/] ").strip()

    if choice == "1":
        text = console.input("[bold]Text to hash:[/] ").strip()
        result = hash_text(text)
        _display_hash_result(result)

    elif choice == "2":
        path = console.input("[bold]File path:[/] ").strip()
        result = hash_file(path)
        if result:
            _display_hash_result(result)
            console.print(f"[bold]File size:[/] {result.get('size', 0):,} bytes")

    elif choice == "3":
        h = console.input("[bold]Hash string:[/] ").strip()
        types = identify_hash(h)
        console.print(f"\n[bold]Possible hash type(s):[/] [cyan]{', '.join(types)}[/]")

    elif choice == "4":
        text = console.input("[bold]Text to encrypt:[/] ").strip()
        password = console.input("[bold]Password:[/] ", password=True)
        mode = console.input("[bold]Mode (GCM/CBC) [GCM]:[/] ").strip() or "GCM"
        result = aes_encrypt(text, password, mode)
        if "error" not in result:
            console.print(f"\n[bold]Mode:[/] {result['mode']}")
            console.print(f"[bold]Combined (base64):[/]\n[green]{result.get('combined')}[/]")
        else:
            print_error(result["error"])

    elif choice == "5":
        combined = console.input("[bold]Encrypted data (base64):[/] ").strip()
        password = console.input("[bold]Password:[/] ", password=True)
        mode = console.input("[bold]Mode (GCM/CBC) [GCM]:[/] ").strip() or "GCM"
        result = aes_decrypt(combined, password, mode)
        if "error" not in result:
            console.print(f"\n[bold green]Decrypted:[/]\n{result['plaintext']}")
        else:
            print_error(result["error"])

    elif choice == "6":
        text = console.input("[bold]Input text:[/] ").strip()
        ops = ["base64_encode", "base64_decode", "hex_encode", "hex_decode",
               "rot13", "url_encode", "url_decode", "binary_encode",
               "binary_decode", "morse_encode", "morse_decode",
               "html_encode", "html_decode", "base32_encode", "base32_decode"]
        console.print("\nOperations: " + ", ".join(ops))
        op = console.input("[bold]Operation:[/] ").strip()
        result = encode_decode(text, op)
        if "error" not in result:
            console.print(f"\n[bold green]Result:[/]\n{result['output']}")
        else:
            print_error(result["error"])

    elif choice == "7":
        text = console.input("[bold]Encoded text to auto-detect:[/] ").strip()
        result = auto_decode(text)
        if result["candidates"]:
            for c in result["candidates"]:
                console.print(f"\n[bold cyan]{c['encoding']}:[/] {c['decoded'][:200]}")
        else:
            console.print("[yellow]No obvious encoding detected[/]")

    elif choice == "8":
        path = console.input("[bold]File path:[/] ").strip()
        offset_str = console.input("[bold]Offset (bytes, default 0):[/] ").strip()
        length_str = console.input("[bold]Length (bytes, default 512):[/] ").strip()
        offset = int(offset_str) if offset_str.isdigit() else 0
        length = int(length_str) if length_str.isdigit() else 512
        result = hex_view(path, offset, length)
        if result:
            console.print(f"\n[bold]Hex Dump:[/]\n[dim]{result.get('hex_dump')}[/]")
            if result.get("strings"):
                console.print("\n[bold]Printable Strings:[/]")
                for s in result["strings"][:15]:
                    console.print(f"  {s}")
            if any(result.get("iocs", {}).values()):
                console.print("\n[bold red]IOCs found:[/]")
                for ioc_type, iocs in result.get("iocs", {}).items():
                    for ioc in iocs[:5]:
                        console.print(f"  [{ioc_type}] {ioc}")

    elif choice == "9":
        path = console.input("[bold]Image path:[/] ").strip()
        result = detect_steganography(path)
        verdict_color = "red" if result.get("suspicious") else "green"
        console.print(f"\n[bold]Verdict:[/] [{verdict_color}]{result.get('verdict')}[/]")
        for ind in result.get("indicators", []):
            console.print(f"  [yellow]•[/] {ind}")
        if result.get("trailing_data_sample"):
            console.print(f"[bold]Trailing data sample:[/] {result['trailing_data_sample']}")

    elif choice == "10":
        import getpass
        password = getpass.getpass("Password to analyze: ")
        result = analyze_password(password)
        _display_password_result(result)

        # Also check HIBP
        hibp_check = console.input("\n[bold]Check against HaveIBeenPwned password list? (y/n):[/] ").strip().lower()
        if hibp_check == "y":
            from utils.api_manager import hibp_check_password
            with console.status("Checking k-anonymity API..."):
                count = hibp_check_password(password)
            if count is None:
                print_warning("Could not check HaveIBeenPwned")
            elif count > 0:
                console.print(f"[bold red]⚠ This password appears {count:,} times in known breaches![/]")
            else:
                print_success("Password not found in known breach databases")

    elif choice == "11":
        length_str = console.input("[bold]Length (default 20):[/] ").strip()
        length = int(length_str) if length_str.isdigit() else 20
        use_special = console.input("[bold]Include special chars? (y/n) [y]:[/] ").strip().lower() != "n"
        exclude_ambiguous = console.input("[bold]Exclude ambiguous chars (Il1O0)? (y/n) [n]:[/] ").strip().lower() == "y"

        result = generate_password(length, use_special=use_special, exclude_ambiguous=exclude_ambiguous)
        console.print(f"\n[bold green]Generated Password:[/] [white on black] {result['password']} [/]")
        console.print(f"[bold]Entropy:[/] {result['entropy_bits']} bits")
        console.print(f"[bold]Strength:[/] {result['strength']}")
    else:
        print_error("Invalid option")
