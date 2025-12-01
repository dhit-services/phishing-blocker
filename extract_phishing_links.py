#!/usr/bin/env python3
import re
import socket
from pathlib import Path
import base64

# ---- Pfade & Dateien --------------------------------------------------------
MAILDIR = Path.home() / ".local/share/evolution/mail/local/.SPAM/cur"
OUTPUT = Path.home() / "./phishingblocker.txt"
WHITELIST = Path.home() / "./whitelist.txt"

# ---- Regexen ---------------------------------------------------------------
URL_REGEX = re.compile(r"(https?://[^\s<>'\"]+|www\.[^\s<>'\"]+)", re.IGNORECASE)
DOMAIN_REGEX = re.compile(r"^[a-z0-9.-]+\.[a-z]{2,}$", re.IGNORECASE)

# ---- Funktionen -------------------------------------------------------------

def decode_mail(text: str) -> str:
    """Dekodiert BASE64-Inhalte, falls Mail so codiert ist."""
    if "content-transfer-encoding: base64" in text.lower():
        parts = text.split("\n\n", 1)
        if len(parts) == 2:
            try:
                decoded = base64.b64decode(parts[1], validate=False)
                return decoded.decode("utf-8", errors="ignore")
            except Exception:
                pass
    return text

def extract_urls(maildir: Path):
    urls = set()
    for f in maildir.glob("*"):
        try:
            raw = f.read_text(errors="ignore")
            decoded = decode_mail(raw)
            urls.update(URL_REGEX.findall(decoded))
        except Exception:
            continue
    return urls

def extract_domain(url: str) -> str:
    url = url.lower().strip()
    url = re.sub(r"^https?://", "", url)
    url = url.split("/")[0].split("?")[0].split("=")[0]
    if url.startswith("www."):
        url = url[4:]
    url = "".join(c for c in url if c.isalnum() or c in ".-")
    return url

def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_REGEX.match(domain))

def load_whitelist(file: Path):
    if not file.exists():
        return set()
    return {line.strip().lower().lstrip("www.") for line in file.read_text().splitlines() if line.strip()}

def domain_is_whitelisted(domain: str, whitelist: set) -> bool:
    for w in whitelist:
        if domain == w or domain.endswith("." + w):
            return True
    return False

def load_existing_blocklist(file: Path):
    if not file.exists():
        return set()
    return {line.strip().lower() for line in file.read_text().splitlines() if line.strip()}

def dns_resolves(domain: str) -> bool:
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False

# ---- Hauptlogik -------------------------------------------------------------

def main():
    print("🔍 Lese Spam-Mails…")
    urls = extract_urls(MAILDIR)
    print(f"Gefundene URLs: {len(urls)}")

    domains = {extract_domain(u) for u in urls}
    domains = {d for d in domains if is_valid_domain(d)}
    print(f"Extrahierte Domains: {len(domains)}")

    whitelist = load_whitelist(WHITELIST)
    if whitelist:
        print(f"🛡️ Whitelist geladen ({len(whitelist)} Einträge)")

    filtered = {d for d in domains if not domain_is_whitelisted(d, whitelist)}
    print(f"Domains nach Whitelist-Filter: {len(filtered)}")

    # DNS-Check (Domains, die nicht auflösbar sind, trotzdem blocken)
    blocklist = set()
    for d in sorted(filtered):
        if dns_resolves(d):
            print(f"✅ OK, blocken: {d}")
        else:
            print(f"⚠️ Nicht auflösbar, trotzdem blocken: {d}")
        blocklist.add(d)  # immer hinzufügen

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    existing = load_existing_blocklist(OUTPUT)
    merged = existing.union(blocklist)

    with OUTPUT.open("w") as f:
        for d in sorted(merged):
            f.write(d + "\n")

    print("\n🎉 Fertig!")
    print(f"Gesamt Domains in Blockliste: {len(merged)}")
    print(f"Gespeichert unter: {OUTPUT}")

if __name__ == "__main__":
    main()

