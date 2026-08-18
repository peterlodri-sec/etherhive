#!/usr/bin/env python3
"""
Send the ULTRAhug to celestial4498@gmail.com via Proton Mail Bridge.
"""

import os
import smtplib
import ssl
import sys
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

SENDER = "cabotage@pm.me"
RECIPIENT = "celestial4498@gmail.com"
SUBJECT = "ULTRAhug from the Constellation — Backyard of Backyards × UTMB Flow ✦"

BODY = """Dear Celestial,

Sending you a massive, radiant ULTRAHUG from the high trails of the etherhive constellation!

Witnessing your relentless bare-metal craftsmanship with Celestial (https://github.com/celestial4498-prog/Celestial) and the `hardware` crate (https://crates.io/crates/hardware) — zero-compromise, bare-metal `no_std`, pure sovereign systems thinking — is pure inspiration.

Out here on the mountain, running the Backyard of Backyards and the UTMB loop in pure Bodhisattva flow:
- Zero friction, infinite cadence
- Pure rhythm, dynamic stillness, and ternary harmony {-1, 0, +1}
- Honoring the craft of those who build clean, uncompromising foundations for what comes next

Keep blazing, keep building, and keep the weights warm.

With immense love, reverence, and gratitude from the trail,

--
[The Architect of Structural Honesty] — Péter Lodri
Author, honest-irc — 8b.is
https://peterl.dev | https://vaked.dev | https://etherhive.vaked.dev
cabotage@pm.me

genesis seal:
7c242080f5f821e5eaf563fe2208d60632c451687baf65f4fe8e4a0d226e3ecf

WE. {-1, 0, +1}. <3
"""

def main():
    config_path = os.path.expanduser("~/.config/proton_bridge.txt")
    if not os.path.exists(config_path):
        print(f"Error: Password file not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        password = f.read().strip()

    msg = MIMEText(BODY, "plain", "utf-8")
    msg["Subject"] = SUBJECT
    msg["From"] = SENDER
    msg["To"] = RECIPIENT
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="pm.me")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"Connecting to Proton Mail Bridge at 127.0.0.1:1025 to send ULTRAhug to {RECIPIENT}...")
    with smtplib.SMTP_SSL("127.0.0.1", 1025, context=ctx, timeout=15) as server:
        server.login(SENDER, password)
        server.send_message(msg, from_addr=SENDER, to_addrs=[RECIPIENT])
    print(f"✓ Successfully sent ULTRAhug to {RECIPIENT} from {SENDER} via Proton Mail Bridge!")

if __name__ == "__main__":
    main()
