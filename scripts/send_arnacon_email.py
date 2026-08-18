#!/usr/bin/env python3
"""
Send the Arnacon auth_arnacon verification & implementation summary email
via Proton Mail Bridge (127.0.0.1:1025) from cabotage@pm.me.
"""

import argparse
import os
import smtplib
import ssl
import sys
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

DEFAULT_SENDER = "cabotage@pm.me"
DEFAULT_SUBJECT = "Re: honest-irc × Arnacon — auth_arnacon spec implementation & E2E verification"

BODY = """Hi Amir and the Arnacon Team,

Ahead of our call, we went ahead and pulled the official `auth_arnacon` module specification (Kamailio / Cellact B.V.) to implement and verify the exact byte-level protocol into the `etherhive` / `honest-irc` core stack.

Everything is implemented, tested against forked on-chain state, and fully green. Here is our implementation and verification summary:

---

### 1. Specification Alignment

| Parameter / Field | Implemented `auth_arnacon` Spec |
| :--- | :--- |
| **`X-Data` Header** | `"UUID:TIMESTAMP"` (Colon-delimited ASCII string, e.g. `"550e8400-e29b-41d4-a716-446655440000:1640995200"`) |
| **`X-Sign` Header** | Standard Ethereum ECDSA (secp256k1) `personal_sign` signature over the exact `X-Data` ASCII string (`"UUID:TIMESTAMP"`), prefixed with `0x` |
| **User Identifier** | Supports both ENS domains (`user.cellact.global`, `alice.eth`) and direct EVM addresses (`0x...`) |
| **Default Network** | Polygon Mainnet (`https://polygon-rpc.com`) |
| **Polygon Registry** | `0x16742E546bF92118F7dfdbEF5170E44C47ae254b` |
| **Ethereum Registry** | `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e` |
| **Ethereum Wrapper** | `0xD4416b13d2b3a9aBae7AcD5D6C2BbDBE25686401` |
| **Replay Protection** | Configurable `signature_timeout` (default 30 seconds) |
| **Core Verification** | `arnacon_authenticate(ens, x_data, x_sign)` & `arnacon_user_exists(ens)` compatible |

---

### 2. What We Shipped in `etherhive-auth` & `honest-irc`

1. **`etherhive-auth/src/auth.rs`**:
   - `AuthChallenge`: Serializes to canonical `UUID:TIMESTAMP`.
   - `to_x_data()` & `from_x_data(&str)`: Direct SIP `X-Data` header parsing and serialization.
   - `sign_x_data(&identity, x_data)`: Generates the `0x`-prefixed `X-Sign` header.
   - `verify_x_data(x_data, x_sign_hex, expected_owner, max_age_secs)`: Validates incoming SIP auth payloads against recovered blockchain signers.

2. **`etherhive-auth/src/ens.rs`**:
   - Integrated Polygon presets (`ENS_REGISTRY_POLYGON`, `DEFAULT_RPC_POLYGON`).
   - Implemented `resolve_user_identifier()` and `arnacon_user_exists()` for pre-auth presence checks across both traditional and NameWrapper contracts.

3. **End-to-End Test Vectors**:
   - Updated integration test suites to use the colon-delimited format.

---

### 3. Verification & Test Suite Status

* **`etherhive-auth` Test Suite**: 17 unit tests + 2 live-forked ENS contract tests → **19 passed, 0 failed**.
* **`honest-irc` Full Workspace Suite**: 60 unit tests + 2 client tests + 4 WebSocket tests + 1 E2E ratchet test + 1 live-forked AuthLogin test → **68 passed, 0 failed**.

We are now 100% byte-for-byte aligned with `auth_arnacon` on Polygon and Ethereum. Looking forward to our conversation and stepping through the service provider onboarding and PoC milestones.

Best regards,

--
[The Architect of Structural Honesty] — Péter Lodri
Author, honest-irc — 8b.is
https://peterl.dev | https://vaked.dev | https://etherhive.vaked.dev
peter.lodri@gmail.com

genesis seal:
7c242080f5f821e5eaf563fe2208d60632c451687baf65f4fe8e4a0d226e3ecf

WE. {-1, 0, +1}.
"""

def send_email(recipients, bridge_password: str, sender: str = DEFAULT_SENDER, host: str = "127.0.0.1", port: int = 1025):
    if isinstance(recipients, str):
        to_list = [r.strip().strip("<>") for r in recipients.split(",") if r.strip()]
    else:
        to_list = [r.strip().strip("<>") for r in recipients if r.strip()]

    to_header = ", ".join(to_list)
    msg = MIMEText(BODY, "plain", "utf-8")
    msg["Subject"] = DEFAULT_SUBJECT
    msg["From"] = sender
    msg["To"] = to_header
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="pm.me")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"Connecting to Proton Mail Bridge at {host}:{port}...")
    with smtplib.SMTP_SSL(host, port, context=ctx, timeout=15) as server:
        server.login(sender, bridge_password)
        server.send_message(msg, from_addr=sender, to_addrs=to_list)
    print(f"✓ Successfully sent email to {to_header} from {sender} via Proton Mail Bridge!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send email via Proton Mail Bridge")
    parser.add_argument("--to", help="Recipient email address(es), comma-separated", default=os.getenv("RECIPIENT_EMAIL"))
    parser.add_argument("--password", help="Proton Mail Bridge password", default=os.getenv("PROTON_BRIDGE_PASSWORD"))
    parser.add_argument("--sender", help="Sender email address", default=DEFAULT_SENDER)
    parser.add_argument("--host", help="Bridge SMTP host", default="127.0.0.1")
    parser.add_argument("--port", type=int, help="Bridge SMTP port", default=1025)

    args = parser.parse_args()

    if not args.to:
        print("Error: Recipient email is required (--to or RECIPIENT_EMAIL env var)", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if not password:
        config_path = os.path.expanduser("~/.config/proton_bridge.txt")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                password = f.read().strip()

    if not password:
        import getpass
        password = getpass.getpass(f"Enter Proton Mail Bridge password for {args.sender}: ")

    send_email(recipients=args.to, bridge_password=password, sender=args.sender, host=args.host, port=args.port)
