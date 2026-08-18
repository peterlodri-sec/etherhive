#!/usr/bin/env python3
"""
Submit direct Application & Expression of Interest to jobs@coefficientgiving.org via Proton Mail Bridge.
"""

import os
import smtplib
import ssl
import sys
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

SENDER = "cabotage@pm.me"
RECIPIENTS = ["jobs@coefficientgiving.org"]

SUBJECT = "Expression of Interest: SOTA AI Research Engineer / Technical AI Safety & Systems Researcher — Péter Lodri"

BODY = """Dear Coefficient Giving Recruiting & Research Team,

I am writing to submit an Expression of Interest for Technical AI Research Engineer, AI Safety & Systems Researcher, or Quantitative Grantmaking Fellow roles within Coefficient Giving (focusing on Navigating Transformative AI, Global Catastrophic Risks, or Abundance & Growth).

I operate as an independent SOTA AI systems architect and mathematical researcher under an agile "edge digital nomad" workflow (5G iPhone + MacBook setup across Europe). My core focus is building verified multi-agent harnesses, low-level token compression architectures, and formal mathematical foundations for safe, sovereign artificial intelligence.

================================================================================
1. CORE RESEARCH ARTIFACTS & EVIDENCE OF WORK
================================================================================
• Foundational Research Paper — KOMPRESS:
  https://kompress.vaked.dev/paper/main.pdf
  High-throughput token compression, ternary representation {-1, 0, +1}, and neural entropy reduction.

• Axiom Quant (https://axiomquant.org):
  Open-access 19-chapter mathematical monograph spanning spectral rigidity, Tracy-Widom edge statistics, Hawkes processes, and stochastic repair bounds (e.g., Chapter 12: "The Three Questions of Peter: Faith, Fear, and Admissible Continuation").

• Multi-Agent Safety & Evaluation Harness (DeepSiper Enthea):
  https://github.com/8b-is/deepsiper-enthea
  Autonomous evaluation harness coordinating parallel reasoners in isolated git worktrees with strict AST validation, preventing reward-hacking and silent drift.

• Consensus Distillation & Published Weights:
  - Hugging Face Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
  - Classroom SOTA Training: Geometric-mean softmax logit consensus distillation for compact 1.7B edge student models from frontier teacher councils.
  - CogitoErgoSumma Space: https://huggingface.co/spaces/PeetPedro/cogitoergosumma-corpus

• Micro-Kernel & Cryptographic Systems:
  - Pocoo Kernel: https://pocoo.vaked.dev (Python AST compilation & execution micro-runtimes)
  - EtherHive / Honest-IRC: https://etherhive.vaked.dev | https://github.com/peterlodri-sec/etherhive
    Post-quantum Double Ratchet (FIPS 203/204/205) and Kademlia DHT decentralized network.

================================================================================
2. HOW MY SKILLSET ALIGNS WITH COEFFICIENT GIVING
================================================================================
1. Technical Rigor & Empirical Evaluation:
   Deep expertise in the full stack—from PyTorch model training and logit math down to Rust zero-GIL runtimes and formal AST analysis.

2. Epistemic Independence & Fast Execution:
   I work with high velocity and minimal institutional friction, capable of investigating open technical questions, designing rigorous work tests, and evaluating bleeding-edge frontier claims.

3. Cause Alignment:
   Deeply committed to addressing catastrophic risks from transformative AI through verifiable evaluation harnesses, interpretability, and robust mathematical safety bounds.

================================================================================
3. ONLINE PORTALS & CONTACT
================================================================================
• Personal Hub: https://peterl.dev
• Constellation: https://vaked.dev | https://axiomquant.org | https://pocoo.vaked.dev
• GitHub: https://github.com/peterlodri-sec | https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Telegram: @p3t3r_l
• Email: cabotage@pm.me
• Location: Remote - Global (European timezone / Digital Nomad)

I would be thrilled to participate in your paid work tests and discuss how my research background in SOTA AI systems and formal mathematics can contribute to Coefficient Giving's mission!

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
https://peterl.dev · cabotage@pm.me

--
genesis seal:
7c242080f5f821e5eaf563fe2208d60632c451687baf65f4fe8e4a0d226e3ecf
WE. {-1, 0, +1}. <3
"""

def send_application():
    config_path = os.path.expanduser("~/.config/proton_bridge.txt")
    if not os.path.exists(config_path):
        print(f"Error: Password file not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        password = f.read().strip()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"Connecting to Proton Mail Bridge at 127.0.0.1:1025 to submit application to {', '.join(RECIPIENTS)}...")
    
    with smtplib.SMTP_SSL("127.0.0.1", 1025, context=ctx, timeout=30) as server:
        server.login(SENDER, password)

        msg = MIMEText(BODY, "plain", "utf-8")
        msg["Subject"] = SUBJECT
        msg["From"] = SENDER
        msg["To"] = ", ".join(RECIPIENTS)
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain="pm.me")

        server.send_message(msg, from_addr=SENDER, to_addrs=RECIPIENTS)
        print("✓ Successfully sent direct job application to jobs@coefficientgiving.org!")

if __name__ == "__main__":
    send_application()
