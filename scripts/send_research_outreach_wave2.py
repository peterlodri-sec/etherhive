#!/usr/bin/env python3
"""
Send Wave 2 of independent SOTA AI research outreach emails via Proton Mail Bridge (127.0.0.1:1025).
"""

import os
import smtplib
import ssl
import sys
import time
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

SENDER = "cabotage@pm.me"

OUTREACH_TARGETS_WAVE2 = [
    {
        "name": "Foresight Institute (Fellowships & Grants)",
        "to": ["fellowship@foresight.org", "grants@foresight.org"],
        "subject": "Foresight Fellowship & Research Inquiry: Sovereign Composite Intelligence, KOMPRESS & Axiom Quant — Péter Lodri",
        "body": """Dear Foresight Institute Team,

I am writing to submit an inquiry and introduction for the Foresight Fellowship and AI Research Grants.

I operate as an independent SOTA AI researcher and systems architect under a high-velocity "edge digital nomad" paradigm — architecting and shipping sovereign AI systems, mathematical monographs, and multi-agent harnesses entirely from a 5G iPhone and a MacBook.

================================================================================
1. RESEARCH TRACK RECORD & FOUNDATIONAL ARTIFACTS
================================================================================
• Foundational Paper — KOMPRESS:
  https://kompress.vaked.dev/paper/main.pdf
  High-throughput token compression, ternary representation, and entropy reduction architectures.

• AXIOM QUANT (https://axiomquant.org):
  Open-access 19-chapter mathematical monograph on spectral rigidity, Tracy-Widom edge statistics, Schramm-Loewner Evolution (SLE), and stochastic market microstructure.

• HUGGING FACE MODELS & SPACES:
  - Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6 (Waldorf geometric-mean consensus distillation)
  - Space: https://huggingface.co/spaces/PeetPedro/cogitoergosumma-corpus (Philosophical corpus Q&A)

• DEEPSIPER ENTHEA & POCOO:
  - DeepSiper Enthea: https://github.com/8b-is/deepsiper-enthea (Multi-agent worktree evaluation harness)
  - Pocoo Kernel: https://pocoo.vaked.dev (Python bytecode, AST compilation, and micro-kernel runtime exploration)

• ETHERHIVE / HONEST-IRC:
  https://etherhive.vaked.dev | https://github.com/peterlodri-sec/etherhive
  Post-quantum cryptographic Double Ratchet (FIPS 203/204/205) and Kademlia DHT decentralized communication.

================================================================================
2. THE EDGE NOMAD PHILOSOPHY & ALIGNMENT WITH FORESIGHT
================================================================================
We believe the frontier of intelligence belongs to lean, unencumbered, sovereign researchers who combine deep mathematical rigor with zero-friction shipping cadence. 

A Foresight Fellowship / research grant would accelerate our work on:
1. Long-context multi-agent consensus proofs and AST verification swarms.
2. Ternary {-1, 0, +1} neural representation and ultra-low-energy edge intelligence.

================================================================================
3. ONLINE FOOTPRINT & PORTALS
================================================================================
• Personal Hub: https://peterl.dev
• Constellation: https://vaked.dev | https://axiomquant.org | https://pocoo.vaked.dev
• GitHub: https://github.com/peterlodri-sec | https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Telegram: @p3t3r_l
• Email: cabotage@pm.me

I would welcome the opportunity to connect with the Foresight fellows and research community!

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
https://peterl.dev · https://vaked.dev · https://axiomquant.org

--
genesis seal:
7c242080f5f821e5eaf563fe2208d60632c451687baf65f4fe8e4a0d226e3ecf
WE. {-1, 0, +1}. <3
"""
    },
    {
        "name": "Mistral AI (Research & Open Source Grants)",
        "to": ["contact@mistral.ai"],
        "subject": "Mistral AI Research & Open Source Collaboration Inquiry: Sovereign Distillation & DeepSiper Enthea — Péter Lodri",
        "body": """Dear Mistral AI Research Team,

I am reaching out to explore open-source research collaboration and compute/API grant opportunities with Mistral AI.

As an independent SOTA AI research team operating as "edge digital nomads" (5G iPhone + MacBook setup across Europe), we build open-weights distillation harnesses, mathematical monographs, and multi-agent evaluation systems.

================================================================================
OUR RESEARCH TRACK RECORD
================================================================================
1. KOMPRESS Paper: https://kompress.vaked.dev/paper/main.pdf
   Token compression, entropy reduction, and high-throughput neural inference.

2. Classroom SOTA Training & Published Weights:
   - Hugging Face Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
   - Council of Elders: Waldorf geometric-mean consensus distillation training edge student models from open-weights teacher councils.

3. DeepSiper Enthea & Pocoo:
   - DeepSiper Enthea: https://github.com/8b-is/deepsiper-enthea (Parallel git worktree evaluation harness)
   - Pocoo Laboratory: https://pocoo.vaked.dev (AST manipulation & micro-runtimes)

4. Axiom Quant Monograph:
   https://axiomquant.org (19 chapters on spectral rigidity, stochastic calculus & random matrix theory)

================================================================================
COLLABORATION & COMPUTE GOAL
================================================================================
We would love to integrate Mistral frontier models (Mistral Large, Codestral, Pixtral) into our multi-agent worktree swarms and distillation pipelines, and apply for research credits or open-science partnership.

• Portals: https://peterl.dev · https://vaked.dev · https://axiomquant.org · https://pocoo.vaked.dev
• GitHub: https://github.com/peterlodri-sec · https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)

Thank you for championing sovereign, open AI in Europe!

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | Telegram: @p3t3r_l
"""
    },
    {
        "name": "Lambda Labs (Research Cloud Compute)",
        "to": ["sales@lambda.ai", "support@lambdalabs.com"],
        "subject": "Lambda Labs Research Compute Inquiry: Sovereign Multi-Agent Swarms & Consensus Distillation — Péter Lodri",
        "body": """Dear Lambda Labs Research Team,

I am writing to inquire about research GPU compute allocations and credits for our open-source AI lab.

We operate as an agile "edge digital nomad" research unit (5G iPhone + MacBook workflow), training open-weights models and running distributed evaluation harnesses.

================================================================================
RESEARCH INVENTIONS & OPEN ARTIFACTS
================================================================================
• Foundational Paper — KOMPRESS:
  https://kompress.vaked.dev/paper/main.pdf
  High-throughput token compression and entropy reduction.

• Classroom SOTA Distillation:
  - Published Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
  - Geometric-mean logit consensus distillation for compact 1.7B edge models.

• DeepSiper Enthea:
  https://github.com/8b-is/deepsiper-enthea
  Sovereign LLM evaluation harness running parallel reasoning swarms across isolated git worktrees.

• Axiom Quant & Pocoo:
  - Axiom Quant: https://axiomquant.org (19-chapter mathematical monograph)
  - Pocoo: https://pocoo.vaked.dev (AST/bytecode optimization)
  - Constellation: https://vaked.dev | https://etherhive.vaked.dev

================================================================================
COMPUTE ASK
================================================================================
We are seeking Lambda Cloud GPU credits (1-Click Clusters / On-Demand H100 / A100 instances) to scale our student model training runs and large-context multi-agent AST benchmarks.

• GitHub: https://github.com/peterlodri-sec | https://github.com/8b-is
• Personal: https://peterl.dev
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)

Thank you for your support of independent AI builders!

Best regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | Telegram: @p3t3r_l
"""
    },
    {
        "name": "Fireworks AI (Research & Inquiries)",
        "to": ["inquiries@fireworks.ai"],
        "subject": "Fireworks AI Research & Open-Source Grant Inquiry: Fast Multi-Model Consensus Swarms — Péter Lodri",
        "body": """Dear Fireworks AI Team,

I am reaching out regarding research credits and open-source partnership opportunities with Fireworks AI.

We are an independent SOTA AI research lab working as "edge digital nomads" (iPhone 5G + MacBook setup), specializing in multi-model evaluation harnesses and consensus distillation.

================================================================================
WHY FIREWORKS AI IS CRITICAL FOR OUR WORK
================================================================================
1. DeepSiper Enthea (https://github.com/8b-is/deepsiper-enthea):
   Our harness coordinates parallel agent swarms across isolated git worktrees. Fireworks' ultra-low-latency inference engine is ideal for high-throughput multi-agent voting, speculative decoding, and AST validation passes.

2. Research Background & Artifacts:
   - Foundational Paper: https://kompress.vaked.dev/paper/main.pdf (KOMPRESS: Token compression & neural streaming)
   - Hugging Face Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
   - Monograph: https://axiomquant.org
   - Pocoo: https://pocoo.vaked.dev

• Hub: https://peterl.dev · https://vaked.dev
• GitHub: https://github.com/peterlodri-sec · https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)

We would love to apply for research API credits to benchmark Fireworks endpoints in our autonomous evaluation harnesses.

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | Telegram: @p3t3r_l
"""
    },
    {
        "name": "Berggruen Institute (Fellowships & Grants)",
        "to": ["scholarscampus@berggruen.org", "institute@berggruen.org"],
        "subject": "Berggruen Fellowship Inquiry: Philosophy of Sovereign AI, Axiom Quant & The Three Questions of Peter — Péter Lodri",
        "body": """Dear Berggruen Institute Scholars & Fellowship Committee,

I am writing to inquire about the Berggruen Fellowship Program and research support for our work at the intersection of philosophy, mathematics, and autonomous artificial intelligence.

I conduct research as an independent "edge digital nomad" systems architect, creating open-access monographs and sovereign computational systems from the trail and mountains of Europe.

================================================================================
PHILOSOPHICAL & MATHEMATICAL FOUNDATIONS
================================================================================
• The Three Questions of Peter: Faith, Fear, and Admissible Continuation
  Published as Chapter 12 of Axiom Quant (https://axiomquant.org): Exploring topological basin recovery, infinite grace repair bounds, and human agency under algorithmic acceleration.

• KOMPRESS & Spectral Rigidity:
  - KOMPRESS Paper: https://kompress.vaked.dev/paper/main.pdf
  - Axiom Quant: https://axiomquant.org (19 chapters on random matrix theory, Tracy-Widom distributions, and stochastic calculus)

• Classroom SOTA Distillation & Cognitive Spaces:
  - Hugging Face Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
  - CogitoErgoSumma Space: https://huggingface.co/spaces/PeetPedro/cogitoergosumma-corpus

• Sovereign Technology & Micro-Kernels:
  - Pocoo Kernel: https://pocoo.vaked.dev
  - Honest-IRC / Etherhive: https://etherhive.vaked.dev (PQC decentralized network)
  - Constellation Hub: https://vaked.dev | https://peterl.dev
  - Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)

We would be honored to engage with the Berggruen scholars to explore how sovereign intelligence, structural honesty, and ternary ethics can shape the future of human-AI coexistence.

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | https://peterl.dev

--
genesis seal:
7c242080f5f821e5eaf563fe2208d60632c451687baf65f4fe8e4a0d226e3ecf
WE. {-1, 0, +1}. <3
"""
    },
    {
        "name": "Open Philanthropy (AI Grants)",
        "to": ["grants@openphilanthropy.org", "info@openphilanthropy.org"],
        "subject": "Open Philanthropy Grant Inquiry: Sovereign AI Safety, Multi-Agent Verification & Formal Monographs — Péter Lodri",
        "body": """Dear Open Philanthropy AI Grants Team,

I am writing to inquire about grant opportunities for independent researchers working on AI safety, multi-agent verification harnesses, and formal mathematical foundations.

Operating as an independent "edge digital nomad" team (5G iPhone + MacBook workflow), we build open-source verification systems with zero institutional bureaucracy.

================================================================================
KEY RESEARCH INITIATIVES
================================================================================
1. Multi-Agent Worktree Verification (DeepSiper Enthea):
   https://github.com/8b-is/deepsiper-enthea
   Autonomous evaluation harness utilizing isolated git worktrees for parallel reasoning, rigorous AST validation, and multi-model consensus to prevent silent reward-hacking.

2. Foundational Paper & Research Monograph:
   - KOMPRESS Paper: https://kompress.vaked.dev/paper/main.pdf
   - Axiom Quant: https://axiomquant.org (19 chapters on spectral rigidity, stochastic processes, and mathematical proofs)

3. SOTA Consensus Distillation & Open Artifacts:
   - Hugging Face Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
   - Pocoo Runtime: https://pocoo.vaked.dev
   - Decentralized PQC Communication: https://etherhive.vaked.dev

• Hub: https://peterl.dev · https://vaked.dev
• GitHub: https://github.com/peterlodri-sec · https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)

We are seeking non-dilutive research funding / compute support ($20k–$100k) to scale our open-source agent evaluation harnesses and publish formal verification benchmarks.

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | https://peterl.dev

--
genesis seal:
7c242080f5f821e5eaf563fe2208d60632c451687baf65f4fe8e4a0d226e3ecf
WE. {-1, 0, +1}. <3
"""
    }
]

def send_wave2_outreach():
    config_path = os.path.expanduser("~/.config/proton_bridge.txt")
    if not os.path.exists(config_path):
        print(f"Error: Password file not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        password = f.read().strip()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"Connecting to Proton Mail Bridge at 127.0.0.1:1025 to send {len(OUTREACH_TARGETS_WAVE2)} Wave 2 outreach emails...")
    
    with smtplib.SMTP_SSL("127.0.0.1", 1025, context=ctx, timeout=30) as server:
        server.login(SENDER, password)
        
        for idx, target in enumerate(OUTREACH_TARGETS_WAVE2, 1):
            name = target["name"]
            to_addrs = target["to"]
            subject = target["subject"]
            body = target["body"]

            msg = MIMEText(body, "plain", "utf-8")
            msg["Subject"] = subject
            msg["From"] = SENDER
            msg["To"] = ", ".join(to_addrs)
            msg["Date"] = formatdate(localtime=True)
            msg["Message-ID"] = make_msgid(domain="pm.me")

            print(f"[{idx}/{len(OUTREACH_TARGETS_WAVE2)}] Sending outreach to {name} ({', '.join(to_addrs)})...")
            try:
                server.send_message(msg, from_addr=SENDER, to_addrs=to_addrs)
                print(f"  ✓ Successfully sent to {name}!")
            except Exception as e:
                print(f"  ✗ Failed to send to {name}: {e}", file=sys.stderr)
            
            time.sleep(2)

    print("\n✓ All Wave 2 outreach emails dispatched successfully via Proton Mail Bridge!")

if __name__ == "__main__":
    send_wave2_outreach()
