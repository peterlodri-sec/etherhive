#!/usr/bin/env python3
"""
Send direct B2B AI Research & Systems Engineering Consulting proposals
to select SOTA AI infrastructure & agent companies via Proton Mail Bridge (127.0.0.1:1025).
"""

import os
import smtplib
import ssl
import sys
import time
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

SENDER = "cabotage@pm.me"

B2B_TARGETS = [
    {
        "name": "Fireworks AI (Founding Team & Partnerships)",
        "to": ["inquiries@fireworks.ai"],
        "subject": "B2B / Advisory: High-Throughput Agent Swarms & Low-Latency LLM Inference — Péter Lodri",
        "body": """Hi Fireworks Team,

I'm reaching out to introduce our boutique SOTA AI research and systems engineering practice for B2B contract consulting, advisory, or fractional research engineering.

I operate as a high-velocity "edge digital nomad" systems architect (iPhone 5G + MacBook setup), building production-grade multi-agent harnesses, low-latency inference runtimes in Rust, and mathematical models with zero overhead.

================================================================================
CORE CONSULTING & RESEARCH CAPABILITIES
================================================================================
1. High-Throughput Multi-Agent Orchestration (DeepSiper Enthea):
   https://github.com/8b-is/deepsiper-enthea
   We build autonomous evaluation harnesses running parallel coder swarms in isolated git worktrees with strict AST-level verification and multi-model consensus.

2. Token Compression & High-Throughput Inference:
   - Foundational Paper: https://kompress.vaked.dev/paper/main.pdf (KOMPRESS: Token compression & entropy reduction)
   - Low-latency inference backends bridging PyTorch and Rust (zero-GIL, Candle, Tokio concurrency).

3. Waldorf Consensus Distillation (Classroom SOTA Training):
   - Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
   - Distilling 1.7B edge models from frontier teacher councils via geometric-mean softmax logit consensus.

4. Quantitative & Mathematical Monograph (Axiom Quant):
   https://axiomquant.org (19 chapters on spectral rigidity, stochastic calculus & random matrix theory).

================================================================================
HOW WE ENGAGE WITH TEAMS
================================================================================
• Fractional AI Research Engineer / Systems Architect (10–20 hrs/week)
• Custom Multi-Agent Harness & Benchmark Design
• Inference Latency & Cost Optimization (PyTorch -> Rust/C++ compilation)
• Model Distillation & Post-Training Pipelines

• Hub: https://peterl.dev · https://vaked.dev · https://axiomquant.org
• GitHub: https://github.com/peterlodri-sec · https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Telegram: @p3t3r_l
• Email: cabotage@pm.me

If you have technical bottlenecks in agentic concurrency, evaluation harnesses, or model optimization where an experienced researcher-builder can add immediate velocity, let's connect!

Best regards,

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
        "name": "Baseten (AI Engineering Team)",
        "to": ["support@baseten.co"],
        "subject": "B2B AI Systems Consulting / Fractional Research Engineer — Péter Lodri",
        "body": """Hi Baseten Team,

I'm reaching out to introduce our independent AI research and systems engineering practice for contract consulting, model optimization, and agent infrastructure.

We operate as an agile "edge digital nomad" engineering lab (5G iPhone + MacBook workflow across Europe), delivering production-grade multi-agent systems, inference optimization, and open-weights distillation.

================================================================================
PROVEN TECHNICAL TRACK RECORD
================================================================================
• Token Compression & Inference Speedups:
  - KOMPRESS Paper: https://kompress.vaked.dev/paper/main.pdf
  - High-performance Rust & PyTorch inference pipelines, eliminating concurrency bottlenecks.

• Multi-Agent Worktree Harnesses:
  - DeepSiper Enthea: https://github.com/8b-is/deepsiper-enthea
  - Parallel git worktree swarms with strict AST validation and multi-model consensus.

• Classroom SOTA Consensus Distillation:
  - Hugging Face Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
  - Geometric-mean logit consensus distillation for compact 1.7B edge models.

• Research Monograph:
  - Axiom Quant: https://axiomquant.org (19-chapter quantitative monograph)
  - Pocoo Kernel: https://pocoo.vaked.dev (Python AST & runtime compilation)

================================================================================
ENGAGEMENT FORMATS
================================================================================
• B2B Research & Systems Engineering Contracts
• Custom Model Distillation & Serving Infrastructure
• Agent Harness Architecture & Benchmark Suites

• Hub: https://peterl.dev · https://vaked.dev · https://axiomquant.org
• GitHub: https://github.com/peterlodri-sec · https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Telegram: @p3t3r_l
• Email: cabotage@pm.me

Looking forward to exploring how we can support high-performance model deployments and agent systems!

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | https://peterl.dev
"""
    },
    {
        "name": "Together AI (Engineering & Partnerships)",
        "to": ["support@together.ai"],
        "subject": "B2B / Contract: Sovereign Agent Swarms, Distillation & Rust Inference — Péter Lodri",
        "body": """Hi Together AI Team,

I'm reaching out regarding B2B contract consulting, advisory, and fractional research engineering in bleeding-edge AI systems.

Operating as an independent "edge digital nomad" team (MacBook + 5G iPhone workflow), we design, build, and deploy production multi-agent harnesses, consensus distillation pipelines, and low-level inference runtimes.

================================================================================
WHAT WE BRING TO THE TABLE
================================================================================
1. High-Performance Multi-Agent Swarms (DeepSiper Enthea):
   https://github.com/8b-is/deepsiper-enthea
   Coordinating parallel LLM agents in isolated git worktrees with strict AST-level validation and multi-model consensus.

2. Token Compression & High-Throughput Serving:
   - KOMPRESS Paper: https://kompress.vaked.dev/paper/main.pdf
   - Rust-based low-latency inference pipelines (zero-GIL, Candle, PyTorch C++ bindings).

3. Waldorf Consensus Distillation:
   - Hugging Face Model: https://huggingface.co/PeetPedro/quantal-classroom-1.6
   - Distilling 1.7B edge student models from frontier teacher councils via geometric-mean softmax logit consensus.

4. Quantitative Research:
   https://axiomquant.org (19 chapters on spectral rigidity, stochastic calculus & random matrix theory).

================================================================================
SERVICES & COLLABORATION
================================================================================
• Fractional Research Engineer / Systems Architect
• Bespoke Agent Evaluation Harnesses & Benchmarking
• Custom Model Distillation on Open-Weights
• High-Performance Inference Optimization

• Portals: https://peterl.dev · https://vaked.dev · https://axiomquant.org
• GitHub: https://github.com/peterlodri-sec · https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Telegram: @p3t3r_l
• Email: cabotage@pm.me

Let's connect if you have technical initiatives where high-velocity, sovereign AI engineering can deliver immediate impact!

Best regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | https://peterl.dev
"""
    }
]

def send_b2b_outreach():
    config_path = os.path.expanduser("~/.config/proton_bridge.txt")
    if not os.path.exists(config_path):
        print(f"Error: Password file not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        password = f.read().strip()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"Connecting to Proton Mail Bridge at 127.0.0.1:1025 to send {len(B2B_TARGETS)} B2B proposals...")
    
    with smtplib.SMTP_SSL("127.0.0.1", 1025, context=ctx, timeout=30) as server:
        server.login(SENDER, password)
        
        for idx, target in enumerate(B2B_TARGETS, 1):
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

            print(f"[{idx}/{len(B2B_TARGETS)}] Sending B2B proposal to {name} ({', '.join(to_addrs)})...")
            try:
                server.send_message(msg, from_addr=SENDER, to_addrs=to_addrs)
                print(f"  ✓ Successfully sent to {name}!")
            except Exception as e:
                print(f"  ✗ Failed to send to {name}: {e}", file=sys.stderr)
            
            time.sleep(2)

    print("\n✓ All B2B consulting proposals dispatched successfully via Proton Mail Bridge!")

if __name__ == "__main__":
    send_b2b_outreach()
