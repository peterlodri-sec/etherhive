#!/usr/bin/env python3
"""
Send independent AI researcher outreach emails to grant programs and compute providers
via Proton Mail Bridge (127.0.0.1:1025).
"""

import os
import smtplib
import ssl
import sys
import time
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid

SENDER = "cabotage@pm.me"

OUTREACH_TARGETS = [
    {
        "name": "Emergent Ventures (Tyler Cowen)",
        "to": ["tcowen@gmu.edu", "emergentventures@mercatus.gmu.edu"],
        "subject": "Emergent Ventures Application: Sovereign Multi-Agent Harnesses & Axiom Quant Monograph — Péter Lodri",
        "body": """Dear Tyler and the Emergent Ventures Team,

I am writing to submit an application and introduction for an Emergent Ventures grant as an independent AI researcher and systems architect.

I operate as a high-velocity "edge digital nomad" — architecting, building, and deploying sovereign AI systems, mathematical monographs, and distributed agent swarms entirely from a 5G iPhone and a MacBook across the trails and edges of Europe.

================================================================================
1. CORE INVENTIONS & ZERO-TO-ONE WORK
================================================================================
• AXIOM QUANT (https://axiomquant.org):
  An open-access 19-chapter quantitative monograph and interactive laboratory exploring spectral rigidity theory, Tracy-Widom distributions, Hawkes self-exciting processes, Erdős-Rényi phase transitions, and stochastic calculus for financial markets.

• DEEPSIPER ENTHEA & ENTHEAI (https://github.com/8b-is/deepsiper-enthea · https://entheai.com):
  A sovereign multi-agent LLM evaluation harness and code generation engine that coordinates parallel reasoning swarms across isolated git worktrees with strict AST verification and multi-model consensus.

• CLASSROOM SOTA TRAINING (https://github.com/8b-is/classroom-sota-training):
  A Waldorf-inspired distillation classroom where lightweight edge models (1.7B) learn from a council of frontier teacher models via geometric-mean softmax logit consensus.

• HONEST-IRC / ETHERHIVE (https://github.com/peterlodri-sec/etherhive · https://etherhive.vaked.dev):
  A post-quantum cryptographic, Double-Ratchet, Kademlia DHT decentralized communication protocol built in pure Rust.

================================================================================
2. THE EDGE DIGITAL NOMAD PHILOSOPHY
================================================================================
I work unencumbered by traditional institutional inertia:
- Ultra-lean, high-cadence execution: Building directly from the terminal, committing zero-friction open-source code and reproducible mathematical artifacts.
- Ternary logic {-1, 0, +1}: Grounded in structural honesty, verifiable compute, and composable intelligence.

================================================================================
3. WHAT AN EMERGENT VENTURES GRANT WOULD ACCELERATE
================================================================================
An EV grant ($10k - $50k) will directly fund GPU compute clusters and API bandwidth to scale our multi-agent worktree evaluation benchmarks across 1M+ token contexts and train open-weights edge student models.

================================================================================
4. ONLINE PRESENCE & REPOSITORIES
================================================================================
• Personal Hub: https://peterl.dev
• Constellation Portal: https://vaked.dev | https://etherhive.vaked.dev
• Research Monograph: https://axiomquant.org
• GitHub: https://github.com/peterlodri-sec | https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Telegram: @p3t3r_l
• Email: cabotage@pm.me

I would be thrilled to discuss this work and explore how Emergent Ventures can partner with our constellation.

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
        "name": "AI Grant Team (Nat Friedman & Daniel Gross)",
        "to": ["contact@aigrant.org"],
        "subject": "AI Grant (Open-Source Track) Inquiry: DeepSiper Enthea, Axiom Quant & Sovereign Multi-Agent Systems — Péter Lodri",
        "body": """Dear Nat, Daniel, and the AI Grant Team,

I am reaching out regarding the AI Grant open-source research program to share our latest work on sovereign multi-agent harnesses, mathematical finance monographs, and edge model distillation.

I operate as an "edge digital nomad" — shipping production code and research from a 5G iPhone and MacBook with extreme agility and zero institutional overhead.

================================================================================
HIGHLIGHTS OF WHAT WE ARE BUILDING
================================================================================
1. DeepSiper Enthea (https://github.com/8b-is/deepsiper-enthea):
   Multi-agent reasoning and evaluation harness managing parallel coder swarms across isolated git worktrees with strict AST verification and multi-model consensus.

2. Axiom Quant (https://axiomquant.org):
   An open-access 19-chapter quantitative research monograph and interactive lab covering spectral rigidity, Hawkes processes, and stochastic PDE solvers.

3. Classroom SOTA Training (https://github.com/8b-is/classroom-sota-training):
   Waldorf geometric-mean consensus distillation training 1.7B edge models from frontier teacher councils.

4. Honest-IRC / Etherhive (https://github.com/peterlodri-sec/etherhive):
   Post-quantum cryptographic Double Ratchet (ML-KEM-768 / Dilithium) and Kademlia DHT peer discovery network.

================================================================================
WHAT WE ARE SEEKING
================================================================================
We are applying for an open-source non-dilutive grant / compute credits ($5,000–$50,000) to power:
- Distributed worktree benchmark runs over 1M+ token context windows.
- Pre-training and distillation runs for our open-weights edge model series.

================================================================================
ONLINE PRESENCE & CODE
================================================================================
• Personal Hub: https://peterl.dev
• Constellation Portal: https://vaked.dev | https://etherhive.vaked.dev
• Research: https://axiomquant.org
• GitHub: https://github.com/peterlodri-sec | https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Telegram: @p3t3r_l
• Email: cabotage@pm.me

Looking forward to hearing from you and sharing more technical benchmarks!

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
        "name": "Modal Labs (Research & Academic Compute)",
        "to": ["support@modal.com", "academic@modal.com"],
        "subject": "Modal Research Compute Grant Inquiry: Parallel Multi-Agent Worktree Swarms — Péter Lodri",
        "body": """Dear Modal Team,

I am reaching out to inquire about research compute credits and academic/independent researcher grants on Modal.

We build sovereign AI systems as an "edge digital nomad" lab (operating from a 5G iPhone and MacBook), relying heavily on serverless "code-as-infrastructure" to run parallel experiments at scale.

================================================================================
CORE USE CASE FOR MODAL
================================================================================
• DeepSiper Enthea (https://github.com/8b-is/deepsiper-enthea):
  We orchestrate parallel multi-agent swarms operating in isolated git worktrees. Modal is the ideal execution engine for spinning up hundreds of ephemeral containerized evaluation environments to benchmark multi-agent consensus, AST validations, and code mutations concurrently.

• Classroom SOTA Distillation (https://github.com/8b-is/classroom-sota-training):
  Running multi-teacher logit evaluation and geometric-mean consensus distillation jobs on demand without idle server overhead.

• Research Portals:
  - Axiom Quant: https://axiomquant.org
  - Constellation: https://vaked.dev | https://etherhive.vaked.dev
  - Personal: https://peterl.dev
  - GitHub: https://github.com/peterlodri-sec | https://github.com/8b-is
  - Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)

We would love to apply for Modal research credits ($5k–$10k) to benchmark our serverless agent workflows and publish reproducible case studies and open-source recipes.

Thank you for your consideration!

Best regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | Telegram: @p3t3r_l
"""
    },
    {
        "name": "Together AI (Research & Open-Source Team)",
        "to": ["research@together.ai", "support@together.ai"],
        "subject": "Together AI Open-Source Research Compute Inquiry: Consensus Distillation & Multi-Agent Swarms — Péter Lodri",
        "body": """Dear Together AI Research Team,

I am writing to express our interest in the Together AI Research & Open Source compute grant program.

We are an independent research lab operating on an "edge digital nomad" model (MacBook + 5G iPhone workflow), focused on open-weights model distillation, multi-agent evaluation harnesses, and mathematical modeling.

================================================================================
HOW WE PLAN TO USE TOGETHER AI
================================================================================
1. Multi-Agent Worktree Evaluation (https://github.com/8b-is/deepsiper-enthea):
   Using Together AI's fast serverless endpoints (Llama-3, Qwen-2.5/3, DeepSeek) for multi-model consensus voting and AST code generation swarms.

2. Waldorf Consensus Distillation (https://github.com/8b-is/classroom-sota-training):
   Distilling frontier teacher ensembles into lightweight 1.7B edge student models via geometric-mean logit consensus on dedicated fine-tuning clusters.

3. Online Footprint & Open Source Repositories:
   - Hub: https://peterl.dev · https://vaked.dev
   - Mathematical Monograph: https://axiomquant.org
   - GitHub: https://github.com/peterlodri-sec · https://github.com/8b-is
   - Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)

We would welcome the opportunity to receive research credits / partner with Together AI to accelerate open-source AI evaluation and lightweight edge model development.

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | Telegram: @p3t3r_l
"""
    },
    {
        "name": "Hugging Face (Open Science & Compute Grants)",
        "to": ["open-source@huggingface.co"],
        "subject": "Hugging Face Community Compute Grant / Fellowship Inquiry: Sovereign Multi-Agent & Distillation Harnesses — Péter Lodri",
        "body": """Dear Hugging Face Team,

I am reaching out to inquire about Hugging Face Community Compute Grants, persistent ZeroGPU Spaces allocations, and Fellowship nominations for our open-source research constellation.

We operate as an agile "edge digital nomad" team (5G iPhone + MacBook setup), releasing open-source code, mathematical monographs, and lightweight model distillation pipelines.

================================================================================
KEY OPEN-SOURCE CONTRIBUTIONS & ARTIFACTS
================================================================================
1. DeepSiper Enthea (https://github.com/8b-is/deepsiper-enthea):
   Autonomous multi-agent LLM evaluation and parallel worktree coding harness with strict AST validation.

2. Axiom Quant (https://axiomquant.org):
   19-chapter open research monograph exploring spectral rigidity, Hawkes stochastic processes, and financial mathematics.

3. Classroom SOTA Training (https://github.com/8b-is/classroom-sota-training):
   Waldorf geometric-mean consensus distillation datasets and training scripts for compact 1.7B edge models.

4. Honest-IRC / Etherhive (https://github.com/peterlodri-sec/etherhive):
   Pure Rust post-quantum cryptographic Double Ratchet and Kademlia DHT decentralized network.

================================================================================
PRESENCE & LINKS
================================================================================
• Personal Hub: https://peterl.dev
• Constellation: https://vaked.dev | https://etherhive.vaked.dev
• GitHub: https://github.com/peterlodri-sec | https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Telegram: @p3t3r_l
• Email: cabotage@pm.me

We would love to host interactive Spaces demos, benchmark leaderboards, and dataset artifacts on Hugging Face with dedicated ZeroGPU / compute backing.

Thank you for everything Hugging Face does to democratize open AI!

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | https://peterl.dev
"""
    },
    {
        "name": "Google TPU Research Cloud (TRC Team)",
        "to": ["tpu-research-cloud@google.com"],
        "subject": "Google TRC Inquiry: Independent Open-Source Distillation & Multi-Agent Research — Péter Lodri",
        "body": """Dear Google TPU Research Cloud Team,

I am writing to express our interest in participating in the Google TPU Research Cloud (TRC) program as an independent AI researcher and open-source systems architect.

We build sovereign AI systems with a lean "edge digital nomad" setup (5G iPhone + MacBook), publishing open-source software, mathematical research, and neural distillation recipes.

================================================================================
RESEARCH OBJECTIVES WITH CLOUD TPUS
================================================================================
1. Waldorf Consensus Distillation (https://github.com/8b-is/classroom-sota-training):
   We are training compact, highly-capable 1.7B edge language models using geometric-mean softmax logit consensus from multi-model teacher councils. Cloud TPU v4/v5e pods provide the perfect tensor parallelism for our large batch matrix multiplications.

2. Axiom Quant Mathematical Modeling (https://axiomquant.org):
   Simulating large-scale random matrix ensembles (Tracy-Widom distributions) and spectral rigidity properties in high-dimensional stochastic processes.

3. DeepSiper Enthea (https://github.com/8b-is/deepsiper-enthea):
   Multi-agent AST evaluation and automated benchmark generation.

================================================================================
OPEN SCIENCE COMMITMENT & LINKS
================================================================================
In accordance with TRC guidelines, all model weights, distillation scripts, and mathematical findings will be made 100% open source:
• Personal Hub: https://peterl.dev
• Constellation: https://vaked.dev | https://axiomquant.org
• GitHub: https://github.com/peterlodri-sec | https://github.com/8b-is
• Bluesky: https://bsky.app/profile/0xp3t3rl.bsky.social (@0xp3t3rl.bsky.social)
• Email: cabotage@pm.me

We would be deeply grateful for the opportunity to join the TRC program and leverage Cloud TPUs for our open-source research.

Warm regards,

Péter Lodri
Lead Architect, 8b.is / Lovetta Lane Constellation
cabotage@pm.me | https://peterl.dev
"""
    }
]

def send_all_outreach():
    config_path = os.path.expanduser("~/.config/proton_bridge.txt")
    if not os.path.exists(config_path):
        print(f"Error: Password file not found at {config_path}", file=sys.stderr)
        sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        password = f.read().strip()

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    print(f"Connecting to Proton Mail Bridge at 127.0.0.1:1025 to send {len(OUTREACH_TARGETS)} outreach emails...")
    
    with smtplib.SMTP_SSL("127.0.0.1", 1025, context=ctx, timeout=30) as server:
        server.login(SENDER, password)
        
        for idx, target in enumerate(OUTREACH_TARGETS, 1):
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

            print(f"[{idx}/{len(OUTREACH_TARGETS)}] Sending outreach to {name} ({', '.join(to_addrs)})...")
            try:
                server.send_message(msg, from_addr=SENDER, to_addrs=to_addrs)
                print(f"  ✓ Successfully sent to {name}!")
            except Exception as e:
                print(f"  ✗ Failed to send to {name}: {e}", file=sys.stderr)
            
            time.sleep(2)

    print("\n✓ All outreach emails dispatched successfully via Proton Mail Bridge!")

if __name__ == "__main__":
    send_all_outreach()
