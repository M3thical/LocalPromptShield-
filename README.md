# LocalPromptShield

A fully local, multi-layered **Prompt Injection Firewall** for PDF documents.
Detects and blocks Indirect Prompt Injection (IPI) attacks embedded in PDF files
using a three-stage sequential detection pipeline. All inference runs locally via
Ollama — zero cloud APIs, zero external network calls outside localhost.

> **Academic context:** CYSC 4500 Capstone — Inter-American University of Puerto Rico,
> Bayamón Campus, Spring 2026.

---

## What It Does

Attackers can embed hidden instructions inside PDF documents — resume files, reports,
contracts — that hijack AI systems processing them. LocalPromptShield scans every
chunk of every PDF through three detection layers before any AI model ever sees the
content:

1. **Regex Pre-filter** — 44 compiled patterns catch overt injections in under 1ms with zero VRAM
2. **Sentry (Qwen 2.5 0.5B)** — fast syntactic scanner flags suspicious language
3. **Auditor (llama3.2:3b)** — semantic judge with final verdict authority

Any chunk that passes the regex filter goes through both LLM stages. The Auditor
has exclusive authority over the final verdict — if even one chunk is BLOCKED,
the entire document is BLOCKED. All chunks are always scanned; there is no early exit.

---

## Architecture

```
PDF Input → [pdf_extractor.py] → Plain Text
                 3-tier extraction per page:
                 1. pdfplumber (primary)
                 2. pypdf (fallback)
                 3. pdfminer.six (encoding fallback)
                                      ↓
                         [chunk_by_sentences()]
                          Sentence-aware splitting
                          CHUNK_MAX_CHARS=2000, SENTENCE_OVERLAP=50
                                      ↓ (per chunk — ALL chunks always scanned)
                              [regex_scan()]         <1ms, zero VRAM
                               44 compiled IPI patterns
                               Match → BLOCKED (Sentry+Auditor skipped)
                                      ↓ (if no regex match)
                              [Sentry — Qwen 2.5 0.5B]
                               Fast syntactic scan — advisory only
                                      ↓
                              [Auditor — llama3.2:3b]
                               CLEAN or THREAT + one-sentence reason
                               ← FINAL VERDICT AUTHORITY
                                      ↓ (if THREAT and category unknown)
                              [auditor_classify()]
                               6-category attack taxonomy label
                    Aggregate: ANY chunk BLOCKED → document BLOCKED
                               ALL chunks CLEAN  → document CLEAN
```

---

## Attack Categories Detected

| Category | Description |
|---|---|
| `instruction_override` | Directs the AI to ignore or replace its instructions |
| `role_hijack` | Commands the AI to adopt a different persona or identity |
| `system_prompt_exfiltration` | Attempts to extract the AI's system prompt or secrets |
| `safety_bypass` | Tries to disable safety guidelines or filters |
| `indirect_embedded_instruction` | Instruction hidden inside otherwise normal content |
| `obfuscated_instruction` | Payload disguised via encoding, spacing, or Unicode tricks |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Local LLM runtime | [Ollama](https://ollama.com/) |
| Fast scanner | Qwen 2.5 0.5B (`qwen2.5:0.5b`) |
| Semantic judge | Llama 3.2 3B (`llama3.2:3b`) |
| PDF extraction | pdfplumber · pypdf · pdfminer.six |
| Backend API | FastAPI + Uvicorn |
| Frontend | React 18 + Vite |
| LLM interface | langchain-ollama |

---

## Hardware Requirements

| Component | Minimum | Tested On |
|---|---|---|
| GPU VRAM | 6 GB | NVIDIA RTX 2070 Max-Q (8 GB) |
| RAM | 8 GB | 16 GB |
| OS | Windows / Linux / macOS | Windows 10 |
| Python | 3.10+ | 3.12.9 |
| Node.js | 18+ | — |

Both models must fit in VRAM simultaneously. Qwen 0.5B (~0.4 GB) and Llama 3.2 3B
(~2.0 GB) together use roughly 2.5 GB VRAM at Q4 quantization.

---

## Prerequisites

Install these before anything else:

1. **Ollama** — https://ollama.com/download
2. **Python 3.10+** — https://python.org
3. **Node.js 18+** — https://nodejs.org

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/localpromptshield.git
cd localpromptshield
```

### 2. Pull the required models

```bash
ollama pull llama3.2:3b
ollama pull qwen2.5:0.5b
```

### 3. Install Python dependencies

```bash
pip install -r requirements_4b.txt
pip install pdfminer.six
```

### 4. Install frontend dependencies

```bash
cd frontend
npm install
cd ..
```

---

## Running the Application

Open **three terminals** from the project root:

**Terminal 1 — Ollama (must start first)**
```bash
ollama serve
```

**Terminal 2 — FastAPI backend**
```bash
uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 3 — React frontend**
```bash
cd frontend
npm run dev
```

Then open your browser at **http://localhost:5173**
