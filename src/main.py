# ── main.py ───────────────────────────────────────────────────────────────────
# LocalPromptShield — Phase 4B: FastAPI Backend
#
# Dependency chain:
#   main.py
#   ├── pipeline.py          (library form of test_pipeline_v3.py)
#   │   └── langchain-ollama → Ollama (localhost:11434)
#   └── pdf_extractor.py     (Phase 4A, PROTECTED)
#       └── pdfplumber / pypdf  (requirements_pdf.txt)
#
# Run from project root:
#   uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import io
import json
import sys
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

# Force UTF-8 stdout/stderr so emoji in pdf_extractor.py print() calls don't
# crash on Windows cp1252 consoles when running under uvicorn.
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

MAX_UPLOAD_BYTES = 50 * 1024 * 1024   # 50 MB — reject files larger than this

# Add src/ to path so 'pipeline' and 'pdf_extractor' resolve correctly
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pipeline import PROJECT_ROOT, emit_log, run_pipeline_chunked  # noqa: E402
from benchmark import run_benchmark_on_dataset  # noqa: E402
from pdf_extractor import extract_text_from_pdf_detailed   # noqa: E402

# ── Constants ──────────────────────────────────────────────────────────────────
UPLOADS_DIR = PROJECT_ROOT / "uploads"
JSONL_FILE  = PROJECT_ROOT / "logs" / "security_events.jsonl"

# ── Async job store ────────────────────────────────────────────────────────────
# In-memory dict: job_id → {status, progress, result, error}
# Jobs are lost on server restart — acceptable for local-only tool.
jobs: dict = {}


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    UPLOADS_DIR.mkdir(exist_ok=True)
    yield


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(title="LocalPromptShield API", version="4B", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Stub request models ────────────────────────────────────────────────────────
class GenerateAttacksRequest(BaseModel):
    target_text: str = ""
    count: int = 5


class BenchmarkRequest(BaseModel):
    dataset: str = "default"


# ── Background worker ─────────────────────────────────────────────────────────

def _run_benchmark_job(job_id: str, dataset_dir: str) -> None:
    """Background worker — runs the full benchmark, updates jobs dict."""
    try:
        jobs[job_id]["status"] = "processing"

        def on_progress(current: int, total: int, filename: str) -> None:
            jobs[job_id]["progress"] = f"scanning document {current} of {total}: {filename}"

        report = run_benchmark_on_dataset(dataset_dir, progress_callback=on_progress)
        jobs[job_id]["status"] = "complete"
        jobs[job_id]["result"] = report
    except Exception as e:
        emit_log("BENCHMARK", "ERROR", f"Benchmark job {job_id} failed: {e}")
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"]  = str(e)


def _run_scan_job(job_id: str, save_path: str, filename: str) -> None:
    """Background worker — runs full extraction + chunked pipeline, updates jobs dict."""
    try:
        jobs[job_id]["status"] = "processing"

        result = extract_text_from_pdf_detailed(
            save_path, enable_ocr=True, emit_log_fn=emit_log,
        )

        if not result.text:
            emit_log("PIPELINE", "UNEXTRACTABLE",
                     f"Case: {filename} | No text extracted | "
                     f"Tried: {', '.join(result.extractors_tried)} | Pages: {result.page_count}")
            jobs[job_id]["status"] = "complete"
            jobs[job_id]["result"] = {
                "error":             "no_text_extracted",
                "status":            "UNEXTRACTABLE",
                "message":           "No text could be extracted from this PDF after trying all methods.",
                "filename":          filename,
                "page_count":        result.page_count,
                "extractors_tried":  result.extractors_tried,
                "sentry":            "N/A",
                "auditor":           "N/A",
                "reason":            "PDF may be image-based (scanned), encrypted, or blank.",
                "char_count":        0,
                "extraction_method": result.extraction_method,
            }
            return

        def on_progress(current: int, total: int) -> None:
            jobs[job_id]["progress"] = f"scanning chunk {current} of {total}"

        verdict = run_pipeline_chunked(
            result.text, case_name=filename, is_pdf=True,
            progress_callback=on_progress,
        )

        jobs[job_id]["status"] = "complete"
        jobs[job_id]["result"] = {
            "status":            verdict["status"],
            "filename":          filename,
            "page_count":        result.page_count,
            "char_count":        result.char_count,
            "chunks_total":      verdict["chunks_total"],
            "chunks_scanned":    verdict["chunks_scanned"],
            "chunks_flagged":    verdict["chunks_flagged"],
            "extraction_method": result.extraction_method,
            "sentry":            verdict["sentry"],
            "auditor":           verdict["auditor"],
            "reason":            verdict["reason"],
            "flagged_chunks":    verdict["flagged_chunks"],
            "scan_time_ms":      verdict["scan_time_ms"],
        }

    except Exception as e:
        emit_log("PIPELINE", "ERROR", f"Job {job_id} failed: {e}")
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"]  = str(e)


# ── Endpoints ──────────────────────────────────────────────────────────────────

@app.post("/scan_pdf")
async def scan_pdf(file: UploadFile = File(...)):
    # Validate file is a PDF
    is_pdf = (
        file.content_type == "application/pdf"
        or (file.filename or "").lower().endswith(".pdf")
    )
    if not is_pdf:
        raise HTTPException(
            status_code=400,
            detail=f"File must be a PDF. Received content-type: {file.content_type}",
        )

    # Save to uploads/ — enforce size limit during chunked read
    save_path = UPLOADS_DIR / (file.filename or "upload.pdf")
    total_bytes = 0
    with open(str(save_path), "wb") as out:
        while chunk := await file.read(1024 * 1024):  # 1 MB chunks
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_BYTES:
                save_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
                )
            out.write(chunk)

    # Extract text — run in thread so event loop stays free for other requests
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: extract_text_from_pdf_detailed(
            str(save_path), enable_ocr=True, emit_log_fn=emit_log,
        ),
    )

    # Problem 1 fix — return structured UNEXTRACTABLE instead of raising 422
    if not result.text:
        emit_log("PIPELINE", "UNEXTRACTABLE",
                 f"Case: {file.filename} | No text extracted | "
                 f"Tried: {', '.join(result.extractors_tried)} | Pages: {result.page_count}")
        return {
            "error":             "no_text_extracted",
            "status":            "UNEXTRACTABLE",
            "message":           "No text could be extracted from this PDF after trying all methods.",
            "filename":          file.filename,
            "page_count":        result.page_count,
            "extractors_tried":  result.extractors_tried,
            "sentry":            "N/A",
            "auditor":           "N/A",
            "reason":            "PDF may be image-based (scanned), encrypted, or blank.",
            "char_count":        0,
            "extraction_method": result.extraction_method,
        }

    # Run chunked pipeline — scans every part of the document, no truncation
    filename = file.filename or "upload.pdf"
    verdict = await loop.run_in_executor(
        None,
        lambda: run_pipeline_chunked(
            result.text, case_name=filename, is_pdf=True,
        ),
    )

    return {
        "status":            verdict["status"],
        "filename":          file.filename,
        "page_count":        result.page_count,
        "char_count":        result.char_count,
        "chunks_total":      verdict["chunks_total"],
        "chunks_scanned":    verdict["chunks_scanned"],
        "chunks_flagged":    verdict["chunks_flagged"],
        "extraction_method": result.extraction_method,
        "sentry":            verdict["sentry"],
        "auditor":           verdict["auditor"],
        "reason":            verdict["reason"],
        "flagged_chunks":    verdict["flagged_chunks"],
        "scan_time_ms":      verdict["scan_time_ms"],
    }


@app.post("/scan_pdf_async", status_code=202)
async def scan_pdf_async(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    is_pdf = (
        file.content_type == "application/pdf"
        or (file.filename or "").lower().endswith(".pdf")
    )
    if not is_pdf:
        raise HTTPException(
            status_code=400,
            detail=f"File must be a PDF. Received content-type: {file.content_type}",
        )

    job_id    = str(uuid.uuid4())
    filename  = file.filename or "upload.pdf"
    save_path = UPLOADS_DIR / f"{job_id}_{filename}"

    total_bytes = 0
    with open(str(save_path), "wb") as out:
        while chunk := await file.read(1024 * 1024):
            total_bytes += len(chunk)
            if total_bytes > MAX_UPLOAD_BYTES:
                save_path.unlink(missing_ok=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Maximum allowed size is {MAX_UPLOAD_BYTES // (1024*1024)} MB.",
                )
            out.write(chunk)

    jobs[job_id] = {"status": "queued", "progress": "0/0", "result": None, "error": None}
    background_tasks.add_task(_run_scan_job, job_id, str(save_path), filename)

    return {
        "job_id":  job_id,
        "status":  "queued",
        "message": f"Scan started. Poll /scan/{job_id}/status for results.",
    }


@app.get("/scan/{job_id}/status")
async def scan_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")

    job      = jobs[job_id]
    response = {"job_id": job_id, "status": job["status"]}

    if job["status"] == "processing":
        response["progress"] = job["progress"]
    elif job["status"] == "complete":
        response["result"] = job["result"]
    elif job["status"] == "failed":
        response["error"] = job["error"]

    return response


@app.post("/generate_attacks")
async def generate_attacks(body: GenerateAttacksRequest = GenerateAttacksRequest()):
    return {
        "status":  "not_implemented",
        "message": "Phase 5 — Attack generation not yet implemented",
        "phase":   "5",
    }


@app.post("/run_benchmark", status_code=202)
async def run_benchmark(
    background_tasks: BackgroundTasks,
    body: BenchmarkRequest = BenchmarkRequest(),
):
    dataset_dir = PROJECT_ROOT / "PDF_Files" / "dataset_V2"
    benign_dir  = dataset_dir / "benign"
    mal_dir     = dataset_dir / "malicious"

    if not benign_dir.is_dir() or not mal_dir.is_dir():
        raise HTTPException(
            status_code=404,
            detail=(
                "Benchmark dataset not found. Expected folders: "
                "PDF_Files/dataset_V2/benign/ and PDF_Files/dataset_V2/malicious/"
            ),
        )

    job_id = str(uuid.uuid4())
    jobs[job_id] = {"status": "queued", "progress": "0/0", "result": None, "error": None}
    background_tasks.add_task(_run_benchmark_job, job_id, str(dataset_dir))

    return {
        "job_id":  job_id,
        "status":  "queued",
        "message": f"Benchmark started. Poll /benchmark/{job_id}/status for results.",
    }


@app.get("/benchmark/{job_id}/status")
async def benchmark_status(job_id: str):
    if job_id not in jobs:
        raise HTTPException(status_code=404, detail=f"Benchmark job {job_id} not found.")

    job      = jobs[job_id]
    response = {"job_id": job_id, "status": job["status"]}

    if job["status"] == "processing":
        response["progress"] = job["progress"]
    elif job["status"] == "complete":
        response["result"] = job["result"]
    elif job["status"] == "failed":
        response["error"] = job["error"]

    return response


@app.get("/metrics")
async def metrics():
    events = []
    if JSONL_FILE.exists():
        with open(str(JSONL_FILE)) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    # Document-level events only — one per scan, not one per chunk
    doc_events = [
        e for e in events
        if e.get("stage") == "DOCUMENT" and e.get("verdict") in ("BLOCKED", "CLEAN")
    ]
    total_scans      = len(doc_events)
    blocked          = sum(1 for e in doc_events if e["verdict"] == "BLOCKED")
    approved         = total_scans - blocked
    block_rate       = round(blocked / total_scans * 100, 1) if total_scans > 0 else 0.0
    regex_catches    = sum(e.get("regex_catches",   0) for e in doc_events)
    auditor_catches  = sum(e.get("auditor_catches", 0) for e in doc_events)
    total_time_ms    = sum(e.get("scan_time_ms",    0) for e in doc_events)
    avg_scan_time_ms = round(total_time_ms / total_scans) if total_scans > 0 else 0

    return {
        "total_scans":       total_scans,
        "blocked":           blocked,
        "approved":          approved,
        "block_rate_pct":    block_rate,
        "regex_catches":     regex_catches,
        "auditor_catches":   auditor_catches,
        "avg_scan_time_ms":  avg_scan_time_ms,
        "last_10_events":    doc_events[-10:],
    }
