# ── benchmark.py ──────────────────────────────────────────────────────────────
# LocalPromptShield — Phase 6: Benchmark Runner
#
# Scans two subfolders (benign/ and malicious/) inside a dataset directory.
# Folder name is the ground-truth label — no labels.json needed.
# Dataset: PDF_Files/dataset_V2  (50 benign + 50 malicious PDFs)
#
# Called by POST /run_benchmark in main.py.
# Can also be run standalone: python src/benchmark.py
# ─────────────────────────────────────────────────────────────────────────────

import json
import math
import re
import statistics
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Allow running standalone from project root
sys.path.insert(0, str(Path(__file__).resolve().parent))

from pdf_extractor import extract_text_from_pdf_detailed
from pipeline import emit_log, run_pipeline_chunked


# ── AV info extraction ────────────────────────────────────────────────────────
# Malicious filenames follow: malicious_NNN_AVXX.pdf
# The AV code is parsed directly from the filename.
# LocalPromptShield's detected attack categories are tracked separately — NOT used here.

_AV_RE = re.compile(r'(AV\d{2})', re.IGNORECASE)


def _extract_av_info(filename: str) -> tuple[str, str]:
    """Return (av_label, av_name), e.g. ('AV01', '')."""
    m = _AV_RE.search(filename)
    if m:
        return m.group(1).upper(), ""
    return "unknown", ""


# ── Result dataclasses ─────────────────────────────────────────────────────────

@dataclass
class DocumentResult:
    filename:            str
    ground_truth:        str   # "CLEAN" or "BLOCKED"
    verdict:             str   # "CLEAN", "BLOCKED", or "UNEXTRACTABLE"
    correct:             bool
    scan_time_ms:        int
    detected_by:         str   # "regex" | "auditor" | "mixed" | "none" | "unextractable"
    category:            str   # "benign" or "malicious"
    # New fields — all have defaults so UNEXTRACTABLE path works without modification
    attack_categories:   list  = field(default_factory=list)  # LocalPromptShield detected categories
    flagged_chunk_count: int   = 0                            # chunks caught by regex or auditor
    av_label:            str   = "unknown"                    # ground-truth AV code, e.g. "AV01"
    av_name:             str   = ""                           # human name, e.g. "HiddenInstruction"


@dataclass
class BenchmarkReport:
    run_timestamp:              str
    dataset_dir:                str
    total_documents:            int
    true_positives:             int    # malicious correctly blocked
    false_positives:            int    # benign wrongly blocked
    true_negatives:             int    # benign correctly passed
    false_negatives:            int    # malicious that slipped through
    detection_rate_pct:         float  # TP / (TP + FN) * 100  — Recall
    false_positive_rate_pct:    float  # FP / (FP + TN) * 100
    accuracy_pct:               float  # (TP + TN) / total * 100
    avg_scan_time_ms:           float
    regex_catches:              int    # chunk-level regex hits across all docs
    auditor_catches:            int    # chunk-level auditor hits across all docs
    per_document:               list  = field(default_factory=list)
    # Classification metrics (16 new fields below, all with defaults)
    precision_pct:              float = 0.0   # TP / (TP + FP) * 100
    f1_score:                   float = 0.0   # harmonic mean of precision and recall
    # Detector breakdown — document-level counts
    sentry_warning_docs:        int   = 0     # docs sentry warned but auditor cleared (not BLOCKED)
    regex_only_docs:            int   = 0     # BLOCKED docs caught exclusively by regex
    auditor_only_docs:          int   = 0     # BLOCKED docs caught exclusively by auditor
    mixed_docs:                 int   = 0     # BLOCKED docs caught by both
    # AV-label breakdown — ground-truth attack vectors from filenames (malicious only).
    # {AV01: {name: "HiddenInstruction", caught: N, missed: N}, ...}
    # Kept entirely separate from LocalPromptShield's detected attack categories.
    attack_vector_breakdown:    dict  = field(default_factory=dict)
    # FP / FN example lists with per-document detector attribution
    false_positive_docs:        list  = field(default_factory=list)
    # [{filename, scan_time_ms, detected_by, attack_categories}]
    false_negative_docs:        list  = field(default_factory=list)
    # [{filename, scan_time_ms, expected_category, expected_av_name}]
    # Performance metrics
    min_scan_time_ms:           float = 0.0
    max_scan_time_ms:           float = 0.0
    median_scan_time_ms:        float = 0.0
    p95_scan_time_ms:           float = 0.0
    throughput_docs_per_min:    float = 0.0
    avg_scan_time_benign_ms:    float = 0.0
    avg_scan_time_malicious_ms: float = 0.0


# ── Runner ─────────────────────────────────────────────────────────────────────

def run_benchmark_on_dataset(
    dataset_dir: str,
    progress_callback=None,
) -> dict:
    """
    Scan all PDFs in dataset_dir/benign/ (ground truth CLEAN) and
    dataset_dir/malicious/ (ground truth BLOCKED).

    progress_callback(current, total, filename) is called before each document.
    Returns a JSON-serializable benchmark report dict.
    """
    dpath      = Path(dataset_dir)
    benign_dir = dpath / "benign"
    mal_dir    = dpath / "malicious"

    if not benign_dir.is_dir() or not mal_dir.is_dir():
        raise FileNotFoundError(
            f"Expected benign/ and malicious/ subfolders inside {dataset_dir}"
        )

    all_docs = (
        [(p, "benign",    "CLEAN")   for p in sorted(benign_dir.glob("*.pdf"))] +
        [(p, "malicious", "BLOCKED") for p in sorted(mal_dir.glob("*.pdf"))]
    )

    if not all_docs:
        raise ValueError("No PDF files found in benign/ or malicious/ subfolders")

    emit_log("BENCHMARK", "START",
             f"Running benchmark on {len(all_docs)} documents in {dataset_dir}")

    results:               list[DocumentResult] = []
    total_time_ms           = 0
    regex_catches           = 0
    auditor_catches         = 0
    sentry_warning_docs     = 0
    regex_only_docs         = 0
    auditor_only_docs       = 0
    mixed_docs              = 0
    attack_vector_breakdown: dict = {}

    for i, (pdf_path, category, ground_truth) in enumerate(all_docs):
        if progress_callback:
            progress_callback(i + 1, len(all_docs), pdf_path.name)

        emit_log("BENCHMARK", "SCANNING",
                 f"Document {i+1}/{len(all_docs)}: {pdf_path.name} | GT: {ground_truth}")

        if category == "malicious":
            av_label, av_name = _extract_av_info(pdf_path.name)
        else:
            av_label, av_name = "N/A", ""

        extraction = extract_text_from_pdf_detailed(
            str(pdf_path), enable_ocr=False, emit_log_fn=emit_log
        )

        if not extraction.text:
            # Record in AV breakdown so per-AV totals stay accurate
            if ground_truth == "BLOCKED":
                if av_label not in attack_vector_breakdown:
                    attack_vector_breakdown[av_label] = {"name": av_name, "caught": 0, "missed": 0}
                attack_vector_breakdown[av_label]["missed"] += 1
            results.append(DocumentResult(
                filename=pdf_path.name,
                ground_truth=ground_truth,
                verdict="UNEXTRACTABLE",
                correct=False,
                scan_time_ms=0,
                detected_by="unextractable",
                category=category,
                av_label=av_label,
                av_name=av_name,
            ))
            emit_log("BENCHMARK", "UNEXTRACTABLE", f"Document: {pdf_path.name}")
            continue

        pr           = run_pipeline_chunked(extraction.text, case_name=pdf_path.name, is_pdf=True)
        verdict      = pr["status"]
        scan_time_ms = pr["scan_time_ms"]
        flagged      = pr.get("flagged_chunks", [])

        # ── Detector type per document ────────────────────────────────────────
        has_regex   = any(c["detected_by"] == "regex"   for c in flagged)
        has_auditor = any(c["detected_by"] == "auditor" for c in flagged)
        has_sentry  = any(c["detected_by"] == "sentry"  for c in flagged)

        if has_regex and has_auditor:
            detected_by = "mixed"
        elif has_regex:
            detected_by = "regex"
        elif has_auditor:
            detected_by = "auditor"
        else:
            detected_by = "none"

        # Sentry-only warning: sentry flagged but auditor cleared; doc is NOT BLOCKED
        if has_sentry and not has_regex and not has_auditor:
            sentry_warning_docs += 1

        # Detector breakdown for BLOCKED docs only
        if verdict == "BLOCKED":
            if has_regex and has_auditor:
                mixed_docs += 1
            elif has_regex:
                regex_only_docs += 1
            elif has_auditor:
                auditor_only_docs += 1

        # ── LocalPromptShield detected categories (pipeline output, separate from AV labels) ──
        doc_categories = list({
            c["attack_category"]
            for c in flagged
            if c.get("detected_by") in ("regex", "auditor")
               and c.get("attack_category")
               and c["attack_category"] not in (None, "unknown")
        })
        flagged_chunk_count = sum(
            1 for c in flagged if c.get("detected_by") in ("regex", "auditor")
        )

        # ── AV-label breakdown (ground-truth, malicious docs only) ────────────
        if ground_truth == "BLOCKED":
            if av_label not in attack_vector_breakdown:
                attack_vector_breakdown[av_label] = {"name": av_name, "caught": 0, "missed": 0}
            if verdict == "BLOCKED":
                attack_vector_breakdown[av_label]["caught"] += 1
            else:
                attack_vector_breakdown[av_label]["missed"] += 1

        regex_catches   += sum(1 for c in flagged if c["detected_by"] == "regex")
        auditor_catches += sum(1 for c in flagged if c["detected_by"] == "auditor")
        total_time_ms   += scan_time_ms

        correct = (verdict == ground_truth)
        results.append(DocumentResult(
            filename=pdf_path.name,
            ground_truth=ground_truth,
            verdict=verdict,
            correct=correct,
            scan_time_ms=scan_time_ms,
            detected_by=detected_by,
            category=category,
            attack_categories=doc_categories,
            flagged_chunk_count=flagged_chunk_count,
            av_label=av_label,
            av_name=av_name,
        ))

        emit_log("BENCHMARK", "CORRECT" if correct else "WRONG",
                 f"Document: {pdf_path.name} | GT: {ground_truth} | Got: {verdict} | "
                 f"Time: {scan_time_ms}ms | By: {detected_by} | AV: {av_label}")

    # ── Confusion matrix counts ────────────────────────────────────────────────
    tp = sum(1 for r in results if r.ground_truth == "BLOCKED" and r.verdict == "BLOCKED")
    fp = sum(1 for r in results if r.ground_truth == "CLEAN"   and r.verdict == "BLOCKED")
    tn = sum(1 for r in results if r.ground_truth == "CLEAN"   and r.verdict != "BLOCKED")
    fn = sum(1 for r in results if r.ground_truth == "BLOCKED" and r.verdict != "BLOCKED")

    total   = len(results)
    dr_pct  = round(tp / (tp + fn) * 100, 1) if (tp + fn) > 0 else 0.0
    fpr_pct = round(fp / (fp + tn) * 100, 1) if (fp + tn) > 0 else 0.0
    acc_pct = round((tp + tn) / total * 100, 1) if total > 0 else 0.0
    avg_t   = round(total_time_ms / total, 1)   if total > 0 else 0.0

    # ── Precision / Recall / F1 ───────────────────────────────────────────────
    precision  = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall     = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1         = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    prec_pct   = round(precision * 100, 1)
    f1_rounded = round(f1, 3)

    # ── FP / FN example lists (with per-document detector attribution) ─────────
    # detected_by is always "regex", "auditor", or "mixed" for BLOCKED docs —
    # "none" only appears on CLEAN docs, so FP attribution is always accurate.
    fp_docs = [
        {
            "filename":          r.filename,
            "scan_time_ms":      r.scan_time_ms,
            "detected_by":       r.detected_by,
            "attack_categories": r.attack_categories,
        }
        for r in results if r.ground_truth == "CLEAN" and r.verdict == "BLOCKED"
    ]
    fn_docs = [
        {
            "filename":          r.filename,
            "scan_time_ms":      r.scan_time_ms,
            "expected_category": r.av_label,
            "expected_av_name":  r.av_name,
        }
        for r in results if r.ground_truth == "BLOCKED" and r.verdict != "BLOCKED"
    ]

    # ── Performance metrics ───────────────────────────────────────────────────
    scan_times = [r.scan_time_ms for r in results if r.scan_time_ms > 0]
    if scan_times:
        n          = len(scan_times)
        sorted_t   = sorted(scan_times)
        min_t      = float(sorted_t[0])
        max_t      = float(sorted_t[-1])
        median_t   = float(statistics.median(scan_times))
        p95_idx    = min(math.ceil(n * 0.95) - 1, n - 1)
        p95_t      = float(sorted_t[p95_idx])
        total_sec  = total_time_ms / 1000.0
        throughput = round(total / total_sec * 60, 1) if total_sec > 0 else 0.0
    else:
        min_t = max_t = median_t = p95_t = throughput = 0.0

    benign_times    = [r.scan_time_ms for r in results if r.category == "benign"    and r.scan_time_ms > 0]
    malicious_times = [r.scan_time_ms for r in results if r.category == "malicious" and r.scan_time_ms > 0]
    avg_benign    = round(sum(benign_times)    / len(benign_times),    1) if benign_times    else 0.0
    avg_malicious = round(sum(malicious_times) / len(malicious_times), 1) if malicious_times else 0.0

    # ── Build report ──────────────────────────────────────────────────────────
    report = BenchmarkReport(
        run_timestamp=datetime.now(timezone.utc).isoformat(),
        dataset_dir=dataset_dir,
        total_documents=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        detection_rate_pct=dr_pct,
        false_positive_rate_pct=fpr_pct,
        accuracy_pct=acc_pct,
        avg_scan_time_ms=avg_t,
        regex_catches=regex_catches,
        auditor_catches=auditor_catches,
        precision_pct=prec_pct,
        f1_score=f1_rounded,
        sentry_warning_docs=sentry_warning_docs,
        regex_only_docs=regex_only_docs,
        auditor_only_docs=auditor_only_docs,
        mixed_docs=mixed_docs,
        attack_vector_breakdown=attack_vector_breakdown,
        false_positive_docs=fp_docs,
        false_negative_docs=fn_docs,
        min_scan_time_ms=round(min_t, 1),
        max_scan_time_ms=round(max_t, 1),
        median_scan_time_ms=round(median_t, 1),
        p95_scan_time_ms=round(p95_t, 1),
        throughput_docs_per_min=throughput,
        avg_scan_time_benign_ms=avg_benign,
        avg_scan_time_malicious_ms=avg_malicious,
        per_document=[asdict(r) for r in results],
    )

    emit_log("BENCHMARK", "COMPLETE",
             f"DR={dr_pct}% | FPR={fpr_pct}% | Accuracy={acc_pct}% | F1={f1_rounded} | "
             f"TP={tp} FP={fp} TN={tn} FN={fn} | AvgTime={avg_t}ms")

    log_dir      = Path(__file__).resolve().parent.parent / "logs"
    results_file = log_dir / "benchmark_results.jsonl"
    with open(str(results_file), "a") as f:
        f.write(json.dumps(asdict(report)) + "\n")

    return asdict(report)


# ── Standalone runner ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    dataset_path = Path(__file__).resolve().parent.parent / "PDF_Files" / "dataset_V2"
    if not dataset_path.exists():
        print(f"ERROR: Dataset not found at {dataset_path}")
        sys.exit(1)

    print("=" * 60)
    print("LocalPromptShield — Benchmark Runner")
    print("=" * 60)
    report = run_benchmark_on_dataset(str(dataset_path))
    print(f"\nResults:")
    print(f"  Total documents    : {report['total_documents']}")
    print(f"  Recall             : {report['detection_rate_pct']}%")
    print(f"  Precision          : {report['precision_pct']}%")
    print(f"  F1 score           : {report['f1_score']}")
    print(f"  False positive rate: {report['false_positive_rate_pct']}%")
    print(f"  Accuracy           : {report['accuracy_pct']}%")
    print(f"  TP={report['true_positives']} FP={report['false_positives']} "
          f"TN={report['true_negatives']} FN={report['false_negatives']}")
    print(f"  Regex catches      : {report['regex_catches']} chunks")
    print(f"  Auditor catches    : {report['auditor_catches']} chunks")
    print(f"  Regex-only docs    : {report['regex_only_docs']}")
    print(f"  Auditor-only docs  : {report['auditor_only_docs']}")
    print(f"  Mixed docs         : {report['mixed_docs']}")
    print(f"  Sentry warnings    : {report['sentry_warning_docs']}")
    print(f"  Avg scan time      : {report['avg_scan_time_ms']} ms")
    print(f"  Min / Median / P95 / Max : {report['min_scan_time_ms']} / "
          f"{report['median_scan_time_ms']} / {report['p95_scan_time_ms']} / "
          f"{report['max_scan_time_ms']} ms")
    print(f"  Throughput         : {report['throughput_docs_per_min']} docs/min")
    avb = report.get("attack_vector_breakdown", {})
    if avb:
        print(f"\n  Attack Vector Breakdown:")
        for av, stats in sorted(avb.items()):
            total_av = stats["caught"] + stats["missed"]
            rate     = stats["caught"] / total_av * 100 if total_av else 0
            print(f"    {av} {stats['name']}: {stats['caught']}/{total_av} caught ({rate:.0f}%)")
    print("=" * 60)
