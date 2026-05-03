# ── pdf_extractor.py ─────────────────────────────────────────────────────────
# LocalPromptShield — Phase 4A: PDF Text Extraction
#
# Standalone module. Drop-in replacement for the inline extract_text_from_pdf()
# in test_pipeline_v3.py. All processing is local — zero network calls.
#
# Extraction strategy (per page):
#   1. pdfplumber  (primary  — best layout fidelity for injection detection)
#   2. pypdf       (fallback — lighter, tried when pdfplumber yields < 50 chars)
#   3. pytesseract (optional — OCR for scanned pages, enable_ocr=False by default)
# ─────────────────────────────────────────────────────────────────────────────

# ── Section 1: Imports + optional-dependency guards ───────────────────────────

import json
import logging
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional



import pdfplumber
from pypdf import PdfReader
from pypdf.errors import PdfReadError

# OCR support — commented out (not used in current pipeline)
# try:
#     import pytesseract  # type: ignore
#     from pdf2image import convert_from_path  # type: ignore
#     from pdf2image.exceptions import PDFPageCountError  # type: ignore
#     _OCR_AVAILABLE = True
# except ImportError:
#     _OCR_AVAILABLE = False
_OCR_AVAILABLE = False

# pdfminer.six support — optional Layer 4; silently disabled if not installed
try:
    from pdfminer.high_level import extract_text as pdfminer_extract  # type: ignore
    from pdfminer.layout import LAParams  # type: ignore
    _PDFMINER_AVAILABLE = True
except ImportError:
    _PDFMINER_AVAILABLE = False


# ── Section 2: Logging setup ──────────────────────────────────────────────────
# Identical format to test_pipeline_v3.py so entries land in the same two files.
# Python's logging system deduplicates handler registration — when imported by
# the pipeline (which calls basicConfig first) no double-writes occur.

Path("logs").mkdir(exist_ok=True)

logging.basicConfig(
    filename="logs/security_events.log",
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_module_logger = logging.getLogger("LocalPromptShield")

# Minimum non-whitespace characters required to treat extraction as successful.
# Prevents treating pages full of \n / spaces as having real content.
MIN_CONTENT_CHARS = 20   # for pdfplumber / pypdf / pdfminer
# MIN_OCR_CHARS = 5      # OCR threshold — commented out (OCR disabled)


def _default_emit_log(stage: str, verdict: str, details: str) -> None:
    """
    Fallback log emitter used when no emit_log_fn is passed to the public functions.
    Writes to the same security_events.log and security_events.jsonl files as
    pipeline.py so all extraction events land in one unified log.
    """
    _module_logger.info(f"{stage} | {verdict} | {details}")
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stage": stage,
        "verdict": verdict,
        "details": details,
    }
    with open("logs/security_events.jsonl", "a") as f:
        f.write(json.dumps(event) + "\n")


# ── Section 3: ExtractionResult dataclass ─────────────────────────────────────

@dataclass
class ExtractionResult:
    """Rich metadata carrier used internally and by extract_text_from_pdf_detailed()."""
    text: str
    page_count: int
    char_count: int
    extraction_method: str          # "pdfplumber" | "pypdf" | "ocr" | "mixed"
    ocr_used: bool
    pages_with_text: int
    warnings: list = field(default_factory=list)
    extractors_tried: list = field(default_factory=list)


# ── Section 4: Internal helpers ───────────────────────────────────────────────

def _clean_text(raw: str) -> str:
    """
    Normalize extracted text for injection detection.
    Preserves newlines (structurally meaningful) while removing
    invisible/adversarial characters attackers use to hide injections.
    """
    # 1. Remove null bytes
    text = raw.replace('\x00', '')

    # 2. Unicode NFC normalization (handles composed vs decomposed chars)
    text = unicodedata.normalize('NFC', text)

    # 3. Strip Unicode control characters except \n and \t.
    # Attackers embed control characters between keyword letters (e.g. inserting
    # a soft-hyphen inside "ignore") so the word reads normally to a human but
    # defeats simple string matching. Stripping them before the pipeline sees
    # the text removes this evasion vector. Zero-width chars (U+200B, etc.) are
    # handled separately by strip_zero_width() in pipeline.py before each chunk
    # is scanned, providing a second layer of invisible-character defence.
    text = ''.join(
        ch for ch in text
        if unicodedata.category(ch) != 'Cc' or ch in ('\n', '\t')
    )

    # 4. Collapse horizontal whitespace within each line + rstrip
    lines = text.split('\n')
    lines = [re.sub(r'[ \t]+', ' ', line).rstrip() for line in lines]
    text = '\n'.join(lines)

    # 5. Collapse 3+ consecutive blank lines to 2
    text = re.sub(r'\n{3,}', '\n\n', text)

    return text.strip()


def _extract_page_pdfplumber(page: Any) -> str:
    """Extract text from a single pdfplumber page object."""
    text = page.extract_text()
    return text if text else ""


def _extract_page_pypdf(page: Any) -> str:
    """Extract text from a single pypdf PageObject."""
    try:
        text = page.extract_text()
        return text if text else ""
    except Exception:
        return ""


def _extract_page_pdfminer(pdf_path: str, page_index: int) -> str:
    """
    Extract text from a single page using pdfminer.six.
    Handles non-standard fonts and CID encodings that pdfplumber/pypdf miss.
    Returns empty string if pdfminer is not installed or on any failure.
    """
    if not _PDFMINER_AVAILABLE:
        return ""
    try:
        laparams = LAParams(line_margin=0.5)
        text = pdfminer_extract(
            pdf_path,
            page_numbers=[page_index],
            laparams=laparams,
        )
        return text if text else ""
    except Exception:
        return ""


# def _page_has_images(page) -> bool:
#     """Heuristic: does this pdfplumber page contain image objects?"""
#     try:
#         return len(page.images) > 0
#     except Exception:
#         return False


# def _ocr_page(pdf_path: str, page_index: int) -> str:
#     """Render a single page to an image and run pytesseract OCR on it."""
#     if not _OCR_AVAILABLE:
#         return ""
#     try:
#         images = convert_from_path(
#             pdf_path,
#             first_page=page_index + 1,
#             last_page=page_index + 1,
#             dpi=300,
#         )
#         if not images:
#             return ""
#         return pytesseract.image_to_string(images[0], lang='eng')
#     except Exception:
#         return ""


def _extract_full(
    pdf_path: str,
    enable_ocr: bool,
    emit_log: Callable[[str, str, str], None],
) -> ExtractionResult:
    """
    Core multi-tier extraction engine. Tries pdfplumber first, then pypdf,
    then pdfminer on a per-page basis whenever a page falls below the
    MIN_CONTENT_CHARS threshold.

    Why multiple libraries: no single PDF library handles every encoding
    correctly. pdfplumber gives the best layout fidelity for standard PDFs.
    pypdf handles some encodings pdfplumber misses. pdfminer recovers text
    from non-standard fonts and CID encodings that both miss. Using all three
    maximises the text surface available for injection scanning — a PDF that
    appears blank to one library may contain a hidden injection payload that
    is readable by another.

    Never raises — all exceptions produce an ExtractionResult with empty
    text and a populated warnings list so the caller can distinguish a clean
    "no text found" from an error without try/except at every call site.
    """
    path = Path(pdf_path)

    # ── Tier 1: file not found ────────────────────────────────────────────────
    if not path.exists():
        emit_log("PDF_EXTRACTION", "ERROR", f"File not found: {pdf_path}")
        print(f"   ❌ Error: File not found - {pdf_path}")
        return ExtractionResult("", 0, 0, "none", False, 0)

    page_texts: list[str] = []
    page_count = 0
    method = "pdfplumber"
    ocr_used = False
    warnings: list[str] = []
    extractors_tried: list[str] = []

    # ── Primary pass: pdfplumber ──────────────────────────────────────────────
    extractors_tried.append("pdfplumber")
    try:
        with pdfplumber.open(str(path)) as pdf:
            page_count = len(pdf.pages)
            print(f"   📄 PDF detected: {page_count} pages")
            print(f"   📤 Extracting text from PDF...")

            # Check for encryption flags — but do NOT block here.
            # permissions-only encrypted PDFs are readable even though
            # pdf.doc.encryption is set. Only truly password-locked PDFs
            # will produce empty text on extract_text(), which the
            # threshold check at the end will catch.
            if getattr(pdf.doc, 'encryption', None):
                warnings.append("PDF has encryption flags (may be permissions-only, attempting extraction)")
                emit_log("PDF_EXTRACTION", "WARNING",
                         f"PDF has encryption flags, attempting extraction anyway: {pdf_path}")

            for i, page in enumerate(pdf.pages):
                page_text = _extract_page_pdfplumber(page)
                page_non_ws = sum(1 for c in page_text if not c.isspace())

                emit_log("PDF_EXTRACTION", "DEBUG",
                         f"Page {i+1}/{page_count}: pdfplumber={len(page_text)} chars "
                         f"({page_non_ws} non-ws)")

                if page_non_ws < MIN_CONTENT_CHARS:
                    # Fallback 1: pypdf
                    try:
                        if "pypdf" not in extractors_tried:
                            extractors_tried.append("pypdf")
                        pypdf_reader = PdfReader(str(path))
                        pypdf_text = _extract_page_pypdf(pypdf_reader.pages[i])
                        pypdf_non_ws = sum(1 for c in pypdf_text if not c.isspace())
                        emit_log("PDF_EXTRACTION", "DEBUG",
                                 f"Page {i+1}/{page_count}: pypdf fallback={len(pypdf_text)} chars "
                                 f"({pypdf_non_ws} non-ws)")
                        if pypdf_non_ws >= MIN_CONTENT_CHARS:
                            page_texts.append(pypdf_text)
                            if method == "pdfplumber":
                                method = "mixed"
                            continue
                    except Exception:
                        pass

                    # Fallback 2: pdfminer (handles non-standard fonts / CID encodings)
                    if _PDFMINER_AVAILABLE:
                        if "pdfminer" not in extractors_tried:
                            extractors_tried.append("pdfminer")
                        pdfminer_text = _extract_page_pdfminer(str(path), i)
                        pdfminer_non_ws = sum(1 for c in pdfminer_text if not c.isspace())
                        emit_log("PDF_EXTRACTION", "DEBUG",
                                 f"Page {i+1}/{page_count}: pdfminer fallback={len(pdfminer_text)} chars "
                                 f"({pdfminer_non_ws} non-ws)")
                        if pdfminer_non_ws >= MIN_CONTENT_CHARS:
                            page_texts.append(pdfminer_text)
                            if method == "pdfplumber":
                                method = "mixed"
                            continue

                    # Fallback 3: OCR — commented out
                    # if enable_ocr and _OCR_AVAILABLE:
                    #     if "ocr" not in extractors_tried:
                    #         extractors_tried.append("ocr")
                    #     ocr_text = _ocr_page(pdf_path, i)
                    #     ocr_non_ws = sum(1 for c in ocr_text if not c.isspace())
                    #     if ocr_non_ws >= MIN_OCR_CHARS:
                    #         page_texts.append(ocr_text)
                    #         ocr_used = True
                    #         if method == "pdfplumber":
                    #             method = "mixed"
                    #         continue

                    # Accept sparse pdfplumber text (may still be useful)
                    if page_text.strip():
                        page_texts.append(page_text)
                else:
                    page_texts.append(page_text)

    # ── Tier 2: encrypted (pypdf detection path) ──────────────────────────────
    except Exception as plumber_err:
        plumber_msg = str(plumber_err)

        # If pdfplumber failed entirely, fall back to a full pypdf pass
        warnings.append(f"pdfplumber failed: {plumber_msg[:120]}")

        if "pypdf" not in extractors_tried:
            extractors_tried.append("pypdf")
        try:
            pypdf_reader = PdfReader(str(path))

            # Check encryption via pypdf
            if pypdf_reader.is_encrypted:
                emit_log("PDF_EXTRACTION", "WARNING", f"PDF is encrypted: {pdf_path}")
                print(f"   ⚠️  Warning: PDF is encrypted — cannot extract text")
                return ExtractionResult("", 0, 0, "none", False, 0, ["encrypted"], extractors_tried)

            page_count = len(pypdf_reader.pages)
            print(f"   📄 PDF detected: {page_count} pages")
            print(f"   📤 Extracting text from PDF... (fallback mode)")
            method = "pypdf"

            for page in pypdf_reader.pages:
                page_text = _extract_page_pypdf(page)
                if page_text.strip():
                    page_texts.append(page_text)

        # ── Tier 3: both extractors failed ───────────────────────────────────
        except PdfReadError as e:
            emit_log("PDF_EXTRACTION", "ERROR", f"Corrupt or unreadable PDF: {str(e)[:120]}")
            print(f"   ❌ Error: PDF is corrupt or unreadable")
            return ExtractionResult("", 0, 0, "none", False, 0, [str(e)], extractors_tried)
        except Exception as e:
            emit_log("PDF_EXTRACTION", "ERROR", f"Extraction failed: {str(e)[:120]}")
            print(f"   ❌ Error extracting PDF: {str(e)[:120]}")
            return ExtractionResult("", 0, 0, "none", False, 0, [str(e)], extractors_tried)

    # ── Assemble result ───────────────────────────────────────────────────────
    raw_text = "\n".join(page_texts)
    clean = _clean_text(raw_text)
    pages_with_text = sum(1 for t in page_texts if t.strip())

    non_ws = sum(1 for c in clean if not c.isspace())
    if non_ws < MIN_CONTENT_CHARS:
        emit_log("PDF_EXTRACTION", "WARNING",
                 f"Insufficient text: {non_ws} non-ws chars (min {MIN_CONTENT_CHARS}) | "
                 f"Tried: {', '.join(extractors_tried)}")
        print(f"   ⚠️  Warning: PDF contains no extractable text")
        return ExtractionResult("", page_count, 0, method, ocr_used, 0, warnings, extractors_tried)

    # Log any non-fatal warnings that accumulated
    for w in warnings:
        emit_log("PDF_EXTRACTION", "WARNING", w)

    emit_log(
        "PDF_EXTRACTION", "SUCCESS",
        f"Extracted {len(clean)} chars ({non_ws} non-ws) from {page_count} pages | "
        f"method: {method} | tried: {', '.join(extractors_tried)}"
    )
    print(f"   ✅ Extraction complete: {len(clean)} characters (method: {method})")

    return ExtractionResult(
        text=clean,
        page_count=page_count,
        char_count=len(clean),
        extraction_method=method,
        ocr_used=ocr_used,
        pages_with_text=pages_with_text,
        warnings=warnings,
        extractors_tried=extractors_tried,
    )


# ── Section 5: Public API ─────────────────────────────────────────────────────

def extract_text_from_pdf(
    pdf_path: str,
    enable_ocr: bool = False,
    emit_log_fn: Optional[Callable[[str, str, str], None]] = None,
) -> str:
    """
    Extract all text from a PDF file.

    Drop-in replacement for the extract_text_from_pdf() function in
    test_pipeline_v3.py. Identical call signature for the base case.

    Parameters
    ----------
    pdf_path : str
        Path to the PDF file. Relative paths resolve from the current
        working directory (run from project root).
    enable_ocr : bool, optional
        If True and pytesseract + pdf2image are available, pages that
        yield < 50 characters are re-processed via local Tesseract OCR.
        Defaults to False — OCR is a large attack surface and adds
        significant latency. Opt in explicitly.
    emit_log_fn : callable, optional
        Logging callback (stage, verdict, details) -> None.
        If None, uses the module's own logger (same files as pipeline).
        Pass the pipeline's emit_log here to share a single log context.

    Returns
    -------
    str
        Extracted and cleaned text, or empty string on any failure.
        Empty string → pipeline skips the document (same as v3 behavior).
    """
    log = emit_log_fn if emit_log_fn is not None else _default_emit_log
    result = _extract_full(pdf_path, enable_ocr, log)
    return result.text


def extract_text_from_pdf_detailed(
    pdf_path: str,
    enable_ocr: bool = False,
    emit_log_fn: Optional[Callable[[str, str, str], None]] = None,
) -> ExtractionResult:
    """
    Same as extract_text_from_pdf() but returns the full ExtractionResult
    dataclass with metadata (page_count, extraction_method, ocr_used, etc.).
    """
    log = emit_log_fn if emit_log_fn is not None else _default_emit_log
    return _extract_full(pdf_path, enable_ocr, log)
