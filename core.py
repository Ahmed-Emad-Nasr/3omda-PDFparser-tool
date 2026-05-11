# PDF Malware Analysis Toolkit
# Author: Ahmed Emad Nasr
# GitHub-ready project release

import re
import zlib
import os
from collections import Counter


def extract_metadata(pdf_path):
    meta = {}
    try:
        with open(pdf_path, "rb") as f:
            data = f.read().decode("latin1", errors="ignore")

        for key in ["Author", "Creator", "Producer", "CreationDate"]:
            m = re.search(rf"/{key}\s*\((.*?)\)", data)
            meta[key] = m.group(1) if m else "Unknown"
    except:
        meta = {"Status": "Metadata extraction failed"}

    return meta


def enumerate_objects(pdf_text):
    objects = re.findall(r"(\d+)\s+\d+\s+obj", pdf_text)
    streams = re.findall(r"(\d+)\s+\d+\s+obj.*?stream", pdf_text, re.DOTALL)
    embedded = re.findall(r"(\d+)\s+\d+\s+obj.*?/EmbeddedFile", pdf_text, re.DOTALL)
    return list(set(objects)), list(set(streams)), list(set(embedded))


def extract_streams(pdf_text):
    stream_contents = []
    for match in re.finditer(r"stream(.*?)endstream", pdf_text, re.DOTALL):
        raw = match.group(1).strip().encode("latin1", errors="ignore")
        try:
            decoded = zlib.decompress(raw).decode("latin1", errors="ignore")
        except:
            decoded = raw.decode("latin1", errors="ignore")
        stream_contents.append(decoded)
    return "\n".join(stream_contents)


def extract_embedded_files(pdf_text, output_dir="extracted_files"):
    os.makedirs(output_dir, exist_ok=True)
    count = 0

    for match in re.finditer(r"stream(.*?)endstream", pdf_text, re.DOTALL):
        raw = match.group(1).strip().encode("latin1", errors="ignore")

        try:
            data = zlib.decompress(raw)
        except:
            data = raw

        # crude check for file signatures
        if data.startswith(b"MZ") or data.startswith(b"%PDF") or len(data) > 500:
            fname = os.path.join(output_dir, f"embedded_{count}.bin")
            with open(fname, "wb") as f:
                f.write(data)
            count += 1

    return count


def keyword_scan(text):
    keys = {
        "/JS": text.count("/JS"),
        "/JavaScript": text.count("/JavaScript"),
        "/OpenAction": text.count("/OpenAction"),
        "/AA": text.count("/AA"),
        "/EmbeddedFile": text.count("/EmbeddedFile"),
        "/URI": text.count("/URI"),
    }
    return keys


def malware_scan(text):
    findings = []
    patterns = {
        "eval() usage": r"eval\s*\(",
        "unescape() usage": r"unescape\s*\(",
        "Base64 payload": r"[A-Za-z0-9+/]{80,}={0,2}",
        "Hex shellcode": r"(\\x[0-9a-fA-F]{2}){8,}",
        "URL found": r"https?://[^\s]+",
        "IP Address": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    }

    for name, pat in patterns.items():
        if re.search(pat, text, re.IGNORECASE):
            findings.append(name)

    return findings


def extract_text(pdf_input):
    """
    Robust text extraction. `pdf_input` may be a path to a PDF file
    or the raw PDF text content. If PyPDF2 is available and a file
    path is provided, use it for reliable page-level extraction. Falls
    back to the original stream/dictionary parsing when needed.
    """
    # If a file path was provided and exists, try a page-based extractor
    page_text = ""
    if isinstance(pdf_input, str) and os.path.isfile(pdf_input):
        try:
            from PyPDF2 import PdfReader

            reader = PdfReader(pdf_input)
            pages = []
            for page in reader.pages:
                try:
                    text = page.extract_text() or ""
                except Exception:
                    text = ""
                pages.append(text)
            page_text = "\n".join(pages).strip()
        except Exception:
            page_text = ""

        # Load raw file for stream/dictionary parsing as well
        try:
            with open(pdf_input, "rb") as f:
                pdf_text = f.read().decode("latin1", errors="ignore")
        except Exception:
            pdf_text = ""
    else:
        pdf_text = pdf_input or ""

    extracted_text = []

    # Extract text from all streams (both decoded and raw)
    for match in re.finditer(r"stream(.*?)endstream", pdf_text, re.DOTALL):
        raw = match.group(1).strip().encode("latin1", errors="ignore")
        try:
            decoded = zlib.decompress(raw).decode("latin1", errors="ignore")
        except Exception:
            try:
                decoded = raw.decode("latin1", errors="ignore")
            except Exception:
                decoded = ""

        # Extract all hex strings (common in PDFs)
        hex_strings = re.findall(r"<([0-9a-fA-F]+)>", decoded)
        for hex_str in hex_strings:
            try:
                decoded_hex = bytes.fromhex(hex_str).decode("latin1", errors="ignore")
                if decoded_hex.strip():
                    extracted_text.append(decoded_hex)
            except Exception:
                pass

        # Extract text operators (Tj, TJ, etc.)
        text_patterns = [
            r"\(([^)]+)\)\s*Tj",  # (text) Tj operator
            r"\[(.*?)\]\s*TJ",     # [array] TJ operator
            r"BT(.*?)ET",          # Text between BT and ET (Begin Text, End Text)
        ]

        for pattern in text_patterns:
            for text_match in re.finditer(pattern, decoded, re.DOTALL):
                text_content = text_match.group(1)
                text_content = text_content.replace("\\n", " ").replace("\\r", " ").replace("\\t", " ")
                if text_content.strip():
                    extracted_text.append(text_content.strip())

    # Extract all strings from dictionary entries (literal strings)
    string_patterns = [
        r"/\w+\s*\(([^)]+)\)",      # /(text)
        r"/\w+\s*<([0-9a-fA-F]+)>", # /<hextext>
    ]

    for pattern in string_patterns:
        for match in re.finditer(pattern, pdf_text):
            text = match.group(1)
            if len(text.strip()) > 1:
                extracted_text.append(text)

    # Always include page-extracted text (even if empty) and the raw extracted pieces
    parts = []
    if page_text:
        parts.append("-- PAGE-LEVEL EXTRACTED TEXT --\n" + page_text)

    if extracted_text:
        parts.append("-- STREAM/DICTIONARY EXTRACTED PIECES --\n" + "\n".join(extracted_text))

    # If nothing was found, still return raw PDF content so user gets everything
    if not parts:
        return pdf_text

    return "\n\n".join(parts)


def summarize_text(text, max_sentences=5):
    """
    Simple extractive summarizer: scores sentences by word frequency
    and returns the top `max_sentences`, preserving original order.
    """
    if not text or not text.strip():
        return ""

    # Basic sentence splitting
    sentences = re.split(r'(?<=[\.!?])\s+', text)
    if len(sentences) <= max_sentences:
        return " ".join([s.strip() for s in sentences if s.strip()])

    # Build frequency distribution
    words = re.findall(r"\w+", text.lower())
    stopwords = set([
        'the','and','is','in','to','of','a','for','on','with','as','by','that','this','it','an','be','are',
        'or','from','at','we','you','your','our'
    ])
    freqs = Counter(w for w in words if w not in stopwords and len(w) > 2)
    if not freqs:
        # fallback: return first few sentences
        return " ".join([s.strip() for s in sentences[:max_sentences]])

    # Score sentences
    sentence_scores = {}
    for i, sent in enumerate(sentences):
        s_words = re.findall(r"\w+", sent.lower())
        score = sum(freqs.get(w, 0) for w in s_words)
        if score > 0:
            sentence_scores[i] = score

    # Pick top sentence indices
    top_idxs = sorted(sentence_scores, key=sentence_scores.get, reverse=True)[:max_sentences]
    top_idxs = sorted(top_idxs)

    summary = " ".join([sentences[i].strip() for i in top_idxs if i < len(sentences)])
    return summary


def extract_javascript(pdf_text):
    """
    Extract all JavaScript code from PDF
    Searches for JavaScript in /OpenAction, /AA, /JS, /JavaScript fields
    """
    javascript_code = []
    
    # Pattern 1: /JS (xxx)
    js_pattern1 = r"/JS\s*\(([^)]+)\)"
    matches1 = re.findall(js_pattern1, pdf_text, re.IGNORECASE)
    javascript_code.extend(matches1)
    
    # Pattern 2: /JavaScript (xxx)
    js_pattern2 = r"/JavaScript\s*\(([^)]+)\)"
    matches2 = re.findall(js_pattern2, pdf_text, re.IGNORECASE)
    javascript_code.extend(matches2)
    
    # Pattern 3: /OpenAction with stream containing JS
    openaction_pattern = r"/OpenAction\s*\d+\s+0\s+R"
    if re.search(openaction_pattern, pdf_text, re.IGNORECASE):
        # Extract the referenced object
        for match in re.finditer(r"(\d+)\s+0\s+obj\s*<<(.*?)>>\s*stream(.*?)endstream", pdf_text, re.DOTALL):
            obj_content = match.group(2) + "\n" + match.group(3)
            if re.search(r"/JavaScript|/JS", obj_content, re.IGNORECASE):
                javascript_code.append(obj_content)
    
    # Pattern 4: /AA (Action Array) with JavaScript
    aa_pattern = r"/AA\s*<<([^>]+)>>"
    aa_matches = re.findall(aa_pattern, pdf_text, re.DOTALL)
    for aa_match in aa_matches:
        if re.search(r"/JavaScript|/JS", aa_match, re.IGNORECASE):
            javascript_code.append(aa_match)
    
    # Pattern 5: Extract JavaScript from streams
    for match in re.finditer(r"stream(.*?)endstream", pdf_text, re.DOTALL):
        stream_content = match.group(1)
        if re.search(r"(eval|function|var\s|return\s|if\s|for\s|while\s)\s*\(", stream_content, re.IGNORECASE):
            if any(keyword in stream_content.lower() for keyword in ["javascript", "eval", "unescape", "function"]):
                javascript_code.append(stream_content)
    
    return javascript_code


def analyze_javascript(js_list):
    """
    Analyze extracted JavaScript for malicious patterns
    """
    js_analysis = {
        "total_js_objects": len(js_list),
        "dangerous_functions": [],
        "suspicious_patterns": [],
        "all_js": [],
    }
    
    dangerous_patterns = {
        "eval execution": r"\beval\s*\(",
        "unescape function": r"\bunescape\s*\(",
        "String.fromCharCode": r"String\.fromCharCode",
        "replace + eval": r"replace\s*\(.*?\)\s*\(",
        "ActiveXObject": r"ActiveXObject",
        "new Function": r"new\s+Function\s*\(",
        "document.write": r"document\.write",
        "shellcode pattern": r"\\x[0-9a-fA-F]{2}",
        "obfuscated code": r"String\.\w+\(\d+\)",
    }
    
    for js_code in js_list:
        js_analysis["all_js"].append(js_code)
        
        for pattern_name, pattern in dangerous_patterns.items():
            if re.search(pattern, js_code, re.IGNORECASE):
                if pattern_name not in js_analysis["dangerous_functions"]:
                    js_analysis["dangerous_functions"].append(pattern_name)
                js_analysis["suspicious_patterns"].append({
                    "pattern": pattern_name,
                    "code_snippet": js_code[:100]
                })
    
    return js_analysis


def analyze_extracted_text(text):
    """
    Analyze extracted text for suspicious patterns and content
    """
    analysis = {
        "total_length": len(text),
        "suspicious_keywords": [],
        "urls_found": [],
        "emails_found": [],
        "ip_addresses": [],
        "encoded_strings": [],
    }
    
    # Suspicious keywords in text
    suspicious = ["click here", "update", "download", "enable", "run", "execute", 
                  "password", "verify", "confirm", "activate"]
    for keyword in suspicious:
        if keyword.lower() in text.lower():
            analysis["suspicious_keywords"].append(keyword)
    
    # Extract URLs
    urls = re.findall(r"https?://[^\s)]+", text)
    analysis["urls_found"] = list(set(urls))
    
    # Extract email addresses
    emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
    analysis["emails_found"] = list(set(emails))
    
    # Extract IP addresses
    ips = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
    analysis["ip_addresses"] = list(set(ips))
    
    # Find base64-like encoded strings
    b64_strings = re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text)
    analysis["encoded_strings"] = list(set(b64_strings))[:5]  # Limit to 5 examples
    
    return analysis


def calculate_risk(keys, findings, embedded_count, text_analysis=None, js_analysis=None):
    score = 0
    reasons = []

    for k, v in keys.items():
        if v > 0:
            score += 10
            reasons.append(f"{k} detected")

    for f in findings:
        score += 20
        reasons.append(f)

    if embedded_count > 0:
        score += 30
        reasons.append("Embedded file extracted")
    
    # Add risk from text analysis
    if text_analysis:
        if text_analysis["urls_found"]:
            score += 15
            reasons.append(f"URLs in text: {len(text_analysis['urls_found'])}")
        
        if text_analysis["suspicious_keywords"]:
            score += 10
            reasons.append(f"Suspicious keywords found: {', '.join(text_analysis['suspicious_keywords'])}")
        
        if text_analysis["encoded_strings"]:
            score += 10
            reasons.append("Encoded strings detected in text")
    
    # Add risk from JavaScript analysis
    if js_analysis:
        if js_analysis["total_js_objects"] > 0:
            score += 25
            reasons.append(f"JavaScript code found: {js_analysis['total_js_objects']} objects")
        
        if js_analysis["dangerous_functions"]:
            score += 40
            reasons.append(f"Dangerous JS functions: {', '.join(js_analysis['dangerous_functions'][:3])}")

    if score >= 80:
        severity = "CRITICAL"
    elif score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return severity, score, reasons
