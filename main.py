# PDF Malware Analysis Toolkit
# Author: Ahmed Emad Nasr
# GitHub-ready project release

import os
from core import (
    extract_metadata,
    enumerate_objects,
    extract_streams,
    extract_embedded_files,
    extract_text,
    summarize_text,
    extract_javascript,
    analyze_extracted_text,
    analyze_javascript,
    keyword_scan,
    malware_scan,
    calculate_risk,
)

from report_generator import generate_report


def get_pdfs(path):
    if os.path.isfile(path) and path.endswith(".pdf"):
        return [path]
    elif os.path.isdir(path):
        return [
            os.path.join(path, f)
            for f in os.listdir(path)
            if f.endswith(".pdf")
        ]
    return []


print("=== PDF Malware Analysis Toolkit ===\n")
user_input = input("Enter PDF file path OR folder path: ").strip().strip('"').strip("'")
pdfs = get_pdfs(user_input)

for pdf in pdfs:
    print(f"\n===== Analyzing: {pdf} =====")

    with open(pdf, "rb") as f:
        pdf_text = f.read().decode("latin1", errors="ignore")

    metadata = extract_metadata(pdf)

    objects, streams, embedded_objs = enumerate_objects(pdf_text)

    stream_text = extract_streams(pdf_text)

    embedded_count = extract_embedded_files(pdf_text)

    # Extract and analyze text (use robust extractor that can accept a file path)
    extracted_text = extract_text(pdf)
    text_analysis = analyze_extracted_text(extracted_text)
    # Add a short extractive summary of the extracted text
    summary = summarize_text(extracted_text, max_sentences=5)
    text_analysis['summary'] = summary
    
    # Extract and analyze JavaScript
    javascript_list = extract_javascript(pdf_text)
    js_analysis = analyze_javascript(javascript_list)

    combined_text = pdf_text + "\n" + stream_text + "\n" + extracted_text

    keys = keyword_scan(combined_text)
    findings = malware_scan(combined_text)
    severity, score, reasons = calculate_risk(keys, findings, embedded_count, text_analysis, js_analysis)

    print("=== OBJECT ENUMERATION ===")
    print(f"Total Objects: {len(objects)}")
    print(f"Stream Objects: {streams}")

    print("\n=== KEYWORDS ===")
    for k, v in keys.items():
        print(f"{k} : {v}")

    print("\n=== TEXT EXTRACTION ===")
    print(f"Total Text Length: {text_analysis['total_length']} characters")
    if text_analysis.get('summary'):
        print("\n=== SUMMARY ===")
        preview = text_analysis['summary'].replace('\n', ' ')[:500]
        print(preview)
    if text_analysis['urls_found']:
        print(f"URLs Found: {text_analysis['urls_found']}")
    if text_analysis['emails_found']:
        print(f"Emails Found: {text_analysis['emails_found']}")
    if text_analysis['ip_addresses']:
        print(f"IP Addresses: {text_analysis['ip_addresses']}")
    if text_analysis['suspicious_keywords']:
        print(f"Suspicious Keywords: {text_analysis['suspicious_keywords']}")

    print("\n=== JAVASCRIPT ANALYSIS ===")
    print(f"JavaScript Objects Found: {js_analysis['total_js_objects']}")
    if js_analysis['dangerous_functions']:
        print(f"⚠️  DANGEROUS FUNCTIONS DETECTED:")
        for func in js_analysis['dangerous_functions']:
            print(f"  - {func}")
    if js_analysis['all_js']:
        print(f"JavaScript Code Snippets:")
        for js in js_analysis['all_js'][:3]:  # Show first 3
            preview = js.replace('\n', ' ')[:100]
            print(f"  - {preview}...")

    print("\n=== MALWARE FINDINGS ===")
    print(findings if findings else "None")

    print(f"\n=== RISK ASSESSMENT ===\n{severity} | Score: {score}")

    reasons.append(f"Embedded File Objects: {embedded_objs}")

    report = generate_report(
        pdf,
        metadata,
        keys,
        findings,
        severity,
        score,
        reasons,
        objects,
        streams,
        text_analysis,
        js_analysis,
    )

    print(f"\nReport saved at: {report}")