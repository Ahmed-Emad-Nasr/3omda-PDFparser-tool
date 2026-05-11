# PDF Malware Analysis Toolkit
# Author: Ahmed Emad Nasr
# GitHub-ready project release

import os
from datetime import datetime


def generate_report(pdf_file, metadata, keywords, findings,
                    severity, score, reasons, objects, streams, text_analysis=None, js_analysis=None):

    os.makedirs("reports", exist_ok=True)
    name = os.path.join("reports", f"report_{os.path.basename(pdf_file)}.txt")

    with open(name, "w", encoding="utf-8") as f:
        f.write("PDF MALWARE ANALYSIS REPORT\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"Analyzed File: {pdf_file}\n")
        f.write(f"Time: {datetime.now()}\n\n")

        f.write("=== METADATA ===\n")
        for k, v in metadata.items():
            f.write(f"{k}: {v}\n")

        f.write("\n=== OBJECT ENUMERATION ===\n")
        f.write(f"Total Objects: {len(objects)}\n")
        f.write(f"Stream Objects: {streams}\n")

        f.write("\n=== KEYWORD SCAN ===\n")
        for k, v in keywords.items():
            f.write(f"{k}: {v}\n")

        # Add text analysis section
        if text_analysis:
            f.write("\n=== TEXT EXTRACTION ANALYSIS ===\n")
            f.write(f"Total Text Length: {text_analysis['total_length']} characters\n")
            
            if text_analysis['urls_found']:
                f.write(f"\nURLs Found ({len(text_analysis['urls_found'])}):\n")
                for url in text_analysis['urls_found']:
                    f.write(f"  - {url}\n")
            
            if text_analysis['emails_found']:
                f.write(f"\nEmails Found ({len(text_analysis['emails_found'])}):\n")
                for email in text_analysis['emails_found']:
                    f.write(f"  - {email}\n")
            
            if text_analysis['ip_addresses']:
                f.write(f"\nIP Addresses Found ({len(text_analysis['ip_addresses'])}):\n")
                for ip in text_analysis['ip_addresses']:
                    f.write(f"  - {ip}\n")
            
            if text_analysis['suspicious_keywords']:
                f.write(f"\nSuspicious Keywords Found ({len(text_analysis['suspicious_keywords'])}):\n")
                for keyword in text_analysis['suspicious_keywords']:
                    f.write(f"  - {keyword}\n")
            
            if text_analysis['encoded_strings']:
                f.write(f"\nEncoded Strings Found ({len(text_analysis['encoded_strings'])}):\n")
                for encoded in text_analysis['encoded_strings']:
                    f.write(f"  - {encoded[:50]}...\n" if len(encoded) > 50 else f"  - {encoded}\n")

            # Include extractive summary if available
            if text_analysis.get('summary'):
                f.write("\n=== EXTRACTIVE SUMMARY ===\n")
                f.write(text_analysis['summary'] + "\n")

        # Add JavaScript analysis section
        if js_analysis:
            f.write("\n=== JAVASCRIPT ANALYSIS ===\n")
            f.write(f"Total JavaScript Objects: {js_analysis['total_js_objects']}\n")
            
            if js_analysis['dangerous_functions']:
                f.write(f"\n⚠️  DANGEROUS FUNCTIONS DETECTED ({len(js_analysis['dangerous_functions'])}):\n")
                for func in js_analysis['dangerous_functions']:
                    f.write(f"  - {func}\n")
            
            if js_analysis['suspicious_patterns']:
                f.write(f"\nSuspicious Patterns ({len(js_analysis['suspicious_patterns'])}):\n")
                for pattern in js_analysis['suspicious_patterns']:
                    f.write(f"  Pattern: {pattern['pattern']}\n")
                    f.write(f"    Code: {pattern['code_snippet'][:80]}...\n\n")
            
            if js_analysis['all_js']:
                f.write(f"\nExtracted JavaScript Code ({len(js_analysis['all_js'])} objects):\n")
                for idx, js_code in enumerate(js_analysis['all_js'][:5], 1):  # Limit to 5
                    f.write(f"\n--- JavaScript Object {idx} ---\n")
                    preview = js_code.replace('\n', ' ')[:200]
                    f.write(f"{preview}...\n")

        f.write("\n=== MALWARE FINDINGS ===\n")
        if findings:
            for item in findings:
                f.write(f"- {item}\n")
        else:
            f.write("None\n")

        f.write("\n=== RISK ASSESSMENT ===\n")
        f.write(f"Severity: {severity}\n")
        f.write(f"Score: {score}\n")
        for r in reasons:
            f.write(f"- {r}\n")

    return name
