> A practical static malware analysis toolkit for dissecting malicious PDF files using object, stream, JavaScript, and text-level inspection.

# 📄 PDF Malware Analysis Toolkit

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Static Analysis](https://img.shields.io/badge/Analysis-Static-green)
![PDF Security](https://img.shields.io/badge/Focus-PDF%20Malware-red)
![Status](https://img.shields.io/badge/Project-Active-brightgreen)
![License](https://img.shields.io/badge/Use-Educational-yellow)
![Blue Team](https://img.shields.io/badge/Team-Blue%20Team-0066cc)

A Python-based **PDF static malware analysis toolkit** that inspects the internal structure of PDF files to detect malicious behavior such as embedded JavaScript, obfuscated payloads, suspicious streams, extracted text, and embedded files.

This toolkit replicates the methodology of professional tools like **pdfid, pdf-parser, peepdf, qpdf, and strings** in a single automated solution.

---

## 👤 Author

**Ahmed Emad Nasr**
- 🔒 Role: SOC Analyst | Incident Response | Cybersecurity Blue Team
- 🎯 Specialization: PDF Malware Analysis, Static Malware Analysis, Threat Detection
- 💼 Focus: Blue Team Operations & Threat Hunting

## 📜 License

This project is released under the MIT License. See [LICENSE](LICENSE) for the full text.

---

## 🎯 Project Goal

To design a toolkit capable of:

- Understanding PDF internal structure
- Enumerating objects and streams
- Detecting malicious JavaScript
- Extracting readable text content
- Analyzing suspicious text patterns
- Extracting Indicators of Compromise (IOC)
- Detecting embedded malicious payloads
- Performing automated risk assessment
- Generating structured malware analysis reports

---

## 🧠 Toolkit Workflow

```
Input PDF 
  → Metadata Extraction
  → Object Enumeration
  → Stream Extraction & Decoding
  → Text Extraction & Analysis
  → JavaScript Extraction & Analysis
  → Keyword Detection
  → IOC Extraction
  → Embedded File Detection
  → Risk Scoring
  → Report Generation
```

---

## 🧩 Features

### Core Analysis
- ✅ Metadata analysis (Author, Creator, Dates)
- ✅ Object enumeration from raw PDF structure
- ✅ Stream detection and zlib decompression
- ✅ Embedded file extraction and analysis

### JavaScript Detection
- ✅ JavaScript malware detection (`eval`, `unescape`, `ActiveXObject`)
- ✅ Obfuscation pattern recognition
- ✅ `/OpenAction`, `/AA`, `/JS`, `/JavaScript` scanning
- ✅ Shellcode pattern detection
- ✅ Full JavaScript code extraction

### Text Analysis
- ✅ Literal text extraction from all streams
- ✅ Hex string decoding
- ✅ URL detection in text
- ✅ Email address extraction
- ✅ IP address discovery
- ✅ Suspicious keyword scanning
- ✅ Encoded string detection (Base64, hex)

### Risk Assessment
- ✅ Automated severity scoring engine
- ✅ Risk level classification (LOW, MEDIUM, HIGH, CRITICAL)
- ✅ Detailed reason tracking
- ✅ Threat pattern matching

### Reporting
- ✅ Detailed malware analysis report generation
- ✅ Complete IOC extraction summary
- ✅ Risk assessment breakdown

---

## 🛠️ Techniques Inspired By

| Toolkit Capability | Industry Tool Equivalent |
|--------------------|--------------------------|
| Keyword detection | pdfid |
| Object parsing | pdf-parser |
| Stream decoding | qpdf |
| JavaScript analysis | peepdf |
| IOC hunting | strings |
| Text extraction | Strings utility |
| JavaScript deobfuscation | Dynamic analysis tools |

---

## 📂 Project Structure

```
PDF-Malware-Analysis-Toolkit/
├── main.py                      # Main execution script
├── core.py                      # Core analysis functions
├── report_generator.py          # Report generation module
├── mPDF.py                      # PDF creation utilities
├── make-pdf-helloworld.py       # Test PDF generator
├── make-pdf-javascript.py       # Malicious PDF generator
├── README.md                    # This file
├── LICENSE                      # License information
├── reports/                     # Generated reports directory
├── extracted_files/             # Extracted embedded files
└── diagrams/                    # Analysis flow diagrams
```

---

## ▶️ Usage

### Basic Usage

```bash
python main.py
```

When prompted, provide:
- **Single PDF file**: `/path/to/file.pdf`
- **Directory with PDFs**: `/path/to/folder/`

### Example Commands

#### Analyze a single PDF file:
```bash
python main.py
# Enter: C:\Users\3omda\Desktop\malware.pdf
```

#### Analyze all PDFs in a folder:
```bash
python main.py
# Enter: C:\Users\3omda\Desktop\pdf_samples/
```

#### Generate test PDFs:
```bash
# Create a basic PDF
python make-pdf-helloworld.py

# Create a PDF with malicious JavaScript
python make-pdf-javascript.py
```

---

## 📊 Analysis Output

### Console Output

```
===== Analyzing: malware.pdf =====

=== OBJECT ENUMERATION ===
Total Objects: 15
Stream Objects: ['1', '3', '5', '7']

=== KEYWORDS ===
/JS : 1
/JavaScript : 1
/OpenAction : 1
/AA : 0
/EmbeddedFile : 2
/URI : 3

=== TEXT EXTRACTION ===
Total Text Length: 2345 characters
URLs Found: ['http://malicious.com', 'https://c2.evil.net']
Emails Found: ['attacker@evil.com']
IP Addresses: ['192.168.1.100', '10.0.0.5']
Suspicious Keywords: ['click here', 'download', 'enable']

=== JAVASCRIPT ANALYSIS ===
JavaScript Objects Found: 3
⚠️  DANGEROUS FUNCTIONS DETECTED:
  - eval execution
  - unescape function
  - String.fromCharCode
  - ActiveXObject

=== MALWARE FINDINGS ===
- eval() usage
- unescape() usage
- Base64 payload
- URL found
- IP Address

=== RISK ASSESSMENT ===
CRITICAL | Score: 145

- /JS detected
- /JavaScript detected
- eval() usage
- Dangerous JS functions: eval execution, unescape function, String.fromCharCode
- URLs in text: 2
- JavaScript code found: 3 objects
```

### Report File

Generated in `reports/report_[filename].txt`

```
PDF MALWARE ANALYSIS REPORT
============================================================

Analyzed File: malware.pdf
Time: 2026-05-11 14:30:45.123456

=== METADATA ===
Author: Unknown
Creator: Microsoft Word
Producer: GPL Ghostscript
CreationDate: 2024-01-15

=== OBJECT ENUMERATION ===
Total Objects: 15
Stream Objects: [1, 3, 5, 7]

=== KEYWORD SCAN ===
/JS: 1
/JavaScript: 1
/OpenAction: 1
/AA: 0
/EmbeddedFile: 2
/URI: 3

=== TEXT EXTRACTION ANALYSIS ===
Total Text Length: 2345 characters

URLs Found (2):
  - http://malicious.com
  - https://c2.evil.net

Emails Found (1):
  - attacker@evil.com

IP Addresses Found (2):
  - 192.168.1.100
  - 10.0.0.5

Suspicious Keywords Found (3):
  - click here
  - download
  - enable

=== JAVASCRIPT ANALYSIS ===
Total JavaScript Objects: 3

⚠️  DANGEROUS FUNCTIONS DETECTED (4):
  - eval execution
  - unescape function
  - String.fromCharCode
  - ActiveXObject

=== RISK ASSESSMENT ===
Severity: CRITICAL
Score: 145
- /JS detected
- /JavaScript detected
- eval() usage
- Dangerous JS functions detected
- URLs in text: 2
- JavaScript code found: 3 objects
```

---

## 🔍 Analysis Functions Reference

### In `core.py`

#### `extract_metadata(pdf_path)`
- **Purpose**: Extract PDF metadata
- **Returns**: Dictionary with Author, Creator, Producer, CreationDate
- **Usage**: `metadata = extract_metadata("file.pdf")`

#### `enumerate_objects(pdf_text)`
- **Purpose**: Find all objects and streams in PDF
- **Returns**: Tuple of (objects_list, streams_list, embedded_list)
- **Usage**: `objects, streams, embedded = enumerate_objects(pdf_text)`

#### `extract_streams(pdf_text)`
- **Purpose**: Extract and decompress streams
- **Returns**: Concatenated stream content
- **Usage**: `stream_content = extract_streams(pdf_text)`

#### `extract_text(pdf_text)`
- **Purpose**: Extract readable text from PDF streams and objects
- **Returns**: String of extracted text
- **Usage**: `text = extract_text(pdf_text)`

#### `extract_javascript(pdf_text)`
- **Purpose**: Extract JavaScript code from PDF
- **Returns**: List of JavaScript code snippets
- **Usage**: `js_list = extract_javascript(pdf_text)`

#### `analyze_javascript(js_list)`
- **Purpose**: Analyze JavaScript for malicious patterns
- **Returns**: Dictionary with dangerous functions and patterns
- **Usage**: `js_analysis = analyze_javascript(js_list)`

#### `analyze_extracted_text(text)`
- **Purpose**: Analyze extracted text for IOCs
- **Returns**: Dictionary with URLs, emails, IPs, keywords
- **Usage**: `text_analysis = analyze_extracted_text(text)`

#### `keyword_scan(text)`
- **Purpose**: Scan for PDF malware keywords
- **Returns**: Dictionary with keyword counts
- **Usage**: `keywords = keyword_scan(text)`

#### `malware_scan(text)`
- **Purpose**: Detect malware patterns
- **Returns**: List of malware findings
- **Usage**: `findings = malware_scan(text)`

#### `calculate_risk(keys, findings, embedded_count, text_analysis, js_analysis)`
- **Purpose**: Calculate risk score and severity
- **Returns**: Tuple of (severity, score, reasons)
- **Usage**: `severity, score, reasons = calculate_risk(keys, findings, count, text_analysis, js_analysis)`

#### `extract_embedded_files(pdf_text, output_dir)`
- **Purpose**: Extract and save embedded files
- **Returns**: Count of extracted files
- **Usage**: `count = extract_embedded_files(pdf_text, "extracted_files")`

---

## 📈 Risk Scoring Logic

| Finding | Points | Category |
|---------|--------|----------|
| PDF keyword detected (/JS, /JavaScript, /AA, /OpenAction, /URI, /EmbeddedFile) | +10 | Keywords |
| Malware pattern found (eval, unescape, Base64, shellcode, URL, IP) | +20 | Patterns |
| Embedded file extracted | +30 | Embedded Files |
| URL in text | +15 | Text Analysis |
| Suspicious keywords in text | +10 | Text Analysis |
| Encoded strings in text | +10 | Text Analysis |
| JavaScript object found | +25 | JavaScript |
| Dangerous JS function detected (eval, unescape, ActiveXObject, etc.) | +40 | JavaScript |

### Severity Classification

| Score Range | Severity |
|------------|----------|
| 0-24 | LOW |
| 25-49 | MEDIUM |
| 50-79 | HIGH |
| 80+ | CRITICAL |

---

## 🎓 Learning Resources

### PDF Malware Analysis Concepts

1. **PDF Structure**: Objects, streams, cross-reference tables, trailers
2. **JavaScript in PDFs**: Action triggers (/OpenAction, /AA), security implications
3. **Obfuscation Techniques**: Hex encoding, string operations, escaped characters
4. **IOC Types**: URLs, email addresses, IP addresses, file hashes, domain names
5. **Threat Intelligence**: Pattern recognition, threat actor TTP tracking

### Tools for Comparison

- **pdfid**: Quick PDF scanning
- **pdf-parser**: Detailed object analysis
- **peepdf**: Interactive PDF analysis
- **qpdf**: PDF manipulation and analysis
- **Didier Stevens' PDF Tools**: Advanced analysis

---

## 🔐 Security Considerations

- ⚠️ This toolkit performs **static analysis only**
- ⚠️ Analyze suspicious PDFs in isolated/sandboxed environments
- ⚠️ Do not open extracted files without proper security precautions
- ⚠️ Use in conjunction with dynamic analysis tools for comprehensive assessment
- ⚠️ Keep threat intelligence feeds updated

---

## 📋 Example Malware Detection Scenarios

### Scenario 1: Ransomware PDF
```
Detection:
- /OpenAction detected
- /JavaScript detected
- eval() function found
- URL pointing to attacker C2 server
- Base64 encoded payload

Risk Score: CRITICAL (125 points)
```

### Scenario 2: Phishing PDF
```
Detection:
- Suspicious keywords: "click here", "enable", "download"
- Email address extracted
- URLs in text body
- No JavaScript

Risk Score: MEDIUM (35 points)
```

### Scenario 3: Trojan PDF
```
Detection:
- /AA trigger detected
- Multiple JavaScript objects
- Shellcode patterns in streams
- Embedded EXE file

Risk Score: CRITICAL (150 points)
```

---

## 🐛 Troubleshooting

### Issue: "File not found" error
**Solution**: Provide absolute path to PDF file or ensure file exists

### Issue: "Metadata extraction failed"
**Solution**: PDF might be corrupted or non-standard format. Analysis will continue.

### Issue: Reports not generating
**Solution**: Ensure `reports/` directory exists and has write permissions

### Issue: Large PDFs taking long time
**Solution**: This is normal for large files. Stream decompression is resource-intensive.

---

## 📚 References & Inspiration

- Didier Stevens' PDF Tools
- SANS Institute PDF Malware Analysis
- Adobe PDF Specification
- Community-driven malware research

---

## 📄 License

Educational Use Only. See LICENSE file for details.

---

## 🤝 Contributing

Feedback and improvements welcome. This toolkit is designed for:
- Blue Team security analysts
- Incident response teams
- Cybersecurity researchers
- Malware analysis professionals

---

## 📞 Support

For issues or questions, refer to the toolkit documentation and industry malware analysis resources.

---

**Last Updated**: May 11, 2026
**Version**: 2.0 (Enhanced with Text & JavaScript Analysis)

CRITICAL | Score: 90

---

## 📑 Report Contains

- Metadata details
- Object & stream enumeration
- Keyword scan results
- Malware findings & IOCs
- Embedded file objects
- Risk severity score

---

## 🎓 Learning Outcomes

This project demonstrates:

- Static malware analysis
- Understanding of PDF internals
- JavaScript-based attack detection
- Threat hunting using IOC patterns
- Automated forensic reporting

---

## ⚠️ Disclaimer

This project is intended for **educational and research purposes only**.

---

## 👨‍💻 Author

PDF Malware Analysis Toolkit Project
