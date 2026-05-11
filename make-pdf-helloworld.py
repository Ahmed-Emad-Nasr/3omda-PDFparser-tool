# PDF Malware Analysis Toolkit
# Author: Ahmed Emad Nasr
# GitHub-ready project release

# Modified for malicious PDF generation (Python 3 compatible)

import mPDF
import sys

if len(sys.argv) != 2:
    print("Usage: make-pdf-helloworld pdf-file")
    print("  Generates PDF with OpenAction JavaScript")
else:
    pdffile = sys.argv[1]

    oPDF = mPDF.cPDF(pdffile)
    oPDF.header()

    # Catalog with OpenAction
    oPDF.indirectobject(1, 0, "<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>")

    # Pages
    oPDF.indirectobject(2, 0, "<< /Type /Pages /Kids [4 0 R] /Count 1 >>")

    # JavaScript Action (malicious)
    js = """<<
    /S /JavaScript
    /JS (app.alert("Malware Test");
         eval(unescape("%41%42%43%44"));
         var url = "http://malicious.example.com";
    )
    >>"""
    oPDF.indirectobject(3, 0, js)

    # Page
    oPDF.indirectobject(4, 0, "<< /Type /Page /Parent 2 0 R /Contents 5 0 R >>")

    # Dummy content stream
    oPDF.stream(5, 0, "BT /F1 12 Tf 100 700 Td (Test Page) Tj ET")

    oPDF.xrefAndTrailer("1 0 R")
