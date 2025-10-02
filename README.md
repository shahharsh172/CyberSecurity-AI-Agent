# CyberSec AI - Incident Analysis Platform
## Overview
CyberSec AI is an AI-powered platform for automated cybersecurity incident analysis. It leverages advanced AI models to analyze raw security logs, generate structured incident reports, provide intelligent Q&A, and suggest mitigation steps. The platform is designed for cybersecurity teams to accelerate incident response and improve security posture.
## Features
- **AI-Powered Log Analysis:** Upload or paste security logs (text, PDF, or image) and get a comprehensive incident report.
- **Incident Dashboard:** Visualize incident metrics, severity, attack types, and more.
- **Incident Q&A:** Ask questions about analyzed incidents and get expert AI responses.
- **Reports & Analytics:** Download incident reports in Markdown or PDF, and view analytics across incidents.
- **Auto-Scan Logs:** Automatically scan and analyze files in the `logs/` folder on startup.
- **OCR Support:** Extract text from PDF and image files for analysis.
## Installation
1. **Clone the repository** (if applicable) or copy the project files to your working directory.
2. **Install dependencies:**
```sh
pip install -r requirements.txt
```
3. **Install Tesseract OCR:**
- Windows: Download from [https://github.com/tesseract-ocr/tesseract](https://github.com/tesseract-ocr/tesseract)
- Add Tesseract to your system PATH.
## Usage
1. **Start the application:**
```sh
streamlit run cybersecurity_ai.py
```
2. **Upload or paste logs:** Use the web interface to analyze new incidents or view auto-analyzed logs from the `logs/` folder.
3. **Download reports:** Export incident reports as Markdown or PDF.
4. **Ask questions:** Use the Q&A module for AI-powered incident investigation.
## File Structure