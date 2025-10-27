# Password Strength Analyzer & Custom Wordlist Generator

**Short description:**  
GUI tool to analyze password strength and generate custom wordlists from user-provided seeds (names, dates, pets, favorite words). Intended **only** for authorized security testing and password recovery.

## Files
- `pwtool_gui.py`  
  GUI-only Python application. Run with `python pwtool_gui.py`. Works without optional libraries (falls back to simple entropy estimation).

- `requirements.txt`  
  Optional Python dependencies. Install with `pip install -r requirements.txt`.

- `Password_Strength_Analyzer_Report.pdf`  
  Short 1–2 page project report (Introduction, Abstract, Tools Used, Steps, Conclusion).

- `examples/`  
  Optional folder for screenshots and small sample wordlists.

## Quick start
1. (Optional) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate   # on Windows: venv\Scripts\activate
