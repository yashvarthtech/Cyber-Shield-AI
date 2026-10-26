# CyberShield AI — File-by-file explanation

## 1. `app.py` — Main backend
This is the Flask application. It serves the dashboard, receives the form, validates text/URL/image input, calls the local detectors, optionally calls Gemma 4, combines the results, and saves a short record in SQLite. It limits uploads to 5 MB and keeps uploaded image bytes in memory. The `/chat` endpoint powers the Q&A assistant; `/history` shows saved scans; `/history/clear` deletes them.

## 2. `ai/gemma_client.py` — Gemma 4 connection
This file isolates all AI API calls. It reads `GEMINI_API_KEY` and `GEMMA_MODEL` from environment variables. `analyze_with_gemma()` sends the supplied text and optional image to Gemma 4. `chat_with_gemma()` answers defensive cybersecurity questions. If no key is set, the functions report an error and the app falls back to local checks.

## 3. `security/phishing_detector.py` — Text rules
A small set of regular expressions looks for common indicators: urgency, account threats, credential requests, payment pressure, prize claims, links, and impersonation language. The score maps to Low/Medium/High. These rules are intentionally transparent, but they are not a trained classifier and cannot prove a message is malicious or legitimate.

## 4. `security/url_analyzer.py` — URL string inspection
This module parses a URL string and looks for structural indicators such as an IP address used as a host, a known shortener, punycode, unusually long hostnames, multiple hyphens, and non-HTTPS schemes. It never opens the URL, makes a network request, or checks a live reputation database. Its results are only heuristic clues.

## 5. `security/risk_assessment.py` — Result combination
This combines local text and URL results and optionally considers the risk label returned in the Gemma response. It keeps evidence and recommendations together and adds a disclaimer. In a production-grade detector, replace the simple maximum-risk rule with a calibrated, tested decision policy.

## 6. `templates/index.html` — Dashboard UI
Contains the main form for message text, URL, and screenshot; status cards; a safety checklist; the chatbot; and recent scan summaries. Jinja fills the dashboard metrics from Flask.

## 7. `templates/history.html` — History page
Displays the most recent 100 scan records and provides a button to clear the local database history.

## 8. `static/css/style.css` — Design
Contains the dark dashboard theme, cards, forms, risk labels, tables, and mobile-responsive layout.

## 9. `static/js/app.js` — Browser behavior
Submits forms using `fetch()` without a full page reload, safely inserts returned text with DOM text nodes, shows analysis results, sends chatbot questions, and confirms before clearing history.

## 10. `database/`
The SQLite database is created automatically on the first app start. The `.gitignore` excludes database files so scan history is not accidentally committed.

## 11. `tests/`
Unit tests cover representative message and URL examples. Run them with `python -m unittest discover -s tests -v`.

## How one scan flows through the system
1. Browser submits the form to `/analyze`.
2. Flask validates the fields and file type/size.
3. The text and URL rule modules produce local indicators.
4. If configured, Gemma 4 analyzes the text and/or image.
5. The risk module combines the signals.
6. Flask saves a short scan record.
7. JavaScript renders the result on the dashboard.

## Hackathon presentation idea
Show a legitimate sample first, then a suspicious message, then a screenshot. Explain what the rules detected and what Gemma added. Be transparent about uncertainty, false positives, API dependency, and the fact that the app does not visit URLs.
