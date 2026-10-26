# CyberShield AI — Multimodal Cybersecurity Awareness Assistant

**Tagline:** Detect threats. Understand risks. Stay protected.

CyberShield AI is a student-friendly Flask web app that reviews suspicious message text, URL strings, and optional screenshots. It combines transparent local heuristics with optional Gemma 4 analysis through Google's Gemini API.

> **Important:** This is an educational prototype, not professional security software. It can make mistakes. A low-risk result does not prove that content is safe.

## Features

- **Message review:** local rules flag common phishing/social-engineering wording.
- **URL string review:** checks URL structure without visiting the site.
- **Screenshot review:** optional Gemma 4 image analysis; images are processed in memory and not saved by this app.
- **Optional Gemma 4 integration:** if no API key is configured, local checks still work.
- **Cybersecurity Q&A:** ask for beginner-friendly defensive advice.
- **Local scan history:** SQLite stores short input previews and analysis summaries; clear history from the history page.
- **Responsive dashboard:** works on desktop and mobile browsers.
- **Basic tests:** checks local rules and URL parsing.

## Requirements

- Python 3.10 or newer (Python 3.11 recommended)
- Internet access only to install packages and, if enabled, call the AI API
- A Gemma-compatible API key from Google AI Studio if you want AI analysis. Check current model availability, account access, and billing/usage limits before relying on it.

## Run locally (Windows)

1. Extract the ZIP.
2. Open the extracted `CyberShield-AI` folder.
3. Open Command Prompt or PowerShell in that folder.
4. Create a virtual environment:

   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

   If PowerShell blocks activation, use Command Prompt and run `.venv\Scripts\activate.bat`.

5. Install dependencies:

   ```powershell
   python -m pip install --upgrade pip
   pip install -r requirements.txt
   ```

6. Copy `.env.example` to `.env`. You can skip the API key for rule-based mode. For Gemma 4, add your own key to `GEMINI_API_KEY` in `.env`. Never share the key or commit `.env` to GitHub.

7. Start the app:

   ```powershell
   python app.py
   ```

8. Open `http://127.0.0.1:5000` in your browser.

## Run locally (Linux/macOS)

```bash
cd CyberShield-AI
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
cp .env.example .env
# Edit .env only if you want to configure the AI API.
python app.py
```

Then open `http://127.0.0.1:5000`.

## Configure Gemma 4

1. Get an API key from Google AI Studio.
2. Copy `.env.example` to `.env`.
3. Set `GEMINI_API_KEY=your_key_here`.
4. Keep `GEMMA_MODEL=gemma-4-26b-a4b-it`, or choose another Gemma 4 model currently supported by your API account.
5. Restart the app.

The project uses the `google-genai` SDK. Current official Gemma documentation lists `gemma-4-26b-a4b-it` and `gemma-4-31b-it` for hosted Gemini API use. Availability can change; check the official documentation before a demo. When the API key is absent or the API call fails, the app falls back to local rule-based checks.

Official setup guide: https://ai.google.dev/gemma/docs/core/gemma_on_gemini_api

## Try these harmless examples

**Example message to analyze:**
> Your account will be suspended today. Verify your account immediately using this link: https://example.com/verify

This should trigger some local indicators such as urgency, account threat, and a URL. `example.com` is used for demonstration; the app does not visit it.

**Example URL string:**
> http://192.0.2.10/login-verify

This reserved documentation IP address is a safe test string. The app checks the string only and does not connect to it.

**Example chatbot question:**
> What should I do if I entered my password on a suspicious website?

## Tests

Install dependencies first, then run:

```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
CyberShield-AI/
├── app.py                     # Flask routes and application setup
├── ai/gemma_client.py         # Optional Gemma 4 API wrapper
├── security/
│   ├── phishing_detector.py  # Local message heuristics
│   ├── url_analyzer.py       # Offline URL string checks
│   └── risk_assessment.py    # Combines results
├── templates/                 # HTML pages
├── static/css/style.css       # Responsive styling
├── static/js/app.js           # Form submissions and result rendering
├── database/                  # SQLite database created at runtime
├── tests/                     # Unit tests
├── requirements.txt
└── .env.example
```

## Privacy and security notes

- Do not paste passwords, OTPs, private messages, personal data, or confidential company content.
- Uploaded images are not written to disk by this app. If AI is enabled, the image is sent to the configured API provider for analysis; check that provider's terms and privacy policy first.
- Text and URL inputs may be saved as short previews in the local SQLite history. Use **Clear history** when needed.
- The URL analyzer never visits a URL or downloads remote content.
- The app does not perform live domain reputation checks unless you add a provider yourself.
- Keep API keys in `.env`, and never commit them.
- Before public deployment, add authentication, CSRF protection, rate limiting, secure cookie settings, HTTPS, stronger data-retention controls, and production logging. Do not expose the development server directly to the public internet.
- Model outputs are untrusted and may be wrong. Do not use the result as the sole basis for financial, legal, or security decisions.

## Suggested improvements for a hackathon

1. Add opt-in threat-intelligence lookup with strict timeouts and clear privacy notices.
2. Add multilingual phishing examples and tests.
3. Add downloadable scan reports.
4. Add a user-controlled retention period.
5. Build a curated test set and measure false positives/false negatives.
6. Include a short demo showing text-only vs. image-plus-text analysis.

## License

This starter project is provided under the MIT License; see `LICENSE`. Confirm all third-party model/API terms separately.
