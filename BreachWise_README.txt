# BreachWise

A security awareness web app that checks whether your password has appeared in known data breaches and analyzes URL/IP reputation.

---

## Requirements

- Python 3.x (you already have this)
- uvicorn and fastapi (already installed)

---

## How to run the app

**Step 1 — Open a terminal and navigate to the project folder:**

```
cd C:\Users\<your-username>\Desktop\BreachWise
```

**Step 2 — Start the server:**

```
python -m uvicorn main:app --reload --port 8080

```

Leave this terminal open the entire time you're using the app. If you close it, the app stops working.

You'll know it's running when you see:
```
INFO:     Uvicorn running on http://127.0.0.1:8080
INFO:     Started reloader process
```

**Step 3 — Open the app in your browser:**

```
http://localhost:8080
```

---

## Stopping the app

Go back to the terminal and press `Ctrl + C`.

---

## Notes

- Do not open `index.html` directly in your browser — it won't work without the server running
- Always use `python -m uvicorn` not just `uvicorn` on Windows
- If port 8080 is blocked, try `--port 3000` and go to `http://localhost:3000` instead

---

## API keys needed

- **HaveIBeenPwned** — no key required, uses k-anonymity API
- **VirusTotal** — free key at https://www.virustotal.com/gui/join-us
- **AbuseIPDB** — free key at https://www.abuseipdb.com/register
- **Anthropic or Google AI Studio** — key at https://console.anthropic.com OR https://aistudio.google.com/api-keys

Add keys to a `.env` file in this folder when ready (never commit this file to GitHub).