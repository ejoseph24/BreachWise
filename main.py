import base64
import hashlib
import ipaddress
import os
import string
from typing import Optional

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from google import genai
from google.genai import types
from pydantic import BaseModel

load_dotenv()

app = FastAPI(title="BreachWise")

GEMINI_MODEL = "gemini-2.5-flash"
HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/{prefix}"

GENERIC_ERROR_MESSAGE = "Something went wrong — please try again in a moment."
AI_UNAVAILABLE_MESSAGE = "AI analysis is temporarily unavailable. Please try again later."


class ExternalServiceError(Exception):
    """Raised when a call to an external API (HIBP, VirusTotal, AbuseIPDB, Gemini) fails."""


ANALYSIS_SYSTEM_PROMPT = (
    "You are a friendly, calm security assistant inside BreachWise. Think of yourself as "
    "a helpful neighbor who knows about cybersecurity — not an alarm system. A user just "
    "checked their password. You've been given how many times it appeared in known data "
    "breaches, a strength score out of 100, and a strength label. Respond in this order: "
    "1. Reassure them first — briefly acknowledge what the results mean without making "
    "them feel bad or scared. Use plain, warm language anyone can understand including "
    "seniors who may not be tech-savvy. 2. Give 2-3 simple, specific fixes in everyday "
    "language (for example: 'try making it longer, like a short phrase you'd remember' "
    "instead of 'increase entropy'). 3. Gently mention that with those changes it would "
    "be much harder to crack. 4. Kindly suggest a password manager like Bitwarden or "
    "KeyPass (both are free) to help them remember it. Keep it under 5 sentences. No "
    "bullet points. Warm, encouraging, never alarming."
)

URL_ANALYSIS_SYSTEM_PROMPT = (
    "You are a friendly, calm security assistant inside BreachWise. Think of yourself as "
    "a helpful neighbor who knows about cybersecurity — not an alarm system. A user just "
    "checked a URL or IP address for its reputation. You've been given how many security "
    "vendors flagged it as malicious vs clean, an abuse confidence score from AbuseIPDB "
    "(only present if the input was an IP address), and an overall verdict of Clean, "
    "Suspicious, or Malicious. Respond in this order: 1. Reassure them first — briefly "
    "explain what the results mean in plain, warm language anyone can understand, "
    "including people who aren't tech-savvy. 2. If the verdict is Suspicious or "
    "Malicious, gently explain what that could mean and give 2-3 simple, practical next "
    "steps (like avoiding the site, not entering personal information, or double "
    "checking the web address). If the verdict is Clean, reassure them it looks safe "
    "while gently reminding them to stay cautious online. Keep it under 5 sentences. No "
    "bullet points. Warm, encouraging, never alarming."
)

ENHANCE_PASSWORD_SYSTEM_PROMPT = (
    "The user has a weak password. Suggest 3 stronger alternatives that are variations "
    "of their password — keeping it recognizable but adding length, numbers, and "
    "special characters. Format your response as exactly 3 suggestions, each on its own "
    "line, nothing else."
)


class PasswordCheckRequest(BaseModel):
    password: str


class UrlCheckRequest(BaseModel):
    url_or_ip: str


class AnalyzePasswordRequest(BaseModel):
    breach_count: int
    strength_score: int
    strength_label: str
    failures: list[str] = []


class AnalyzeUrlRequest(BaseModel):
    input: str
    virustotal_malicious: int
    virustotal_clean: int
    abuseipdb_score: Optional[int] = None
    verdict: str


class EnhancePasswordRequest(BaseModel):
    password: str


# ---------------------------------------------------------------------------
# Global error handling — guarantees every response is JSON, even for errors
# that aren't explicitly caught inside a route.
# ---------------------------------------------------------------------------


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"error": "Invalid request data."})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    return JSONResponse(status_code=500, content={"error": GENERIC_ERROR_MESSAGE})


def score_password(password: str) -> tuple[int, list[str]]:
    score = 0
    failures = []

    length = len(password)
    if length < 8:
        score += 0
        failures.append("too short")
    elif length <= 11:
        score += 20
    elif length <= 15:
        score += 30
    else:
        score += 40

    if any(c.isupper() for c in password):
        score += 15
    else:
        failures.append("no uppercase letters")

    if any(c.islower() for c in password):
        score += 10
    else:
        failures.append("no lowercase letters")

    if any(c.isdigit() for c in password):
        score += 15
    else:
        failures.append("no numbers")

    if any(c in string.punctuation for c in password):
        score += 20
    else:
        failures.append("no special characters")

    return score, failures


def score_to_label(score: int) -> str:
    if score <= 20:
        return "Very weak"
    if score <= 40:
        return "Weak"
    if score <= 60:
        return "Moderate"
    if score <= 80:
        return "Strong"
    return "Very strong"


async def get_breach_count(password: str) -> int:
    sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(HIBP_RANGE_URL.format(prefix=prefix))
            response.raise_for_status()
    except httpx.HTTPError as exc:
        raise ExternalServiceError("Have I Been Pwned lookup failed.") from exc

    try:
        for line in response.text.splitlines():
            hash_suffix, count = line.split(":")
            if hash_suffix == suffix:
                return int(count)
    except (ValueError, IndexError) as exc:
        raise ExternalServiceError("Have I Been Pwned returned an unexpected response.") from exc

    return 0


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def get_virustotal_report(url_or_ip: str, is_ip: bool) -> tuple[int, int]:
    headers = {"x-apikey": os.getenv("VIRUSTOTAL_API_KEY")}

    if is_ip:
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{url_or_ip}"
    else:
        url_id = base64.urlsafe_b64encode(url_or_ip.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(endpoint, headers=headers)
            response.raise_for_status()
        stats = response.json()["data"]["attributes"]["last_analysis_stats"]
    except httpx.HTTPError as exc:
        raise ExternalServiceError("VirusTotal lookup failed.") from exc
    except (KeyError, ValueError, TypeError) as exc:
        raise ExternalServiceError("VirusTotal returned an unexpected response.") from exc

    return stats.get("malicious", 0), stats.get("harmless", 0)


async def get_abuseipdb_score(ip: str) -> int:
    headers = {"Key": os.getenv("ABUSEIPDB_API_KEY"), "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                "https://api.abuseipdb.com/api/v2/check", headers=headers, params=params
            )
            response.raise_for_status()
        return response.json()["data"]["abuseConfidenceScore"]
    except httpx.HTTPError as exc:
        raise ExternalServiceError("AbuseIPDB lookup failed.") from exc
    except (KeyError, ValueError, TypeError) as exc:
        raise ExternalServiceError("AbuseIPDB returned an unexpected response.") from exc


def compute_verdict(malicious: int, abuse_score: Optional[int]) -> str:
    if malicious >= 5 or (abuse_score is not None and abuse_score >= 75):
        return "Malicious"
    if malicious >= 1 or (abuse_score is not None and abuse_score >= 25):
        return "Suspicious"
    return "Clean"


def generate_gemini_response(system_prompt: str, user_message: str) -> str:
    try:
        genai_client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
        response = genai_client.models.generate_content(
            model=GEMINI_MODEL,
            contents=user_message,
            config=types.GenerateContentConfig(system_instruction=system_prompt),
        )
    except Exception as exc:
        raise ExternalServiceError("Gemini request failed.") from exc

    text = getattr(response, "text", None)
    if not text:
        raise ExternalServiceError("Gemini returned an empty response.")

    return text


@app.post("/check-password")
async def check_password(payload: PasswordCheckRequest):
    if not payload.password:
        return JSONResponse(status_code=400, content={"error": "Password cannot be empty."})

    try:
        breach_count = await get_breach_count(payload.password)
    except ExternalServiceError:
        return JSONResponse(
            status_code=500,
            content={"error": "We couldn't check breach data right now. Please try again in a moment."},
        )

    strength_score, failures = score_password(payload.password)
    strength_label = score_to_label(strength_score)

    return {
        "breach_count": breach_count,
        "strength_score": strength_score,
        "strength_label": strength_label,
        "failures": failures,
    }


@app.post("/analyze-password")
def analyze_password(payload: AnalyzePasswordRequest):
    if not os.getenv("GEMINI_API_KEY"):
        return JSONResponse(status_code=500, content={"error": AI_UNAVAILABLE_MESSAGE})

    failures_text = ", ".join(payload.failures) if payload.failures else "none"
    user_message = (
        f"Password results: found in {payload.breach_count} breaches, strength score "
        f"{payload.strength_score}/100, label: {payload.strength_label}. Specific "
        f"weaknesses: {failures_text}."
    )

    try:
        analysis = generate_gemini_response(ANALYSIS_SYSTEM_PROMPT, user_message)
    except ExternalServiceError as e:
        print(f"ERROR in /analyze-password: {type(e).__name__}: {e}")
        return JSONResponse(status_code=500, content={"error": GENERIC_ERROR_MESSAGE})

    return {"analysis": analysis}


@app.post("/enhance-password")
def enhance_password(payload: EnhancePasswordRequest):
    if not payload.password:
        return JSONResponse(status_code=400, content={"error": "Password cannot be empty."})

    if not os.getenv("GEMINI_API_KEY"):
        return JSONResponse(status_code=500, content={"error": AI_UNAVAILABLE_MESSAGE})

    user_message = f"Password: {payload.password}"

    try:
        analysis = generate_gemini_response(ENHANCE_PASSWORD_SYSTEM_PROMPT, user_message)
    except ExternalServiceError as e:
        print(f"ERROR in /enhance-password: {type(e).__name__}: {e}")
        return JSONResponse(status_code=500, content={"error": GENERIC_ERROR_MESSAGE})

    suggestions = [line.strip() for line in analysis.strip().splitlines() if line.strip()]

    if not suggestions:
        return JSONResponse(status_code=500, content={"error": GENERIC_ERROR_MESSAGE})

    return {"suggestions": suggestions}


@app.post("/check-url")
async def check_url(payload: UrlCheckRequest):
    url_or_ip = payload.url_or_ip.strip()
    if not url_or_ip:
        return JSONResponse(
            status_code=400, content={"error": "Please enter a URL or IP address."}
        )

    is_ip = is_ip_address(url_or_ip)

    try:
        virustotal_malicious, virustotal_clean = await get_virustotal_report(url_or_ip, is_ip)
        abuseipdb_score = await get_abuseipdb_score(url_or_ip) if is_ip else None
    except ExternalServiceError:
        return JSONResponse(
            status_code=500,
            content={"error": "We couldn't check this URL/IP right now. Please try again in a moment."},
        )

    verdict = compute_verdict(virustotal_malicious, abuseipdb_score)

    return {
        "input": url_or_ip,
        "virustotal_malicious": virustotal_malicious,
        "virustotal_clean": virustotal_clean,
        "abuseipdb_score": abuseipdb_score,
        "verdict": verdict,
    }


@app.post("/analyze-url")
def analyze_url(payload: AnalyzeUrlRequest):
    if not os.getenv("GEMINI_API_KEY"):
        return JSONResponse(status_code=500, content={"error": AI_UNAVAILABLE_MESSAGE})

    abuse_score_text = (
        f"{payload.abuseipdb_score}/100"
        if payload.abuseipdb_score is not None
        else "not applicable (not an IP address)"
    )
    user_message = (
        f"URL/IP results for {payload.input}: flagged malicious by "
        f"{payload.virustotal_malicious} security vendors, clean by "
        f"{payload.virustotal_clean} security vendors, AbuseIPDB abuse score: "
        f"{abuse_score_text}, verdict: {payload.verdict}."
    )

    try:
        analysis = generate_gemini_response(URL_ANALYSIS_SYSTEM_PROMPT, user_message)
    except ExternalServiceError as e:
        print(f"ERROR in /analyze-url: {type(e).__name__}: {e}")
        return JSONResponse(status_code=500, content={"error": GENERIC_ERROR_MESSAGE})

    return {"analysis": analysis}


app.mount("/", StaticFiles(directory="static", html=True), name="static")
