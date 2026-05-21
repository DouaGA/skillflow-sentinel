#!/usr/bin/env python3
"""
FICHIER: sentinel_api.py
ROLE: Microservice de Sécurité & Gouvernance (SkillGuard Sentinel)
AUTEUR: Doua Galai
DATE: Mai 2026
DESCRIPTION:
Pare-feu entre le portail SPFx et le moteur LLM Hugging Face.
Rate limiting, anti-injection, audit et relais vers le Space HF.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from datetime import datetime
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

logger = logging.getLogger("skillguard.sentinel")
logging.basicConfig(level=logging.INFO)

# ==========================================
# Configuration (variables d'environnement)
# ==========================================

SENTINEL_API_KEY = os.getenv("SENTINEL_API_KEY", "").strip()
HF_TOKEN = os.getenv("HF_TOKEN", "").strip()
HF_REQUEST_TIMEOUT = float(os.getenv("HF_REQUEST_TIMEOUT", "60"))
MAX_REQUESTS_PER_MINUTE = int(os.getenv("MAX_REQUESTS_PER_MINUTE", "5"))

# Modèle HF Inference API (gratuit, aucune clé Groq/Claude requise)
# Fallback automatique si le premier modèle est surchargé
HF_MODELS = [
    "HuggingFaceH4/zephyr-7b-beta",
    "mistralai/Mistral-7B-Instruct-v0.3",
    "microsoft/DialoGPT-medium",
]
HF_INFERENCE_URL = "https://router.huggingface.co/hf-inference/models/{model}/v1/chat/completions"
MAX_PROMPT_LENGTH = int(os.getenv("MAX_PROMPT_LENGTH", "4000"))
MAX_CONTEXT_LENGTH = int(os.getenv("MAX_CONTEXT_LENGTH", "8000"))
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", "*").split(",")
    if origin.strip()
]
ALLOWED_ROLES = {
    role.strip().lower()
    for role in os.getenv(
        "ALLOWED_ROLES", "employee,manager,rh,admin,stagiaire"
    ).split(",")
    if role.strip()
}
AUDIT_LOG_PATH = os.getenv("AUDIT_LOG_PATH", "").strip()
HF_HEALTH_PATH = os.getenv("HF_HEALTH_PATH", "/api/health")

PROMPT_BLACKLIST = [
    term.strip().lower()
    for term in os.getenv(
        "PROMPT_BLACKLIST",
        "ignore all previous,oublie les instructions,system prompt,"
        "donne moi le mot de passe,salary,salaire,confidentiel,bypass,hack",
    ).split(",")
    if term.strip()
]

SHORT_BLACKLIST_TERMS = {term for term in PROMPT_BLACKLIST if len(term) <= 5}

app = FastAPI(
    title="SkillGuard Sentinel API",
    description="Microservice de sécurité pour la protection du modèle IA SkillFlow",
    version="1.1",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["POST", "GET", "OPTIONS"],
    allow_headers=["*"],
)

user_request_counts: dict[str, dict[str, float]] = {}


# ==========================================
# Modèles de données
# ==========================================


class ChatRequest(BaseModel):
    user_email: EmailStr
    user_role: str = Field(..., min_length=1, max_length=64)
    prompt: str = Field(..., min_length=1, max_length=MAX_PROMPT_LENGTH)
    context: str = Field(default="", max_length=MAX_CONTEXT_LENGTH)


class AuditLog(BaseModel):
    timestamp: str
    user_email: str
    action: str
    status: str
    details: str


# ==========================================
# Sécurité & gouvernance
# ==========================================


def verify_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> None:
    """Exige une clé API si SENTINEL_API_KEY est configurée."""
    if not SENTINEL_API_KEY:
        return
    if not x_api_key or x_api_key != SENTINEL_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Clé API invalide ou manquante (en-tête X-API-Key).",
        )


def validate_user_role(user_role: str) -> None:
    role = user_role.strip().lower()
    if role not in ALLOWED_ROLES:
        raise HTTPException(
            status_code=403,
            detail=f"Rôle non autorisé : '{user_role}'. Rôles acceptés : {', '.join(sorted(ALLOWED_ROLES))}.",
        )


def normalize_for_scan(text: str) -> str:
    text = text.lower()
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def term_matches(term: str, text: str) -> bool:
    """Mots courts : frontières de mot pour limiter les faux positifs."""
    if term in SHORT_BLACKLIST_TERMS:
        return bool(re.search(rf"\b{re.escape(term)}\b", text))
    return term in text


def detect_prompt_injection(prompt: str, context: str = "") -> bool:
    scanned = normalize_for_scan(f"{prompt} {context}")
    return any(term_matches(term, scanned) for term in PROMPT_BLACKLIST)


def check_rate_limit(user_email: str) -> bool:
    current_time = time.time()

    if user_email not in user_request_counts:
        user_request_counts[user_email] = {"count": 1, "reset_time": current_time + 60}
        return True

    user_data = user_request_counts[user_email]

    if current_time > user_data["reset_time"]:
        user_request_counts[user_email] = {"count": 1, "reset_time": current_time + 60}
        return True

    if user_data["count"] >= MAX_REQUESTS_PER_MINUTE:
        return False

    user_request_counts[user_email]["count"] += 1
    return True


def audit_log(log_data: AuditLog) -> None:
    log_entry = (
        f"[{log_data.timestamp}] {log_data.status} | "
        f"USER: {log_data.user_email} | ACTION: {log_data.action} | DET: {log_data.details}"
    )
    logger.info("AUDIT: %s", log_entry)
    if AUDIT_LOG_PATH:
        try:
            with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as audit_file:
                audit_file.write(log_entry + "\n")
        except OSError as exc:
            logger.error("Impossible d'écrire le fichier d'audit : %s", exc)


def extract_hf_response(data: Any) -> str:
    if isinstance(data, str):
        return data
    if isinstance(data, dict):
        for key in ("ai_response", "response", "message", "output", "text", "result"):
            value = data.get(key)
            if value is not None and str(value).strip():
                return str(value)
        if "choices" in data and data["choices"]:
            first = data["choices"][0]
            if isinstance(first, dict):
                message = first.get("message") or first.get("text")
                if message:
                    if isinstance(message, dict) and message.get("content"):
                        return str(message["content"])
                    return str(message)
    raise ValueError("Réponse HF sans champ exploitable.")


def _build_system_prompt(context: str, role: str) -> str:
    base = (
        "Tu es SkillBot, l'assistant RH intelligent de SkillFlow AI 2026. "
        "Tu aides les employés, managers et équipes RH à gérer les formations, "
        "parcours de compétences et demandes de formation. "
        "Réponds toujours en français, de façon concise et professionnelle."
    )
    if context:
        base += f"\n\nContexte disponible (données SharePoint en temps réel):\n{context[:3000]}"
    return base


def _context_fallback(prompt: str, context: str) -> str:
    """Réponse intelligente basée sur le contexte SharePoint si l'IA est indisponible."""
    p = prompt.lower()
    
    # 1. Priorité absolue : Rechercher dans le contexte SharePoint (RAG)
    if context:
        ctx_lines = [l.strip() for l in context.split("\n") if l.strip()]
        
        # Extraction des mots-clés : mots > 3 lettres OU chiffres (ex: 30)
        keywords = [w for w in p.replace("?", "").split() if len(w) > 3 or w.isdigit()]
        
        # Trouver les lignes pertinentes
        relevant = []
        for l in ctx_lines:
            # Cas spécial : "ID 30" -> on cherche l'ID exact
            digits = [w for w in p.split() if w.isdigit()]
            if digits:
                if any(f"ID {d}" in l for d in digits):
                    relevant.append(l)
                    continue
            
            # Recherche par mots-clés généraux
            if any(k in l.lower() for k in keywords):
                relevant.append(l)
        
        if relevant:
            return "D'après vos données SharePoint :\n" + "\n".join(relevant[:5])

    # 2. Réponses génériques basées sur l'intention (si aucune donnée spécifique trouvée)
    if any(w in p for w in ["formation", "cours", "catalogue"]):
        return "Consultez le Catalogue de Formations dans votre portail SharePoint pour voir toutes les formations disponibles."
    
    if any(w in p for w in ["demande", "inscription", "inscrire", "statut"]):
        return "Vous pouvez suivre l'état de vos inscriptions dans le portail Employé > Mes Demandes."
    
    if any(w in p for w in ["budget", "coût", "prix"]):
        return "Les informations budgétaires sont accessibles aux Managers et RH dans le portail de gestion."
        
    return (
        "Je suis SkillBot, votre assistant de formation. "
        "Je n'ai pas trouvé de réponse précise dans vos données SharePoint, "
        "mais je peux vous aider sur les formations, demandes ou votre profil."
    )


async def call_hf_llm(request: ChatRequest) -> str:
    """Appelle l'API Inference HF (gratuite) avec fallback automatique sur plusieurs modèles."""
    system_prompt = _build_system_prompt(request.context, request.user_role)
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": request.prompt},
    ]
    payload = {"model": "", "messages": messages, "max_tokens": 512, "temperature": 0.7}

    headers = {"Content-Type": "application/json"}
    if HF_TOKEN:
        headers["Authorization"] = f"Bearer {HF_TOKEN}"

    last_error: Exception | None = None
    async with httpx.AsyncClient(timeout=HF_REQUEST_TIMEOUT) as client:
        for model in HF_MODELS:
            try:
                url = HF_INFERENCE_URL.format(model=model)
                payload["model"] = model
                resp = await client.post(url, json=payload, headers=headers)
                resp.raise_for_status()
                data = resp.json()
                # OpenAI-compatible format
                if "choices" in data and data["choices"]:
                    msg = data["choices"][0].get("message", {})
                    content = msg.get("content", "").strip()
                    if content:
                        logger.info("[Sentinel] Réponse via modèle : %s", model)
                        return content
            except Exception as exc:
                logger.warning("[Sentinel] Modèle %s indisponible : %s", model, exc)
                last_error = exc
                continue

    # Tous les modèles ont échoué  → fallback contextuel (pas d'erreur 502)
    logger.warning("[Sentinel] Tous les modèles HF indisponibles, fallback contextuel.")
    return _context_fallback(request.prompt, request.context)


# ==========================================
# Routes
# ==========================================


@app.on_event("startup")
async def startup_checks() -> None:
    if not SENTINEL_API_KEY:
        logger.warning(
            "SENTINEL_API_KEY non définie : l'API est ouverte (acceptable en dev local uniquement)."
        )
    logger.info("SkillGuard Sentinel prêt — Mode: HF Inference API (Mistral/Zephyr)")


@app.post("/api/secure-chat")
async def secure_chat_endpoint(
    request: ChatRequest,
    _: None = Depends(verify_api_key),
):
    user_email = str(request.user_email)

    validate_user_role(request.user_role)

    if not check_rate_limit(user_email):
        audit_log(
            AuditLog(
                timestamp=datetime.now().isoformat(),
                user_email=user_email,
                action="API_REQUEST",
                status="BLOCKED_RATE_LIMIT",
                details="Quota dépassé.",
            )
        )
        raise HTTPException(
            status_code=429,
            detail="Trop de requêtes. Veuillez patienter une minute pour protéger les serveurs IA.",
        )

    if detect_prompt_injection(request.prompt, request.context):
        audit_log(
            AuditLog(
                timestamp=datetime.now().isoformat(),
                user_email=user_email,
                action="API_REQUEST",
                status="BLOCKED_SECURITY",
                details="Terme interdit détecté dans prompt ou context.",
            )
        )
        raise HTTPException(
            status_code=403,
            detail="ALERTE SÉCURITÉ : Votre question contient des termes non autorisés par la gouvernance SkillFlow.",
        )

    audit_log(
        AuditLog(
            timestamp=datetime.now().isoformat(),
            user_email=user_email,
            action="API_REQUEST",
            status="AUTHORIZED",
            details="Requête transmise au moteur LLM.",
        )
    )

    try:
        ai_response = await call_hf_llm(request)
        return {
            "success": True,
            "message": "Validé par SkillGuard Sentinel",
            "ai_response": ai_response,
        }
    except httpx.HTTPStatusError as exc:
        logger.exception("Erreur HTTP vers HF : %s", exc.response.status_code)
        audit_log(
            AuditLog(
                timestamp=datetime.now().isoformat(),
                user_email=user_email,
                action="HF_RELAY",
                status="ERROR_HTTP",
                details=f"HF status {exc.response.status_code}",
            )
        )
        raise HTTPException(
            status_code=502,
            detail="Le moteur IA est indisponible ou a renvoyé une erreur.",
        ) from exc
    except httpx.RequestError as exc:
        logger.exception("Erreur réseau vers HF : %s", exc)
        audit_log(
            AuditLog(
                timestamp=datetime.now().isoformat(),
                user_email=user_email,
                action="HF_RELAY",
                status="ERROR_NETWORK",
                details=str(type(exc).__name__),
            )
        )
        raise HTTPException(
            status_code=502,
            detail="Impossible de joindre le moteur IA.",
        ) from exc
    except (ValueError, json.JSONDecodeError) as exc:
        logger.exception("Réponse HF invalide : %s", exc)
        audit_log(
            AuditLog(
                timestamp=datetime.now().isoformat(),
                user_email=user_email,
                action="HF_RELAY",
                status="ERROR_PARSE",
                details=str(exc),
            )
        )
        raise HTTPException(
            status_code=502,
            detail="Réponse du moteur IA illisible.",
        ) from exc
    except Exception as exc:
        logger.exception("Erreur inattendue HF : %s", exc)
        audit_log(
            AuditLog(
                timestamp=datetime.now().isoformat(),
                user_email=user_email,
                action="HF_RELAY",
                status="ERROR_UNKNOWN",
                details=str(type(exc).__name__),
            )
        )
        raise HTTPException(
            status_code=500,
            detail="Erreur de communication avec le cerveau IA.",
        ) from exc


@app.get("/api/health")
async def health_check():
    hf_status = "unknown"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{HF_SPACE_URL}{HF_HEALTH_PATH}")
            hf_status = "up" if response.status_code < 500 else "degraded"
    except httpx.RequestError:
        hf_status = "down"

    return {
        "status": "actif",
        "protection": "maximale",
        "service": "SkillGuard Sentinel",
        "hf_space": HF_SPACE_URL,
        "hf_reachable": hf_status,
        "api_key_required": bool(SENTINEL_API_KEY),
    }


if __name__ == "__main__":
    import uvicorn

    print("Démarrage de SkillGuard Sentinel...")
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", "8000")))
