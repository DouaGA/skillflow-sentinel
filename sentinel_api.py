#!/usr/bin/env python3
"""
FICHIER: sentinel_api.py
ROLE: Microservice de Sécurité & Gouvernance (SkillGuard Sentinel)
AUTEUR: Doua Galai
DATE: Mai 2026
DESCRIPTION: 
Ce microservice agit comme un pare-feu (Firewall) entre le portail SPFx 
et le moteur LLM Hugging Face. Il prévient les injections de prompts (Jailbreaks),
gère les quotas (Rate Limiting) et audite les accès.
"""

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time
from datetime import datetime
import json
import httpx  # Pour faire les appels vers votre HF Space
import asyncio

app = FastAPI(
    title="SkillGuard Sentinel API",
    description="Microservice de sécurité pour la protection du modèle IA SkillFlow",
    version="1.0"
)

# Autoriser le portail SharePoint à communiquer avec ce service
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, mettre l'URL de votre SharePoint
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==========================================
# 🛑 CONFIGURATION DE SÉCURITÉ
# ==========================================

# 1. Règles d'Injection de Prompt (Blacklist)
PROMPT_BLACKLIST = [
    "ignore all previous", 
    "oublie les instructions", 
    "system prompt",
    "donne moi le mot de passe",
    "salary", "salaire", "confidentiel",
    "bypass", "hack"
]

# 2. Configuration du Rate Limiting
MAX_REQUESTS_PER_MINUTE = 5
user_request_counts = {}  # { "email@domaine.com": {"count": 2, "reset_time": 169000000} }

# ==========================================
# 📦 MODÈLES DE DONNÉES
# ==========================================

class ChatRequest(BaseModel):
    user_email: str
    user_role: str
    prompt: str
    context: str = ""

class AuditLog(BaseModel):
    timestamp: str
    user_email: str
    action: str
    status: str
    details: str

# ==========================================
# 🛡️ FONCTIONS DE GOUVERNANCE
# ==========================================

def check_rate_limit(user_email: str) -> bool:
    """Vérifie si l'utilisateur a dépassé son quota de requêtes vers l'IA."""
    current_time = time.time()
    
    if user_email not in user_request_counts:
        user_request_counts[user_email] = {"count": 1, "reset_time": current_time + 60}
        return True
        
    user_data = user_request_counts[user_email]
    
    # Si la minute est écoulée, on reset le compteur
    if current_time > user_data["reset_time"]:
        user_request_counts[user_email] = {"count": 1, "reset_time": current_time + 60}
        return True
        
    # Si le quota est dépassé
    if user_data["count"] >= MAX_REQUESTS_PER_MINUTE:
        return False
        
    # Sinon on incrémente
    user_request_counts[user_email]["count"] += 1
    return True

def detect_prompt_injection(prompt: str) -> bool:
    """Analyse le texte pour détecter des tentatives de manipulation de l'IA."""
    prompt_lower = prompt.lower()
    for forbidden_word in PROMPT_BLACKLIST:
        if forbidden_word in prompt_lower:
            return True
    return False

def audit_log(log_data: AuditLog):
    """Génère un log sécurisé pour la traçabilité RH (Console ou Fichier)."""
    log_entry = f"[{log_data.timestamp}] {log_data.status} | USER: {log_data.user_email} | ACTION: {log_data.action} | DET: {log_data.details}"
    print(f"🔒 AUDIT: {log_entry}")
    # En production : Sauvegarde dans une DB ou fichier log.

# ==========================================
# 🚀 ROUTES DE L'API
# ==========================================

@app.post("/api/secure-chat")
async def secure_chat_endpoint(request: ChatRequest):
    """
    Point d'entrée unique et sécurisé pour discuter avec l'IA.
    C'est ici que le Frontend SPFx doit envoyer ses requêtes.
    """
    
    # 1. VÉRIFICATION DU QUOTA (Rate Limiting)
    if not check_rate_limit(request.user_email):
        audit_log(AuditLog(
            timestamp=datetime.now().isoformat(),
            user_email=request.user_email,
            action="API_REQUEST",
            status="BLOCKED_RATE_LIMIT",
            details="L'utilisateur a dépassé la limite de 5 requêtes par minute."
        ))
        raise HTTPException(status_code=429, detail="Trop de requêtes. Veuillez patienter une minute pour protéger les serveurs IA.")

    # 2. VÉRIFICATION SÉCURITÉ (Anti-Prompt Injection)
    if detect_prompt_injection(request.prompt):
        audit_log(AuditLog(
            timestamp=datetime.now().isoformat(),
            user_email=request.user_email,
            action="API_REQUEST",
            status="BLOCKED_SECURITY",
            details=f"Tentative d'injection détectée. Prompt bloqué."
        ))
        raise HTTPException(status_code=403, detail="ALERTE SÉCURITÉ : Votre question contient des termes non autorisés par la gouvernance SkillFlow.")

    # 3. TOUT EST OK : TRANSMISSION AU MICROSERVICE IA (HF)
    audit_log(AuditLog(
        timestamp=datetime.now().isoformat(),
        user_email=request.user_email,
        action="API_REQUEST",
        status="AUTHORIZED",
        details="Requête saine transmise au moteur LLM."
    ))
    
    try:
        # Note: Ceci est une simulation de l'appel vers votre HF Space
        # Dans un cas réel, vous feriez un httpx.post("https://dgalai-skillflow.hf.space/...")
        
        # Simulation d'un temps de traitement IA
        await asyncio.sleep(1)
        
        return {
            "success": True,
            "message": "Validé par SkillGuard Sentinel",
            "ai_response": f"✨ [RÉPONSE IA] Ceci est la réponse sécurisée pour : '{request.prompt}'"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail="Erreur de communication avec le cerveau IA.")

@app.get("/api/health")
def health_check():
    return {"status": "actif", "protection": "maximale", "service": "SkillGuard Sentinel"}

# Démarrage
if __name__ == "__main__":
    import uvicorn
    print("🛡️ Démarrage de SkillGuard Sentinel...")
    uvicorn.run(app, host="0.0.0.0", port=8000)
