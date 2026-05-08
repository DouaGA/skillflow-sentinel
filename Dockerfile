FROM python:3.10-slim

# Créer l'utilisateur pour Hugging Face Spaces
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH

WORKDIR $HOME/app

# Copier et installer les dépendances
COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copier le code du Sentinel
COPY --chown=user sentinel_api.py .

# Exposer le port pour Render
EXPOSE 8000

# Lancer l'API FastAPI en utilisant le port dynamique de Render (ou 8000 par défaut)
CMD sh -c "uvicorn sentinel_api:app --host 0.0.0.0 --port ${PORT:-8000}"
