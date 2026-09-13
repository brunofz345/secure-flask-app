"""
Aplicação Web Segura - Flask + OWASP Top 10:2025
Mitiga: A01 (Broken Access Control), A02 (Security Misconfiguration),
        A05 (Injection), A07 (Authentication Failures)
"""
import os
import re
import secrets
import time
from datetime import timedelta

from dotenv import load_dotenv
from flask import (
    Flask, render_template, redirect, url_for,
    request, session, flash, abort
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash

# ── Carrega variáveis de ambiente ──
load_dotenv()

app = Flask(__name__)

# ── A02: Security Misconfiguration ──
# Chave secreta forte e vinda do ambiente (nunca hardcoded)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# A05: Cookies de sessão endurecidos
app.config.update(
    SESSION_COOKIE_SECURE=True,        # Só envia via HTTPS
    SESSION_COOKIE_HTTPONLY=True,      # Bloqueia acesso via JavaScript
    SESSION_COOKIE_SAMESITE="Strict",  # Bloqueia envio cross-site
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,          # Token CSRF expira em 1h
)

# ── A01/A05: Proteção CSRF global ──
csrf = CSRFProtect(app)

# ── "Banco" em memória (substitua por DB real em produção) ──
USERS = {
    "admin": {
        "password_hash": generate_password_hash(
            os.environ.get("ADMIN_PASSWORD", "trocar-esta-senha"),
            method="pbkdf2:sha256:600000"
        ),
        "role": "admin",
    }
}

# ── A07: Rate limiting simples (em memória) ──
LOGIN_ATTEMPTS = {}          # {ip: [timestamps]}
MAX_ATTEMPTS = 5
WINDOW_SECONDS = 300         # 5 minutos


def _rate_limit_ok(ip: str) -> bool:
    """Verifica se o IP ainda pode tentar login."""
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(ip, [])
    # Remove tentativas fora da janela
    attempts = [t for t in attempts if now - t < WINDOW_SECONDS]
    LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) < MAX_ATTEMPTS


def _register_attempt(ip: str):
    """Registra tentativa de login falha."""
    LOGIN_ATTEMPTS.setdefault(ip, []).append(time.time())


def _sanitize_username(raw: str) -> str | None:
    """
    A05: Sanitização e validação de entrada.
    Allowlist: apenas letras, números, ponto e hífen.
    """
    if not raw or not isinstance(raw, str):
        return None
    cleaned = raw.strip().lower()
    if not re.fullmatch(r"[a-z0-9._-]{3,32}", cleaned):
        return None
    return cleaned


def _require_auth():
    """
    A01: Controle de acesso centralizado.
    Verifica autenticação e validade da sessão.
    """
    if "user" not in session:
        abort(401)

    # A07: Timeout de inatividade
    last_active = session.get("last_active", 0)
    if time.time() - last_active > 1800:   # 30 minutos
        session.clear()
        abort(401)

    # Atualiza último acesso
    session["last_active"] = time.time()


# ── Rotas ──

@app.route("/")
def index():
    if "user" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        ip = request.remote_addr or "unknown"

        # A07: Rate limiting
        if not _rate_limit_ok(ip):
            flash("Muitas tentativas. Tente novamente em 5 minutos.", "error")
            return render_template("login.html"), 429

        username = _sanitize_username(request.form.get("username", ""))
        password = request.form.get("password", "")

        # A05: Validação de entrada
        if not username or not password:
            flash("Preencha todos os campos corretamente.", "error")
            return render_template("login.html"), 400

        user_data = USERS.get(username)

        # A07: Comparação segura (constant-time) + hash forte
        valid = (
            user_data is not None
            and check_password_hash(user_data["password_hash"], password)
        )

        if not valid:
            _register_attempt(ip)
            flash("Credenciais inválidas.", "error")
            return render_template("login.html"), 401

        # ── A07: Regenera sessão após login (previne Session Fixation) ──
        session.clear()
        session["user"] = username
        session["role"] = user_data["role"]
        session["last_active"] = time.time()
        session.permanent = True

        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    """Página interna — acessível apenas após autenticação."""
    _require_auth()   # A01: verificação server-side obrigatória
    return render_template("dashboard.html", username=session["user"])


@app.route("/logout", methods=["POST"])
def logout():
    """
    Logout seguro:
    - Requer POST (não GET) → evita logout via CSRF
    - Destrói completamente a sessão
    """
    session.clear()
    flash("Sessão encerrada com sucesso.", "success")
    return redirect(url_for("login"))


# ── A02: Handlers de erro que não vazam informação ──

@app.errorhandler(401)
def unauthorized(e):
    flash("Acesso não autorizado. Faça login.", "error")
    return redirect(url_for("login"))


@app.errorhandler(403)
def forbidden(e):
    return render_template("login.html"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("login.html"), 404


# ── A02: Headers de segurança em todas as respostas ──

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=()"
    )
    return response


if __name__ == "__main__":
    # Nunca use debug=True em produção
    app.run(host="127.0.0.1", port=5000, debug=False)
