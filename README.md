# 🔐 Secure Flask App — Secure by Design

Protótipo web em **Python + Flask** desenvolvido com foco em **Secure by Design**,
sem banco de dados e sem separação front-end/back-end. O projeto atende aos
requisitos mínimos exigidos (tela de login, página interna autenticada e logout
funcional) e mitiga ativamente **4 categorias do OWASP Top 10:2025**.

---

## 📌 Requisitos Mínimos Atendidos

| # | Requisito | Implementação | Como Testar |
|---|-----------|---------------|-------------|
| 1 | **Tela de Login** | Rota `GET/POST /login` + `templates/login.html` | Acessar `http://127.0.0.1:5000/login` |
| 2 | **Página interna (pós-login)** | Rota `GET /dashboard` protegida por `_require_auth()` + `templates/dashboard.html` | Tentar acessar `/dashboard` sem login → redireciona para `/login` |
| 3 | **Botão de Logout funcional** | Rota `POST /logout` + botão em `dashboard.html` | Clicar em "Sair" no dashboard |

**Credenciais de teste:**
- Usuário: `admin`
- Senha: `SenhaSuperForte!2025#`

---

## 🛡️ Categorias do OWASP Top 10:2025 Mitigadas

> O requisito mínimo era mitigar **3 categorias**. Este projeto mitiga **4**,
> superando a exigência.

### 🔴 A01:2025 — Broken Access Control (Controle de Acesso Quebrado)

**O que é:** Usuários conseguem agir fora das permissões pretendidas —
acessam páginas, dados ou funcionalidades restritas por falha na verificação
de autorização.

#### 🎯 Onde está a prevenção no código

| Arquivo | Função / Trecho | O que faz |
|---------|-----------------|-----------|
| `app.py` | `_require_auth()` | Verifica **no servidor** se a sessão existe e se está válida antes de liberar a rota `/dashboard`. |
| `app.py` | `@app.route("/dashboard")` | Chama `_require_auth()` como **primeira instrução** — sem confiar em nada vindo do cliente. |
| `app.py` | `@app.route("/logout", methods=["POST"])` | Restringe o logout a **POST** (não GET), impedindo acionamento por link malicioso. |
| `templates/dashboard.html` | `<form method="POST">` no logout | Força envio via POST com token CSRF, bloqueando logout cross-site. |

#### 🔒 Como funciona (fluxo real)

```python
def _require_auth():
    # 1. Sem sessão → 401
    if "user" not in session:
        abort(401)
    # 2. Sessão expirada por inatividade → limpa e 401
    if time.time() - session.get("last_active", 0) > 1800:
        session.clear()
        abort(401)
    # 3. Renova timestamp de atividade
    session["last_active"] = time.time()
```

**Teste:** acessar `/dashboard` sem login → redireciona para `/login`.
**Teste 2:** acessar `/logout` via GET → retorna `405 Method Not Allowed`.

---

### 🔴 A02:2025 — Security Misconfiguration (Configuração Insegura)

**O que é:** Configurações fracas ou padrão — chaves hardcoded, debug ativo em
produção, headers de segurança ausentes, mensagens de erro verbosas.

#### 🎯 Onde está a prevenção no código

| Arquivo | Trecho | O que faz |
|---------|--------|-----------|
| `app.py` | `app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY")` | Chave secreta vem de variável de ambiente, **nunca hardcoded**. |
| `app.py` | `app.config.update(SESSION_COOKIE_SECURE=True, HTTPONLY=True, SAMESITE="Strict")` | Endurece o cookie de sessão contra interceptação (XSS/CSRF). |
| `app.py` | `app.run(debug=False)` | Desativa debug em execução — evita vazamento de stack traces. |
| `app.py` | `@app.after_request` → `set_security_headers()` | Injeta `CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options` e `Referrer-Policy` em **todas** as respostas. |
| `app.py` | `@app.errorhandler(401/403/404)` | Trata erros sem vazar estrutura interna (sem stack traces). |
| `.env.example` | Documentação | Instrui geração da chave com `secrets.token_hex(32)`. |

#### 🔒 Como funciona (headers injetados)

```python
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Content-Security-Policy"] = "default-src 'self'; ..."
    response.headers["Strict-Transport-Security"] = "max-age=31536000; ..."
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
```

**Teste:** inspecionar a resposta HTTP no DevTools (aba Network) → headers presentes.

---

### 🔴 A05:2025 — Injection (Injeção)

**O que é:** Dados não confiáveis do usuário são interpretados como código —
SQL Injection, XSS, Command Injection, CSRF.

#### 🎯 Onde está a prevenção no código

| Arquivo | Função / Trecho | O que faz |
|---------|-----------------|-----------|
| `app.py` | `_sanitize_username()` | Valida o input com **allowlist** (`[a-z0-9._-]{3,32}`) via `re.fullmatch()`. Qualquer caractere fora do padrão é rejeitado. |
| `app.py` | `login()` | Aplica `_sanitize_username()` **antes** de qualquer uso do dado. |
| `app.py` | `csrf = CSRFProtect(app)` | Proteção CSRF global em todos os formulários POST. |
| `templates/login.html` | `{{ csrf_token() }}` | Token CSRF embutido no formulário de login. |
| `templates/dashboard.html` | `{{ csrf_token() }}` | Token CSRF embutido no formulário de logout. |
| Todos os templates | Jinja2 auto-escaping | Escapa HTML automaticamente — previne XSS refletido/armazenado. |

#### 🔒 Como funciona (sanitização)

```python
def _sanitize_username(raw: str) -> str | None:
    cleaned = raw.strip().lower()
    # Allowlist — apenas letras, números, ponto e hífen
    if not re.fullmatch(r"[a-z0-9._-]{3,32}", cleaned):
        return None
    return cleaned
```

**Teste 1:** tentar login com usuário `admin' OR '1'='1` → rejeitado pela regex.
**Teste 2:** enviar POST sem `csrf_token` → erro 400 (CSRF bloqueado).

---

### 🔴 A07:2025 — Identification and Authentication Failures

**O que é:** Falhas de autenticação — senhas fracas, ausência de rate limiting,
sessões não regeneradas, comparações não constant-time.

#### 🎯 Onde está a prevenção no código

| Arquivo | Função / Trecho | O que faz |
|---------|-----------------|-----------|
| `app.py` | `generate_password_hash(..., method="pbkdf2:sha256:600000")` | Armazena senha com hash forte (600.000 iterações). |
| `app.py` | `check_password_hash()` | Comparação **constant-time** — evita timing attacks. |
| `app.py` | `_rate_limit_ok(ip)` | Máx. 5 tentativas por IP em 5 minutos → bloqueia brute-force. |
| `app.py` | `_register_attempt(ip)` | Registra tentativas falhas em janela deslizante. |
| `app.py` | `session.clear()` **antes** de criar nova sessão pós-login | Previne **Session Fixation**. |
| `app.py` | `PERMANENT_SESSION_LIFETIME=30min` + `last_active` | Expira sessão por inatividade. |
| `app.py` | `SESSION_COOKIE_HTTPONLY=True` + `SECURE=True` + `SAMESITE=Strict` | Endurece cookies contra roubo via XSS e envio cross-site. |

#### 🔒 Como funciona (rate limiting + sessão regenerada)

```python
# Rate limiting
if not _rate_limit_ok(ip):
    flash("Muitas tentativas. Tente novamente em 5 minutos.", "error")
    return render_template("login.html"), 429

# ... validação da senha ...

# Regeneração de sessão (anti-fixation)
session.clear()
session["user"] = username
session["role"] = user_data["role"]
session["last_active"] = time.time()
session.permanent = True
```

**Teste:** errar a senha 5 vezes seguidas → 6ª tentativa retorna `429 Too Many Requests`.

---

## 📊 Resumo das Mitigações

| Categoria OWASP | Vetor mitigado | Onde no código |
|-----------------|----------------|----------------|
| **A01:2025** — Broken Access Control | Acesso direto a `/dashboard` sem login | `_require_auth()` + rotas em `app.py` |
| **A02:2025** — Security Misconfiguration | Chave hardcoded, headers ausentes, debug ativo | `app.config`, `@app.after_request`, `debug=False` |
| **A05:2025** — Injection | XSS, CSRF, input malicioso no login | `_sanitize_username()`, `CSRFProtect`, `{{ csrf_token() }}` |
| **A07:2025** — Authentication Failures | Brute-force, session fixation, senhas em texto plano | `pbkdf2`, `_rate_limit_ok()`, `session.clear()` |

---

## 🚀 Como Executar

```bash
# 1. Clonar
git clone <url-do-repo>
cd secure-flask-app

# 2. Ambiente virtual
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# 3. Dependências
pip install -r requirements.txt

# 4. Configurar ambiente
cp .env.example .env
python -c "import secrets; print(secrets.token_hex(32))"
# → cole o valor em SECRET_KEY no .env

# 5. Executar
python app.py
```

Acesse `http://127.0.0.1:5000` e faça login com `admin` / `SenhaSuperForte!2025#`.

---

## 🤖 Codificação Assistida por IA

Este projeto foi desenvolvido com auxílio de **IA generativa** (Google
Antigravity / ChatGPT) para:

1. **Geração inicial:** estrutura Flask, templates e configuração de segurança.
2. **Auditoria:** revisão cruzada com o OWASP Top 10:2025 — identificando
   pontos fracos (ex.: ausência de `SameSite=Strict`, exposição de `debug=True`,
   falta de rate limiting) e propondo correções.
3. **Refatoração:** centralização da checagem de autenticação em `_require_auth()`,
   endurecimento de headers HTTP e sanitização com allowlist.

O fluxo seguiu o princípio **Secure by Design**: a segurança foi tratada desde a
arquitetura inicial, não como uma camada adicionada posteriormente.

---

## ⚠️ Limitações Conhecidas

Este é um **protótipo didático**. Para uso em produção, recomenda-se:

- Substituir o dicionário em memória (`USERS`) por banco de dados com queries
  parametrizadas.
- Migrar rate limiting para Redis (persistente e distribuído).
- Adicionar autenticação em dois fatores (2FA).
- Implementar logging estruturado de eventos de segurança.
- Executar `pip-audit` e `bandit` no pipeline de CI/CD.
- Forçar HTTPS com redirecionamento e certificado válido.

---

## 📜 Licença

Distribuído sob a **MIT License** — consulte o arquivo `LICENSE`.

---

## 🚀 Pipeline CI/CD (GitHub Actions)

Toda vez que um `git push origin main` é executado, a pipeline automatiza:

1. **Testes e auditoria de segurança** (`pip-audit` + `bandit`)
2. **Deploy em produção** via SSH + `rsync`
3. **Reinício do serviço** com `systemctl`
4. **Health check** — valida resposta HTTP 200 em `/login`

---

### 🔐 Gerenciamento de Credenciais

**Nenhuma credencial está no código.** Todas são armazenadas em
**GitHub Secrets** (Settings → Secrets and variables → Actions):

| Secret | Uso |
|--------|-----|
| `SSH_HOST` | Endereço do servidor |
| `SSH_USER` | Usuário SSH dedicado |
| `SSH_PORT` | Porta SSH |
| `SSH_PRIVATE_KEY` | Chave privada SSH (ed25519) |
| `SECRET_KEY_TEST` | Chave Flask usada apenas no job de testes |

---

### 🛡️ Boas Práticas Aplicadas

- ✅ `permissions: contents: read` — princípio do menor privilégio
- ✅ `concurrency` — evita deploys paralelos conflitantes
- ✅ `ssh-keyscan` + `known_hosts` — previne ataques MITM
- ✅ Chave SSH **ed25519** (mais forte que RSA)
- ✅ Usuário `deploy` dedicado com sudoers restrito
- ✅ `.env` gerado **no servidor**, nunca trafega pela pipeline
- ✅ Auditoria de segurança (`pip-audit`, `bandit`) antes do deploy
- ✅ Job `deploy` só executa se `test` passar (`needs: test`)
- ✅ `environment: production` — permite aprovação manual se configurado

---

### 🧪 Como Testar

```bash
# No seu computador
git add .
git commit -m "test: dispara pipeline"
git push origin main
```

Acompanhe em: **GitHub → Actions → 🚀 Deploy para Produção**

O deploy só é considerado bem-sucedido se o health check retornar HTTP 200.
