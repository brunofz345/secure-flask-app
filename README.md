# 🔐 Secure Flask App — Secure by Design

Aplicação web mínima em **Python + Flask** que demonstra a aplicação prática de
**Secure by Design** com mitigação ativa de vulnerabilidades do **OWASP Top 10:2025**.

## 🚀 Como Executar

```bash
# 1. Clone o repositório
git clone <url-do-repo>
cd secure-flask-app

# 2. Crie e ative o ambiente virtual
python -m venv venv
source venv/bin/activate        # Linux/Mac
# venv\Scripts\activate         # Windows

# 3. Instale as dependências
pip install -r requirements.txt

# 4. Configure o ambiente
cp .env.example .env
# Edite o .env e insira uma SECRET_KEY gerada com:
# python -c "import secrets; print(secrets.token_hex(32))"

# 5. Execute
python app.py

## Estrutura do projeto

secure-flask-app/
├── app.py
├── requirements.txt
├── .env.example
├── static/
│   └── style.css
├── templates/
│   ├── base.html
│   ├── login.html
│   └── dashboard.html
└── README.md
