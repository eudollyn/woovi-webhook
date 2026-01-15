import os
import json
import hmac
import hashlib
import base64
import uuid
from datetime import datetime
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

# ====== ENV ======
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
WOOVI_APP_ID = os.getenv("WOOVI_APP_ID", "")  # Authorization header da Woovi
WOOVI_HMAC_SECRET = os.getenv("WOOVI_HMAC_SECRET", "")  # secret do webhook (HMAC)
WOOVI_API_BASE = os.getenv("WOOVI_API_BASE", "https://api.woovi.com")  # produção
# Para sandbox: https://api.woovi-sandbox.com

# ====== Helpers ======
def brl_from_cents(value_cents) -> str:
    try:
        v = int(value_cents)
        return f"R$ {v/100:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except Exception:
        return f"R$ {value_cents}"

def telegram_send(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        app.logger.warning("Telegram env vars não configuradas.")
        return

    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True
    }
    r = requests.post(url, json=payload, timeout=15)
    r.raise_for_status()

def verify_hmac_sha1(raw_body: bytes, signature_b64: str) -> bool:
    """
    Valida o header X-OpenPix-Signature (HMAC-SHA1 em base64)
    conforme doc OpenPix/Woovi.
    """
    if not WOOVI_HMAC_SECRET:
        app.logger.warning("WOOVI_HMAC_SECRET não definido. Bloqueando por segurança.")
        return False

    mac = hmac.new(WOOVI_HMAC_SECRET.encode("utf-8"), raw_body, hashlib.sha1).digest()
    calc = base64.b64encode(mac).decode("utf-8")
    # compare seguro
    return hmac.compare_digest(calc, signature_b64.strip())

def extract_charge_info(payload: dict):
    charge = payload.get("charge") or {}
    customer = charge.get("customer") or {}
    name = customer.get("name") or "Cliente não informado"
    value = charge.get("value")
    status = charge.get("status")
    correlation_id = charge.get("correlationID")
    identifier = charge.get("identifier")
    payment_link = charge.get("paymentLinkUrl") or charge.get("paymentLinkID")
    brcode = charge.get("brCode")
    return {
        "name": name,
        "value": value,
        "status": status,
        "correlationID": correlation_id,
        "identifier": identifier,
        "paymentLink": payment_link,
        "brCode": brcode
    }

# ====== Routes ======
@app.get("/")
def home():
    return "OK", 200

@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}), 200

@app.post("/webhook")
def woovi_webhook():
    raw = request.get_data()  # bytes do body (importante para assinatura)
    # 1) valida assinatura HMAC se vier header
    sig_openpix = request.headers.get("X-OpenPix-Signature")
    if sig_openpix:
        if not verify_hmac_sha1(raw, sig_openpix):
            return jsonify({"error": "invalid signature"}), 401

    payload = request.get_json(silent=True) or {}
    event = payload.get("event", "UNKNOWN")

    info = extract_charge_info(payload)

    # 2) Mensagens por evento
    if event == "OPENPIX:CHARGE_CREATED":
        msg = (
            "🧾 *Nova cobrança criada*\n"
            f"👤 Cliente: {info['name']}\n"
            f"💰 Valor: {brl_from_cents(info['value'])}\n"
            f"🆔 ID: {info['correlationID'] or info['identifier']}\n"
            f"🔗 Link: {info['paymentLink'] or '—'}\n"
        )
        telegram_send(msg.replace("*", ""))

    elif event == "OPENPIX:CHARGE_COMPLETED":
        msg = (
            "✅ *Pagamento confirmado*\n"
            f"👤 Cliente: {info['name']}\n"
            f"💰 Valor: {brl_from_cents(info['value'])}\n"
            f"🧾 Cobrança: {info['correlationID'] or info['identifier']}\n"
        )
        telegram_send(msg.replace("*", ""))

    elif event == "OPENPIX:CHARGE_EXPIRED":
        msg = (
            "⏳ *Cobrança expirada*\n"
            f"👤 Cliente: {info['name']}\n"
            f"💰 Valor: {brl_from_cents(info['value'])}\n"
            f"🧾 Cobrança: {info['correlationID'] or info['identifier']}\n"
        )
        telegram_send(msg.replace("*", ""))

    else:
        # opcional: logar eventos desconhecidos
        app.logger.info(f"Evento recebido: {event}")

    return jsonify({"status": "recebido"}), 200

@app.post("/create-charge")
def create_charge():
    """
    Cria cobrança via API Woovi.
    Body esperado:
    {
      "value": 1500,  # centavos
      "name": "Fulano", (opcional)
      "email": "...", (opcional)
      "phone": "...", (opcional)
      "taxID": "...", (opcional)
      "correlationID": "..." (opcional)
      "comment": "..." (opcional)
    }
    """
    if not WOOVI_A_
