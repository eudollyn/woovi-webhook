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

# ===== ENV =====
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")

WOOVI_APP_ID = os.getenv("WOOVI_APP_ID", "")  # Authorization header
WOOVI_HMAC_SECRET = os.getenv("WOOVI_HMAC_SECRET", "")  # webhook secret (HMAC)
WOOVI_API_BASE = os.getenv("WOOVI_API_BASE", "https://api.woovi.com")  # prod default


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
    try:
        r.raise_for_status()
    except Exception:
        app.logger.error("Erro Telegram: %s %s", r.status_code, r.text[:400])


def verify_hmac_sha1(raw_body: bytes, signature_b64: str) -> bool:
    """
    Valida X-OpenPix-Signature (HMAC-SHA1 base64) — conforme docs OpenPix/Woovi.
    """
    if not WOOVI_HMAC_SECRET:
        # Se você preferir não bloquear, troque para return True
        app.logger.warning("WOOVI_HMAC_SECRET não definido. Bloqueando webhook por segurança.")
        return False

    mac = hmac.new(WOOVI_HMAC_SECRET.encode("utf-8"), raw_body, hashlib.sha1).digest()
    calc = base64.b64encode(mac).decode("utf-8")
    return hmac.compare_digest(calc.strip(), signature_b64.strip())


def extract_charge_info(payload: dict):
    charge = payload.get("charge") or {}
    customer = charge.get("customer") or {}
    name = customer.get("name") or "Cliente não informado"
    value = charge.get("value") or charge.get("amount")
    status = charge.get("status")
    correlation_id = charge.get("correlationID") or charge.get("correlationId")
    identifier = charge.get("identifier") or charge.get("id")
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


@app.get("/")
def home():
    return "OK", 200


@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}), 200


@app.post("/webhook")
def woovi_webhook():
    raw = request.get_data()

    # Assinatura (se vier no header, validamos)
    sig = request.headers.get("X-OpenPix-Signature")
    if sig:
        if not verify_hmac_sha1(raw, sig):
            return jsonify({"error": "invalid signature"}), 401

    payload = request.get_json(silent=True) or {}
    event = payload.get("event", "UNKNOWN")

    info = extract_charge_info(payload)
    cid = info["correlationID"] or info["identifier"] or "—"
    value_brl = brl_from_cents(info["value"]) if info["value"] is not None else "—"

    if event == "OPENPIX:CHARGE_CREATED":
        telegram_send(
            f"🧾 Nova cobrança criada\n"
            f"👤 Cliente: {info['name']}\n"
            f"💰 Valor: {value_brl}\n"
            f"🆔 ID: {cid}\n"
            f"🔗 Link: {info['paymentLink'] or '—'}"
        )
    elif event == "OPENPIX:CHARGE_COMPLETED":
        telegram_send(
            f"✅ PAGAMENTO CONFIRMADO\n"
            f"👤 Cliente: {info['name']}\n"
            f"💰 Valor: {value_brl}\n"
            f"🧾 Cobrança: {cid}"
        )
    elif event == "OPENPIX:CHARGE_EXPIRED":
        telegram_send(
            f"⏳ Cobrança expirada\n"
            f"👤 Cliente: {info['name']}\n"
            f"💰 Valor: {value_brl}\n"
            f"🧾 Cobrança: {cid}"
        )
    else:
        app.logger.info("Evento recebido: %s", event)

    return jsonify({"status": "recebido"}), 200


@app.post("/create-charge")
def create_charge():
    """
    Cria cobrança via API Woovi.
    Body:
    {
      "value": 1500,  # centavos
      "name": "Fulano" (opcional),
      "email": "..." (opcional),
      "phone": "..." (opcional),
      "taxID": "..." (opcional),
      "correlationID": "..." (opcional),
      "comment": "..." (opcional)
    }
    """
    if not WOOVI_APP_ID:
        return jsonify({"error": "WOOVI_APP_ID not set"}), 500

    data = request.get_json(force=True)
    if "value" not in data:
        return jsonify({"error": "missing value"}), 400

    correlation_id = data.get("correlationID") or str(uuid.uuid4())

    payload = {
        "value": int(data["value"]),
        "correlationID": correlation_id,
    }

    customer_fields = {k: data.get(k) for k in ["name", "email", "phone", "taxID"]}
    customer_fields = {k: v for k, v in customer_fields.items() if v}
    if customer_fields:
        payload["customer"] = customer_fields

    if data.get("comment"):
        payload["comment"] = data["comment"]

    url = f"{WOOVI_API_BASE}/api/v1/charge"
    headers = {
        "Authorization": WOOVI_APP_ID,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=20)
    if r.status_code >= 400:
        return jsonify({"error": "woovi_error", "status": r.status_code, "body": r.text}), 400

    resp = r.json()
    charge = resp.get("charge") or {}
    return jsonify({
        "correlationID": correlation_id,
        "paymentLinkUrl": charge.get("paymentLinkUrl"),
        "qrCodeImage": charge.get("qrCodeImage"),
        "brCode": charge.get("brCode"),
        "identifier": charge.get("identifier"),
        "status": charge.get("status"),
    }), 200
