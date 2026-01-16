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

WOOVI_APP_ID = os.getenv("WOOVI_APP_ID", "")  # Authorization header (AppID)
WOOVI_HMAC_SECRET = os.getenv("WOOVI_HMAC_SECRET", "")  # webhook secret (HMAC)
# Produção oficial: https://api.openpix.com.br | Sandbox: https://api.woovi-sandbox.com
WOOVI_API_BASE = os.getenv("WOOVI_API_BASE", "https://api.openpix.com.br")

# Chamada para o seu servidor do BOT (Oracle)
BOT_CALLBACK_URL = os.getenv("BOT_CALLBACK_URL", "")  # ex: https://SEU-DOMINIO-DO-BOT/woovi/callback
BOT_CALLBACK_SECRET = os.getenv("BOT_CALLBACK_SECRET", "")  # string forte

BGD_RECEIVER_URL = os.getenv("BGD_RECEIVER_URL", "")
BGD_RECEIVER_SECRET = os.getenv("BGD_RECEIVER_SECRET", "")

# Se quiser, evita duplicidade por re-tentativas de webhook
PROCESSED_CACHE = set()


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
    Valida X-OpenPix-Signature (HMAC-SHA1 base64)
    """
    if not WOOVI_HMAC_SECRET:
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


def notify_bot_payment_completed(info: dict, event: str):
    """
    Chama o endpoint do BOT (no seu servidor Oracle) para creditar saldo automaticamente.
    """
    if not BOT_CALLBACK_URL or not BOT_CALLBACK_SECRET:
        app.logger.warning("BOT_CALLBACK_URL/SECRET não configurados. Não vou creditar automaticamente.")
        return

    payload = {
        "event": event,
        "correlationID": info.get("correlationID"),
        "identifier": info.get("identifier"),
        "value": info.get("value"),
        "customer_name": info.get("name"),
        "ts": datetime.utcnow().isoformat() + "Z"
    }

    headers = {
        "Content-Type": "application/json",
        "X-BGD-SECRET": BOT_CALLBACK_SECRET,
    }

    try:
        r = requests.post(BOT_CALLBACK_URL, json=payload, headers=headers, timeout=15)
        if r.status_code >= 400:
            app.logger.error("Callback BOT falhou: %s %s", r.status_code, r.text[:300])
        return
    except Exception as e:
        app.logger.exception("Erro chamando BOT_CALLBACK_URL: %s", e)


@app.get("/")
def home():
    return "OK", 200


@app.get("/health")
def health():
    return jsonify({"ok": True, "ts": datetime.utcnow().isoformat() + "Z"}), 200


@app.post("/webhook")
def woovi_webhook():
    raw = request.get_data()

    sig = request.headers.get("X-OpenPix-Signature")
    if sig:
        if not verify_hmac_sha1(raw, sig):
            return jsonify({"error": "invalid signature"}), 401

    payload = request.get_json(silent=True) or {}
    event = payload.get("event", "UNKNOWN")

    info = extract_charge_info(payload)
    cid = info["correlationID"] or info["identifier"] or "—"
    value_brl = brl_from_cents(info["value"]) if info["value"] is not None else "—"

    # Anti-duplicidade simples (webhook pode reenviar)
    dedup_key = f"{event}|{cid}"
    if dedup_key in PROCESSED_CACHE:
        return jsonify({"status": "duplicate_ignored"}), 200
    PROCESSED_CACHE.add(dedup_key)

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

        # ✅ aqui é a INTEGRAÇÃO REAL (crédito automático no bot)
        payer = info["name"]
        notify_receiver(event, cid, info["value"], payer)
        notify_bot_payment_completed(info, event)

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

def notify_receiver(event: str, correlation_id: str, value_cents: int, payer_name: str = "—"):
    if not BGD_RECEIVER_URL or not BGD_RECEIVER_SECRET:
        app.logger.warning("Receiver URL/SECRET não configurados.")
        return

    payload = {
        "event": event,
        "correlationID": correlation_id,
        "value": int(value_cents),
        "payer": payer_name
    }

    try:
        r = requests.post(
            BGD_RECEIVER_URL,
            json=payload,
            headers={"X-Receiver-Secret": BGD_RECEIVER_SECRET},
            timeout=20,
        )
        if r.status_code >= 400:
            app.logger.error("Receiver erro: %s %s", r.status_code, r.text[:400])
    except Exception as e:
        app.logger.error("Receiver exception: %s", str(e))


@app.post("/create-charge")
def create_charge():
    """
    Cria cobrança via API Woovi/OpenPix.
    Body:
    {
      "value": 1500,  # centavos
      "correlationID": "bgd|uid:123|cents:1500|<uuid>" (opcional)
      "name": "Fulano" (opcional),
      "email": "..." (opcional),
      "phone": "..." (opcional),
      "taxID": "..." (opcional),
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
        "Accept": "application/json",
    }

    r = requests.post(url, headers=headers, json=payload, timeout=20)
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


