import os
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
CHAT_ID = os.environ.get("CHAT_ID", "")

def tg_send(text: str):
    if not BOT_TOKEN or not CHAT_ID:
        print("BOT_TOKEN/CHAT_ID não configurados")
        return

    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    r = requests.post(url, json={
        "chat_id": CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }, timeout=15)
    print("Telegram:", r.status_code, r.text[:200])

@app.get("/")
def health():
    return "OK", 200

@app.post("/webhook")
def webhook():
    data = request.get_json(silent=True) or {}
    event = data.get("event", "EVENTO")
    charge = data.get("charge") or {}

    cid = charge.get("correlationID") or charge.get("id") or "?"
    value = charge.get("value") or charge.get("amount") or ""

    if event == "OPENPIX:CHARGE_CREATED":
        tg_send(f"🧾 Cobrança criada\nID: {cid}\nValor: {value}")
    elif event == "OPENPIX:CHARGE_COMPLETED":
        tg_send(f"✅ PAGAMENTO CONFIRMADO\nID: {cid}\nValor: {value}")
    elif event == "OPENPIX:CHARGE_EXPIRED":
        tg_send(f"⌛ Cobrança expirada\nID: {cid}")
    else:
        tg_send(f"📩 Woovi: {event}")

    return jsonify({"ok": True}), 200
