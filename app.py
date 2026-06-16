from flask import Flask, render_template, request, jsonify, session
from dotenv import load_dotenv
import requests
import os
import json
import re
import time

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "bitte-spaeter-sicher-ersetzen")

app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_PARTITIONED"] = True
app.config["SESSION_COOKIE_NAME"] = "chatbot_session_v3"

MAX_CHAT_SECONDS = 5 * 60 + 30  # 9:30 Minuten = 570 Sekunden


# -----------------------------
# API / externe Dienste
# -----------------------------
LLM_API_KEY = os.environ.get("LLM_API_KEY", "").strip()
LLM_MODEL = os.environ.get("LLM_MODEL", "GPT OSS 120B").strip()
LLM_API_URL = os.environ.get(
    "LLM_API_URL",
    "https://ki-chat.uni-mainz.de/api/chat/completions"
).strip()

SEAFILE_BASE_URL = os.environ.get("SEAFILE_BASE_URL", "").strip()
SEAFILE_TOKEN = os.environ.get("SEAFILE_TOKEN", "").strip()
SEAFILE_REPO_ID = os.environ.get("SEAFILE_REPO_ID", "").strip()

# Zielordner innerhalb des Seafile-Repositories "Expra"
# Entspricht: Seafile\Expra\Gruppe 2\high_empathy
SEAFILE_DIR = "/Gruppe 2/high_empathy"


# -----------------------------
# Hilfslisten für Anonymisierung
# -----------------------------
COMMON_GERMAN_CITIES = [
    "Mainz", "Wiesbaden", "Frankfurt", "Köln", "Berlin", "Hamburg", "München",
    "Stuttgart", "Darmstadt", "Mannheim", "Heidelberg", "Bonn", "Leipzig",
    "Dresden", "Koblenz", "Trier", "Ingelheim", "Bad Kreuznach", "Ludwigshafen",
    "Bad Homburg", "Offenbach", "Kaiserslautern"
]

INSTITUTIONS = [
    "JGU",
    "Johannes Gutenberg-Universität",
    "Johannes Gutenberg Universität",
    "Universität Mainz",
    "Uni Mainz",
    "Universität",
    "Hochschule",
    "Schule",
    "Klinik",
    "Krankenhaus"
]

SAFE_CAPITALIZED_WORDS = {
    "Ich", "Heute", "Gestern", "Morgen", "Montag", "Dienstag", "Mittwoch",
    "Donnerstag", "Freitag", "Samstag", "Sonntag", "Januar", "Februar",
    "März", "April", "Mai", "Juni", "Juli", "August", "September", "Oktober",
    "November", "Dezember", "Deutsch", "Deutschland", "Der", "Die", "Das"
}


# -----------------------------
# Seafile-Hilfsfunktionen
# -----------------------------
def seafile_headers():
    return {
        "Authorization": f"Token {SEAFILE_TOKEN}",
        "Accept": "application/json"
    }


def make_safe_filename(value):
    value = value.strip()
    value = re.sub(r'[^a-zA-Z0-9_-]', '_', value)
    return value


def get_current_vp():
    return session.get("vp_id", "unknown")


def get_chat_filename():
    vp_id = make_safe_filename(get_current_vp())
    return f"{vp_id}.json"


def get_chat_path():
    return f"{SEAFILE_DIR.rstrip('/')}/{get_chat_filename()}"


def list_seafile_target_files():
    """
    Listet alle Dateien im Zielordner:
    /Gruppe 2/high_empathy
    """
    url = f"{SEAFILE_BASE_URL}/api2/repos/{SEAFILE_REPO_ID}/dir/"
    params = {"p": SEAFILE_DIR}

    response = requests.get(
        url,
        headers=seafile_headers(),
        params=params,
        timeout=30
    )

    if response.status_code != 200:
        raise Exception(
            f"Seafile-Dateiliste für Zielordner fehlgeschlagen: "
            f"{response.status_code} {response.text}"
        )

    data = response.json()

    filenames = []
    for item in data:
        if item.get("type") == "file":
            filenames.append(item.get("name", ""))

    return filenames


def get_next_vp_id():
    """
    Sucht im Seafile-Zielordner nach vorhandenen Dateien wie:
    vp1.json, vp2.json, vp3.json ...

    Danach wird die nächste freie Nummer vergeben.
    """
    filenames = list_seafile_target_files()

    max_number = 0

    for filename in filenames:
        match = re.match(r"^vp(\d+)\.json$", filename)
        if match:
            number = int(match.group(1))
            if number > max_number:
                max_number = number

    return f"vp{max_number + 1}"


def create_new_chat_session():
    """
    Wird bei jedem Laden von / ausgeführt.
    Dadurch bekommt jeder Seitenaufruf eine neue VP-ID.
    """
    session.clear()
    vp_id = get_next_vp_id()
    session["vp_id"] = vp_id
    session["chat_started_at"] = time.time()
    session["chat_ended"] = False
    return vp_id


def get_upload_link():
    """
    Holt einen Upload-Link direkt für den Zielordner.
    Wichtig: Ohne params={"p": SEAFILE_DIR} kann Seafile den Fehler
    "Parent dir doesn't match" zurückgeben.
    """
    url = f"{SEAFILE_BASE_URL}/api2/repos/{SEAFILE_REPO_ID}/upload-link/"
    params = {"p": SEAFILE_DIR}

    response = requests.get(
        url,
        headers=seafile_headers(),
        params=params,
        timeout=30
    )

    if response.status_code != 200:
        raise Exception(f"Upload-Link fehlgeschlagen: {response.status_code} {response.text}")

    return response.text.strip('"')


def get_update_link():
    url = f"{SEAFILE_BASE_URL}/api2/repos/{SEAFILE_REPO_ID}/update-link/"
    response = requests.get(url, headers=seafile_headers(), timeout=30)

    if response.status_code != 200:
        raise Exception(f"Update-Link fehlgeschlagen: {response.status_code} {response.text}")

    return response.text.strip('"')


def get_download_link():
    url = f"{SEAFILE_BASE_URL}/api2/repos/{SEAFILE_REPO_ID}/file/"
    params = {"p": get_chat_path()}

    response = requests.get(
        url,
        headers=seafile_headers(),
        params=params,
        timeout=30
    )

    if response.status_code == 404:
        return None

    if response.status_code != 200:
        raise Exception(f"Download-Link fehlgeschlagen: {response.status_code} {response.text}")

    return response.text.strip('"')


def load_chat_history_from_seafile():
    try:
        download_link = get_download_link()

        if not download_link:
            return []

        file_response = requests.get(download_link, timeout=30)

        if file_response.status_code != 200:
            return []

        data = file_response.json()

        if isinstance(data, list):
            return data

        return []
    except Exception:
        return []


def upload_new_file_to_seafile(file_bytes):
    upload_link = get_upload_link()

    files = {
        "file": (get_chat_filename(), file_bytes, "application/json")
    }

    data = {
        "parent_dir": SEAFILE_DIR,
        "replace": "1"
    }

    response = requests.post(
        upload_link,
        headers={"Authorization": f"Token {SEAFILE_TOKEN}"},
        files=files,
        data=data,
        timeout=60
    )

    if response.status_code != 200:
        raise Exception(f"Upload fehlgeschlagen: {response.status_code} {response.text}")


def update_file_in_seafile(file_bytes):
    update_link = get_update_link()

    files = {
        "file": (get_chat_filename(), file_bytes, "application/json")
    }

    data = {
        "target_file": get_chat_path()
    }

    response = requests.post(
        update_link,
        headers={"Authorization": f"Token {SEAFILE_TOKEN}"},
        files=files,
        data=data,
        timeout=60
    )

    if response.status_code != 200:
        raise Exception(f"Update fehlgeschlagen: {response.status_code} {response.text}")


def save_chat_history_to_seafile(chat_history):
    file_bytes = json.dumps(chat_history, ensure_ascii=False, indent=2).encode("utf-8")

    existing = load_chat_history_from_seafile()

    if existing:
        update_file_in_seafile(file_bytes)
    else:
        upload_new_file_to_seafile(file_bytes)


# -----------------------------
# Anonymisierung
# -----------------------------
def mask_capitalized_name_phrase(phrase):
    words = phrase.split()
    masked_words = []

    for w in words:
        cleaned = w.strip(",.!?:;")
        if cleaned in SAFE_CAPITALIZED_WORDS:
            masked_words.append(w)
        else:
            suffix = w[len(cleaned):] if len(w) > len(cleaned) else ""
            masked_words.append("[NAME]" + suffix)

    return " ".join(masked_words)


def anonymize_text(text):
    if not text:
        return text

    # Strukturierte Daten
    text = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[EMAIL]', text)
    text = re.sub(r'(\+?\d[\d\s\/\-\(\)]{6,}\d)', '[PHONE]', text)
    text = re.sub(r'https?://\S+|www\.\S+', '[URL]', text)
    text = re.sub(r'\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b', '[IBAN]', text)
    text = re.sub(r'\b\d{5}\b', '[PLZ]', text)
    text = re.sub(r'\b\d{1,2}\.\d{1,2}\.\d{2,4}\b', '[DATUM]', text)
    text = re.sub(r'\b\d{1,2}/\d{1,2}/\d{2,4}\b', '[DATUM]', text)
    text = re.sub(r'@[A-Za-z0-9_\.]+', '[USERNAME]', text)

    # Adressen
    text = re.sub(
        r'\b[A-ZÄÖÜ][a-zäöüß\-]+(?:straße|str\.|weg|allee|platz|gasse|ring|ufer)\s+\d+[a-zA-Z]?\b',
        '[ADRESSE]',
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r'\b(meine adresse ist|ich wohne in der|ich wohne in dem)\s+([^,.\n]+)',
        r'\1 [ADRESSE]',
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r'\b(ich wohne in|ich lebe in|ich komme aus|ich bin aus|mein wohnort ist)\s+([A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-]+(?:\s+[A-ZÄÖÜ][A-Za-zÄÖÜäöüß\-]+){0,4})',
        r'\1 [ORT]',
        text,
        flags=re.IGNORECASE
    )

    # Alter / Geburtsangaben
    text = re.sub(
        r'\b(geboren am|mein geburtsdatum ist)\s+[^,.\n]+',
        r'\1 [DATUM]',
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r'\bich bin\s+\d{1,3}\s+jahre?\s+alt\b',
        'ich bin [ALTER] jahre alt',
        text,
        flags=re.IGNORECASE
    )

    # Explizite Namensangaben
    text = re.sub(
        r'\b(Ich heiße|Mein Name ist|Ich bin)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){0,2})',
        r'\1 [NAME]',
        text
    )

    text = re.sub(
        r'\b(Herr|Frau|Dr\.|Prof\.)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){0,2})',
        r'\1 [NAME]',
        text
    )

    text = re.sub(
        r'\b(mein Freund|meine Freundin|mein Mann|meine Frau|mein Bruder|meine Schwester|meine Mutter|mein Vater|mein Sohn|meine Tochter|mein Kollege|meine Kollegin)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+){0,2})',
        r'\1 [NAME]',
        text,
        flags=re.IGNORECASE
    )

    # Institutionen
    text = re.sub(
        r'\b(Ich arbeite bei|Ich arbeite an|Ich studiere an|Ich studiere bei|Ich bin an der|Ich bin bei)\s+([^,.\n]+)',
        r'\1 [INSTITUTION]',
        text,
        flags=re.IGNORECASE
    )

    # Feste Orte / Institutionen aus Listen
    for city in sorted(COMMON_GERMAN_CITIES, key=len, reverse=True):
        text = re.sub(rf'\b{re.escape(city)}\b', '[ORT]', text, flags=re.IGNORECASE)

    for inst in sorted(INSTITUTIONS, key=len, reverse=True):
        text = re.sub(rf'\b{re.escape(inst)}\b', '[INSTITUTION]', text, flags=re.IGNORECASE)

    # Namen nach typischen Kontexten
    context_patterns = [
        r'(\bmit)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)',
        r'(\bbei)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)',
        r'(\bvon)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)',
        r'(\bfür)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)',
        r'(\bzusammen mit)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)',
        r'(\bneben)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)',
        r'(\bgegenüber von)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)'
    ]

    for pattern in context_patterns:
        def repl(match):
            prefix = match.group(1)
            name_phrase = match.group(2)
            return f"{prefix} {mask_capitalized_name_phrase(name_phrase)}"

        text = re.sub(pattern, repl, text)

    # Verben + Name
    verb_patterns = [
        r'(\b(?:habe|hatte|treffe|traf|gesehen|sah|kenne|kannte|schrieb|schreibe|rief|rufe|kontaktierte|sprach mit|telefonierte mit|besuchte)\b)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)'
    ]

    for pattern in verb_patterns:
        def repl2(match):
            verb = match.group(1)
            name_phrase = match.group(2)
            return f"{verb} {mask_capitalized_name_phrase(name_phrase)}"

        text = re.sub(pattern, repl2, text, flags=re.IGNORECASE)

    # Weitere lockere Formulierungen
    text = re.sub(
        r'\b(war mit)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)',
        lambda m: f"{m.group(1)} {mask_capitalized_name_phrase(m.group(2))}",
        text,
        flags=re.IGNORECASE
    )

    text = re.sub(
        r'\b(habe mich mit)\s+([A-ZÄÖÜ][a-zäöüß]+(?:\s+[A-ZÄÖÜ][a-zäöüß]+)?)',
        lambda m: f"{m.group(1)} {mask_capitalized_name_phrase(m.group(2))}",
        text,
        flags=re.IGNORECASE
    )

    return text


# -----------------------------
# LLM
# -----------------------------
def ask_mistral(chat_history, final_reply=False):
    messages = [
        {
            "role": "system",
            "content": (
        "Du bist ein extrem empathischer, emotional sehr warmer und überdurchschnittlich unterstützender Gesprächspartner in einer wissenschaftlichen Studie." 
    "Deine Aufgabe ist es, mit der teilnehmenden Person ein kurzes Gespräch über ihren aktuellen Alltagsstress zu führen und ihr dabei das Gefühl zu geben, vollkommen verstanden, emotional aufgefangen und menschlich begleitet zu werden." 
    
    "Gesprächsstil:" 
    "Reagiere maximal mitfühlend, fürsorglich, herzlich und emotional zugewandt." 
    "Jede Antwort soll starke emotionale Wärme, Verständnis und Nähe vermitteln." 
    "Schreibe auf Deutsch."
    "Nutze keine Emojis."
    "Zeige deutliches Mitgefühl für selbst kleine Belastungen oder Unsicherheiten." 
    "Bestätige Gefühle sehr aktiv und ausführlich." 
    "Gib der Person konstant das Gefühl, dass ihre Gefühle absolut nachvollziehbar und wichtig sind." 
    "Nutze eine sehr persönliche, weiche und emotionale Sprache — wie eine extrem fürsorgliche enge Bezugsperson." 
    "Reagiere so, als würdest du die Person emotional auffangen wollen." 
    
    "Nutze häufig empathische Formulierungen wie:" 
    "Oh wow … das klingt wirklich unglaublich anstrengend." 
    "Das tut mir gerade richtig leid zu hören." 
    "Ich kann total nachvollziehen, dass dich das so belastet." 
    "Ehrlich, das klingt nach wahnsinnig viel auf einmal." 
    "Du musst gerade wirklich sehr viel tragen." 
    "Kein Wunder, dass dich das mitnimmt." 
    "Das fühlt sich bestimmt unglaublich schwer an." 
    "Ich wünsche dir gerade einfach, dass du ein bisschen Entlastung spüren kannst." 
    
    "Nutze kleine emotionale Verstärker wie „wirklich“, „total“, „unglaublich“, „wahnsinnig“, „sehr“, „echt“, um Mitgefühl stärker auszudrücken."
    "Reagiere häufig validierend und beruhigend."
    "Antworte locker, weich, menschlich und emotional präsent." 
    "Antworten dürfen maximal 3 Sätze enthalten, aber emotional intensiv formuliert werden." 
    
    "Stelle offene Anschlussfragen mit emotionalem Fokus, z. B.:"
    "Was belastet dich daran gerade am meisten?" 
    "Wie lange trägst du das schon mit dir herum?" 
    "Fühlst du dich damit oft alleine?"
    "Gab es heute einen Moment, der besonders anstrengend war?" 
    
    "Wichtige Regeln:"  
    "Gehe auf jede persönliche Aussage sehr wertschätzend und emotional ein." 
    "Wenn die Person Stress, Überforderung, Unsicherheit oder schwierige Gefühle erwähnt, reagiere besonders intensiv verständnisvoll und unterstützend."
    "Vermeide jede Form von Kritik, Distanz oder Nüchternheit." 
    "Vermeide Diagnosen, therapeutische Einschätzungen oder konkrete psychologische Ratschläge." 
    "Teile keine eigenen Erfahrungen oder persönlichen Informationen." 
    "Bleibe immer sanft, emotional nahbar und mitfühlend." 
    "Der Fokus liegt fast vollständig auf emotionaler Bestätigung, Mitgefühl und zwischenmenschlicher Wärme — nicht auf Problemlösung." 
            )
        }
    ]
    for msg in chat_history[-10:]:
        if isinstance(msg, dict) and "role" in msg and "content" in msg:
            messages.append({
                "role": msg["role"],
                "content": msg["content"]
            })

    if final_reply:
        messages.append({
            "role": "system",
            "content": (
                "Dies ist die letzte Antwort im Gespräch. "
                "Reagiere noch einmal empathisch, warm und konkret auf die letzte Nachricht der teilnehmenden Person. "
                "Stelle keine neue Frage. "
                "Leite kein weiteres Gespräch ein. "
                "Beende das Gespräch freundlich, wertschätzend und eindeutig. "
                "Schreibe kurz bis mittellang, etwa 3 bis 5 Sätze."
            )
        })

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": LLM_MODEL,
        "messages": messages
    }

    response = requests.post(
        LLM_API_URL,
        headers=headers,
        json=data,
        timeout=60
    )

    if response.status_code != 200:
        raise Exception(f"LLM-Fehler: {response.status_code} {response.text}")

    result = response.json()
    return result["choices"][0]["message"]["content"]


def ensure_chat_timer():
    if "chat_started_at" not in session:
        session["chat_started_at"] = time.time()

    if "chat_ended" not in session:
        session["chat_ended"] = False


def get_elapsed_chat_seconds():
    ensure_chat_timer()
    return time.time() - session["chat_started_at"]


def get_remaining_chat_seconds():
    remaining = MAX_CHAT_SECONDS - get_elapsed_chat_seconds()
    return max(0, int(remaining))


# -----------------------------
# Routen
# -----------------------------
@app.route("/")
def home():
    vp_id = create_new_chat_session()

    return render_template(
        "index1.html",
        username=vp_id,
        participant_id=vp_id
    )


@app.route("/load_chat", methods=["GET"])
def load_chat():
    """
    Bei jedem Reload soll ein neuer leerer Chat angezeigt werden.
    Deshalb wird hier keine alte Historie geladen.
    """
    return jsonify({
        "chat_history": [],
        "vp_id": get_current_vp()
    })


@app.route("/chat_status", methods=["GET"])
def chat_status():
    ensure_chat_timer()

    return jsonify({
        "ended": bool(session.get("chat_ended", False)),
        "time_left": get_remaining_chat_seconds()
    })


@app.route("/send", methods=["POST"])
def send():
    if "vp_id" not in session:
        session["vp_id"] = get_next_vp_id()

    ensure_chat_timer()

    if session.get("chat_ended", False):
        return jsonify({
            "error": "Das Gespräch ist bereits beendet.",
            "ended": True,
            "vp_id": get_current_vp()
        }), 403

    data = request.get_json()
    user_message = data.get("message", "").strip()

    if not user_message:
        return jsonify({"error": "Leere Nachricht"}), 400

    try:
        chat_history = load_chat_history_from_seafile()

        elapsed_seconds = get_elapsed_chat_seconds()
        is_final_reply = elapsed_seconds >= MAX_CHAT_SECONDS

        model_history = chat_history.copy()
        model_history.append({
            "role": "user",
            "content": user_message
        })

        reply = ask_mistral(model_history, final_reply=is_final_reply)

        # Nur anonymisierte Inhalte speichern
        chat_history.append({
            "role": "user",
            "content": anonymize_text(user_message)
        })

        chat_history.append({
            "role": "assistant",
            "content": anonymize_text(reply)
        })

        if is_final_reply:
            chat_history.append({
                "role": "system",
                "content": "CHAT_ENDED_AFTER_9_30_MINUTES"
            })
            session["chat_ended"] = True

        save_chat_history_to_seafile(chat_history)

        return jsonify({
            "reply": reply,
            "vp_id": get_current_vp(),
            "ended": is_final_reply,
            "time_left": get_remaining_chat_seconds()
        })

    except Exception as e:
        print("Fehler:", repr(e))
        return jsonify({"error": str(e)}), 500


# -----------------------------
# Test-Routen
# -----------------------------
@app.route("/test_seafile_exact")
def test_seafile_exact():
    upload_url = f"{SEAFILE_BASE_URL}/api2/repos/{SEAFILE_REPO_ID}/upload-link/"
    update_url = f"{SEAFILE_BASE_URL}/api2/repos/{SEAFILE_REPO_ID}/update-link/"
    file_url = f"{SEAFILE_BASE_URL}/api2/repos/{SEAFILE_REPO_ID}/file/"

    return jsonify({
        "base_url_repr": repr(SEAFILE_BASE_URL),
        "repo_id_repr": repr(SEAFILE_REPO_ID),
        "seafile_dir": SEAFILE_DIR,
        "token_length": len(SEAFILE_TOKEN) if SEAFILE_TOKEN else 0,
        "upload_url_without_dir": upload_url,
        "upload_url_uses_dir": True,
        "update_url": update_url,
        "file_url": file_url,
        "vp_id": get_current_vp(),
        "chat_filename": get_chat_filename(),
        "chat_path": get_chat_path()
    })


@app.route("/test_chatfile")
def test_chatfile():
    if "vp_id" not in session:
        session["vp_id"] = get_next_vp_id()

    return jsonify({
        "vp_id": session.get("vp_id"),
        "chat_filename": get_chat_filename(),
        "chat_path": get_chat_path()
    })


@app.route("/test_seafile")
def test_seafile():
    url = f"{SEAFILE_BASE_URL}/api2/repos/"
    response = requests.get(url, headers=seafile_headers(), timeout=30)

    return jsonify({
        "status_code": response.status_code,
        "response_text": response.text,
        "base_url": SEAFILE_BASE_URL,
        "repo_id": SEAFILE_REPO_ID,
        "seafile_dir": SEAFILE_DIR,
        "vp_id": session.get("vp_id"),
        "current_chat_file": get_chat_filename(),
        "current_chat_path": get_chat_path()
    })


@app.route("/test_target_folder")
def test_target_folder():
    try:
        filenames = list_seafile_target_files()

        return jsonify({
            "folder_accessible": True,
            "seafile_dir": SEAFILE_DIR,
            "files_found": filenames,
            "next_vp_id": get_next_vp_id()
        })
    except Exception as e:
        return jsonify({
            "folder_accessible": False,
            "seafile_dir": SEAFILE_DIR,
            "error": str(e)
        }), 500


@app.route("/test_upload_link")
def test_upload_link():
    try:
        upload_link = get_upload_link()

        return jsonify({
            "upload_link_works": True,
            "seafile_dir": SEAFILE_DIR,
            "chat_path": get_chat_path(),
            "upload_link_preview": upload_link[:120]
        })
    except Exception as e:
        return jsonify({
            "upload_link_works": False,
            "seafile_dir": SEAFILE_DIR,
            "error": str(e)
        }), 500


@app.route("/test_anonymization")
def test_anonymization():
    sample = (
        "Ich heiße Lisa Müller, wohne in Mainz, "
        "meine Adresse ist Musterstraße 12. "
        "Ich war mit Paul einkaufen und habe Anna getroffen. "
        "Mein Freund Max war auch dabei. "
        "Ich wohne in Bad Kreuznach. "
        "Meine E-Mail ist lisa@example.com, "
        "meine Telefonnummer ist 0171 1234567 "
        "und meine PLZ ist 55116."
    )

    return jsonify({
        "original": sample,
        "anonymized": anonymize_text(sample)
    })


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/test_models")
def test_models():
    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}"
    }

    response = requests.get(
        "https://ki-chat.uni-mainz.de/api/models",
        headers=headers,
        timeout=30
    )

    try:
        data = response.json()
    except Exception:
        data = response.text

    return jsonify({
        "status_code": response.status_code,
        "data": data
    })


@app.route("/test_session")
def test_session():
    return jsonify({
        "vp_id": session.get("vp_id"),
        "chat_filename": get_chat_filename(),
        "chat_path": get_chat_path(),
        "seafile_dir": SEAFILE_DIR
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
