#import libraries
import os
import json
import requests
import re
import time
import random
from dotenv import load_dotenv
from datetime import date, datetime
from urllib.parse import quote


# Load GROK_API_KEY from .env
load_dotenv()
API_KEY = os.getenv("GROK_API_KEY")

if not API_KEY:
    raise ValueError("GROK_API_KEY not found. Check your .env file.")

API_URL = "https://api.x.ai/v1/chat/completions"
MODEL = "grok-4-0709"  # if this ever changes, update to the latest Grok model ID

# Load Airtable credentials from .env
AIRTABLE_API_KEY = os.getenv("AIRTABLE_API_KEY")
AIRTABLE_BASE_ID = os.getenv("AIRTABLE_BASE_ID")

if not AIRTABLE_API_KEY:
    raise ValueError("AIRTABLE_API_KEY not found. Check your .env file.")

if not AIRTABLE_BASE_ID:
    raise ValueError("AIRTABLE_BASE_ID not found. Check your .env file.")

AIRTABLE_API_URL = f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}"

AIRTABLE_PHOTOS_TABLE = "Photos"  
AIRTABLE_BIKES_TABLE = "Bikes"  
AIRTABLE_AI_INTAKE_TABLE = "AI Intake"

AIRTABLE_HEADERS = {
    "Authorization": f"Bearer {AIRTABLE_API_KEY}",
    "Content-Type": "application/json",
}

DEFAULT_WORKSHOP_USER_ID = None  # or set to a real Users record ID if you want a fallback

# For the parts to order table
ALLOWED_PRIORITY = {"Low", "Medium", "High", "Critical"}
ALLOWED_REASON = {"Missing", "Worn", "Damaged", "Donor to other bike", "First Assessment", "Other"}
ALLOWED_PART_STATUS = {"To Order", "Ordered", "Delivered", "Installed"}


#System prompt
system_prompt = """
You are an assistant that converts messy workshop notes about vintage motorcycles into STRICT JSON.

The user will describe:
- The bike (make, model, year, colour, etc.)
- Any repairs that have been done or are planned
- Any missing or donor parts that need to be ordered
- Any parts being put into a parts box
- The parts box location

Return ONLY valid JSON in this exact schema:

{
  "bike": {
    "make": "string or null",
    "model": "string or null",
    "year": "number or null",
    "colour": "string or null",
    "vin_engine_number": "string or null",
    "status": "Under Repair | Ready | Completed | null",
    "odometer_reading": "number or null",
    "odometer_type": "Km | Miles | null",
    "general_notes": "string or null"
  },
  "repairs": [
    {
      "repair_name": "string",
      "status": " Under Repair | Waiting on Parts | Completed | null",
      "completed_where": "Workshop | Pre-arrival | Unknown | null",
      "confidence": "high | medium | low",
      "notes": "string or null",
      "performed_by": "string or null",
      "start_date": "YYYY-MM-DD or null",
      "completion_date": "YYYY-MM-DD or null"
    }
 ],

  "parts_to_order": [
    {
      "part_name": "string",
      "applies_to": "string or null",
      "reason": "Missing | Worn | Damaged | Donor to other bike | First Assessment | Other",
      "priority": "Low | Medium | High | Critical | null",
      "status": "To Order | Ordered | Delivered | Installed | null",
      "notes": "string or null"
    }
  ],
  "parts_box": {
    "box_name": "string or null",
    "location": "string or null",
    "contents_summary": "string or null"
  }
}

Rules:
- ALWAYS return all top-level keys: bike, repairs, parts_to_order, parts_box.
- If you don't know a value, use null.
- Dates MUST be in YYYY-MM-DD format or null.
- Never include comments or extra text outside the JSON.
- If the note includes a bike number like 'Bike 12', treat it as a label only; still extract make/model/year/colour and odometer if present.
- If make/model/year appear but odometer not stated, set odometer_reading=null.
- If multiple colours are mentioned, return them as a single string separated by commas (e.g. "Red,White").
- Extract each discrete observation or work item as one repair entry. Observations include condition statements (e.g., "all lights working", "fuel tank clean", "coolant looks good") and measurements (e.g., "front brake pads 40%"). Do NOT omit them.
- For now, ALWAYS set repairs[].status="Completed" for every repair/observation extracted from the note, unless the note explicitly says something is not working / faulty / needs doing.
- If the note indicates the work has been done (keywords like “done”, “got running”, “replaced”, “new tyres”, “painted”, “swapped”, “repainted”, “installed”, “brand-new”) → status="Completed".
- If the note indicates it needs doing (keywords like “needs”, “require”, “to do”, “check”, “diagnose”, “replace”, “leaking”, “rattling”, “won’t start”) → status="Under Repair".
- If unclear → default status="Completed" with confidence="low" and add uncertainty to notes.
- Correct obvious transcription slips when confident (“pork boots” → “fork boots”), but if uncertain, keep original phrase in notes.
- Set completed_where="Pre-arrival" if the note reads like an intake/condition report (lists of "is good/working/clean/%"). Set completed_where="Workshop" only for explicit work performed in the workshop. If unclear, use "Unknown".
- If the note mentions "headlight fairing" that means "headlight cowl"
- If the note says "both fairings" then create separate "left fairing" and "right fairing" repair entries
- If the note says "plate fitted" that means "VIN plate fitted"
- If the note says "new fasteners fitted" that means "some or all fairing fasteners replaced and fitted"
- If the note says "rear brake cleaned" that means "seals have been pulled out, cleaned and regreased"
- Example: If the note says "all lights are working, front brake pads 40%, coolant looks good",
  create three separate repairs with status="Completed" and completed_where="Pre-arrival".
"""



# Functions #######
#Get user id
def get_effective_user_id(intake_fields: dict):
    """
    Returns a Users record ID or None.
    Priority:
    1. AI Intake -> Submitted By
    2. DEFAULT_WORKSHOP_USER_ID
    """
    submitted = intake_fields.get("Submitted By")

    if isinstance(submitted, list) and len(submitted) > 0:
        return submitted[0]

    return DEFAULT_WORKSHOP_USER_ID

#Set assigned user for bikes table is blank
def set_bike_assigned_user_if_blank(bike_record_id: str | None, user_id: str | None):
    """
    If Bikes.Assigned User is empty, set it to user_id.
    Does NOT overwrite if already set.
    Safe if bike_record_id is None/empty.
    """
    if not bike_record_id:
        return
    if not user_id:
        return

    # Read current bike fields
    resp = requests.get(
        f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_BIKES_TABLE}/{bike_record_id}",
        headers=AIRTABLE_HEADERS,
        timeout=30,
    )
    resp.raise_for_status()
    bike_fields = resp.json().get("fields", {})

    current = bike_fields.get("Assigned User", [])
    if isinstance(current, list) and len(current) > 0:
        return  # already assigned; leave as-is

    patch = {"fields": {"Assigned User": [user_id]}}
    resp2 = requests.patch(
        f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_BIKES_TABLE}/{bike_record_id}",
        headers=AIRTABLE_HEADERS,
        json=patch,
        timeout=30,
    )
    resp2.raise_for_status()
    print(f"Updated Bikes.Assigned User for {bike_record_id} -> {user_id}")




#Get air table record
def get_airtable_record(table_name: str, rec_id: str) -> dict:
    table_path = quote(table_name, safe="")
    url = f"{AIRTABLE_API_URL}/{table_path}/{rec_id}"
    r = requests.get(url, headers=AIRTABLE_HEADERS, timeout=30)
    r.raise_for_status()
    return r.json()

#Patch airtable record
def patch_airtable_record(table_name: str, rec_id: str, fields_to_update: dict) -> dict:
    table_path = quote(table_name, safe="")
    url = f"{AIRTABLE_API_URL}/{table_path}/{rec_id}"
    r = requests.patch(url, headers=AIRTABLE_HEADERS, json={"fields": fields_to_update}, timeout=30)
    r.raise_for_status()
    return r.json()

# Build intake general notes block
def build_intake_general_notes_block(note_text: str,
                                     repairs_list: list,
                                     parts_to_order_list: list,
                                     parts_box_payload: dict = None,
                                     ai_summary: str = None) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    lines = [f"{ts}"]

    # Optional short interpreted summary (1–2 lines max)
    if ai_summary:
        s = " ".join(ai_summary.strip().split())
        if s:
            lines.append(f"Summary: {s}")

    # Repairs section (only if any)
    repair_lines = []
    for r in (repairs_list or []):
        name = (r.get("repair_name") or "").strip()
        if not name:
            continue
        status = (r.get("status") or "").strip()
        if status not in {"Completed", "Under Repair"}:
            status = "Under Repair"

        cw = (r.get("completed_where") or "").strip()
        tag = status
        #remove cw tag from notes
        #if status == "Completed" and cw:
        #    tag = f"{status}/{cw}"

        extra = (r.get("notes") or "").strip()
        #Changed the order of the text in the note
        repair_lines.append(f"- {name}" + (f" — {extra}" if extra else "") + f" [{tag}]")

        #this was how it was originally setup
        #repair_lines.append(f"- [{tag}] {name}" + (f" — {extra}" if extra else ""))

    if repair_lines:
        lines.append("Repairs / Work:")
        lines.extend(repair_lines)

    # Parts to order section (only if any)
    part_lines = []
    for p in (parts_to_order_list or []):
        part = (p.get("part_name") or "").strip()
        if not part:
            continue
        applies_to = (p.get("applies_to") or "").strip()
        part_lines.append(f"- {part}" + (f" (applies to: {applies_to})" if applies_to else ""))

    if part_lines:
        lines.append("Parts to order:")
        lines.extend(part_lines)

    # Parts box section (only if meaningful)
    pb = parts_box_payload or {}
    box_name = (pb.get("box_name") or "").strip()
    location = (pb.get("location") or "").strip()
    contents = (pb.get("contents_summary") or "").strip()
    if box_name or location or contents:
        lines.append("Parts box:")
        if box_name:
            lines.append(f"- Box: {box_name}")
        if location:
            lines.append(f"- Location: {location}")
        if contents:
            lines.append(f"- Contents: {contents}")

    return "\n".join(lines).strip()

#build intake block with ref
def build_intake_block_with_ref(intake_rec_id: str,
                                note_text: str,
                                repairs_list: list,
                                parts_to_order_list: list,
                                parts_box_payload: dict = None) -> str:
    block = build_intake_general_notes_block(
        note_text=note_text,
        repairs_list=repairs_list,
        parts_to_order_list=parts_to_order_list,
        parts_box_payload=parts_box_payload
    )
    # unobtrusive marker for perfect de-dup / replace-on-reprocess
    return block + f"\n(ref: {intake_rec_id})"


#upsert intake block
def upsert_intake_block(existing_notes: str, intake_rec_id: str, new_block: str) -> str:
    existing_notes = (existing_notes or "").strip()
    new_block = (new_block or "").strip()
    if not new_block:
        return existing_notes

    # Match the whole block that ends with (ref: <id>)
    pattern = re.compile(
        rf"^.*?\(ref:\s*{re.escape(intake_rec_id)}\)\s*$",
        re.MULTILINE | re.DOTALL
    )

    # Because DOTALL+MULTILINE can be too greedy, we use a safer block matcher:
    block_pattern = re.compile(
        rf"(^.*?\(ref:\s*{re.escape(intake_rec_id)}\)\s*$)",
        re.MULTILINE | re.DOTALL
    )

    # If the ref exists anywhere, replace that block by splitting on separators
    if f"(ref: {intake_rec_id})" in existing_notes:
        # Split existing into blocks by separator
        blocks = [b.strip() for b in existing_notes.split("\n\n---\n\n") if b.strip()]
        out = []
        replaced = False
        for b in blocks:
            if f"(ref: {intake_rec_id})" in b:
                out.append(new_block)
                replaced = True
            else:
                out.append(b)
        return ("\n\n---\n\n".join(out)).strip() if replaced else existing_notes

    # else append
    if existing_notes:
        return (existing_notes + "\n\n---\n\n" + new_block).strip()
    return new_block



# Update bike general notes from intake
def update_bike_general_notes_from_intake(bike_id: str,
                                         intake_rec_id: str,
                                         note_text: str,
                                         repairs_list: list,
                                         parts_to_order_list: list,
                                         parts_box_payload: dict):
    """
    Reads Bikes.General Notes, then upserts a dated intake block keyed by intake record id.
    """
    bike = get_airtable_record(AIRTABLE_BIKES_TABLE, bike_id)
    existing = (bike.get("fields", {}).get("General Notes") or "")

    block = build_intake_block_with_ref(
        intake_rec_id=intake_rec_id,
        note_text=note_text,
        repairs_list=repairs_list,
        parts_to_order_list=parts_to_order_list,
        parts_box_payload=parts_box_payload
    )

    updated = upsert_intake_block(existing, intake_rec_id, block)


    if updated.strip() != existing.strip():
        patch_airtable_record(AIRTABLE_BIKES_TABLE, bike_id, {"General Notes": updated})




def clean_select(val, allowed, default=None):
    if val is None:
        return default
    if not isinstance(val, str):
        return default
    v = val.strip().strip('"').strip("'")  # removes accidental quoting
    return v if v in allowed else default

#String Normalisation functions
def norm_vin(s: str | None) -> str | None:
    if not s:
        return None
    # Uppercase, remove spaces and common separators
    return (
        s.upper()
         .replace(" ", "")
         .replace("-", "")
         .replace("_", "")
    )

def norm_make(s: str | None) -> str | None:
    if not s:
        return None
    return s.strip().title()  # "kawasaki" -> "Kawasaki"

def norm_colour(value: str | None) -> str | None:
    """
    Normalize colour text into Title-cased, comma-separated colours (1–3).
    Examples:
      "red" -> "Red"
      "REd and White" -> "Red,White"
      "Red, White and Blue" -> "Red,White,Blue"

    Notes:
    - Accepts separators: commas, 'and', '&', '/', '+'
    - Dedupes (case-insensitive)
    - Keeps order of appearance
    - Limits to first 3 colours
    """
    if value is None:
        return None

    s = str(value).strip()
    if not s:
        return None

    # Standardize common separators to comma
    s = s.replace("&", ",")
    s = s.replace("/", ",")
    s = s.replace("+", ",")
    s = re.sub(r"\band\b", ",", s, flags=re.IGNORECASE)

    # Split on commas
    parts = [p.strip() for p in s.split(",") if p.strip()]

    # Clean + Title-case each part (keep hyphens/words)
    cleaned = []
    seen = set()
    for p in parts:
        # remove weird extra punctuation but keep letters, numbers, spaces, hyphens
        p2 = re.sub(r"[^A-Za-z0-9 \-]", "", p).strip()
        if not p2:
            continue

        # collapse spaces
        p2 = re.sub(r"\s+", " ", p2)

        # Title-case each word
        p2 = " ".join(w.capitalize() for w in p2.split(" "))

        key = p2.lower()
        if key in seen:
            continue
        seen.add(key)
        cleaned.append(p2)

        if len(cleaned) == 3:
            break

    if not cleaned:
        return None

    return ",".join(cleaned)


def norm_model(s: str | None) -> str | None:
    if not s:
        return None
    s = s.strip()
    # Uppercase model codes (ZX7R, VFR750F, GSX750E etc)
    s = re.sub(r"\s+", " ", s)
    return s.upper()

def norm_year(y):
    try:
        return int(y) if y is not None else None
    except:
        return None

def norm_odo(x):
    try:
        # allow "123,456" or "123456"
        if x is None:
            return None
        if isinstance(x, str):
            x = x.replace(",", "").strip()
        return int(float(x))
    except:
        return None

import re

def format_general_notes(raw: str) -> str | None:
    """
    Turn messy notes into readable, line-separated bullets.

    Handles:
    - Semicolons
    - Newlines
    - Bullets (-, •)
    - 'Notes:' style prefixes
    - Falls back to commas if needed
    """
    if not raw:
        return None

    text = raw.strip()
    if not text:
        return None

    # Remove common leading labels
    text = re.sub(
        r"^(general notes|notes|work needed|work required)\s*[:\-]*\s*",
        "",
        text,
        flags=re.IGNORECASE
    )

    # Normalize line breaks
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    # Split priority:
    # 1) semicolons
    # 2) line breaks
    # 3) bullets
    # 4) commas (fallback)
    if ";" in text:
        parts = text.split(";")
    elif "\n" in text:
        parts = text.split("\n")
    elif re.search(r"[•\-]\s", text):
        parts = re.split(r"[•\-]\s+", text)
    elif "," in text:
        parts = text.split(",")
    else:
        # Single sentence → just wrap it
        return f"Notes:\n- {text[0].upper() + text[1:]}"

    # Clean parts
    cleaned = []
    for p in parts:
        p = p.strip(" -•\t")
        if not p:
            continue
        p = p[0].upper() + p[1:]
        cleaned.append(p)

    if not cleaned:
        return None

    lines = ["Notes:"]
    for item in cleaned:
        lines.append(f"- {item}")

    return "\n".join(lines)

    
def normalise_bike_data(bike_data: dict) -> dict:
    """Return a copy of bike_data with consistent casing/types for matching + updating."""
    out = dict(bike_data or {})
    out["make"] = norm_make(out.get("make"))
    out["model"] = norm_model(out.get("model"))          # upper-case (ZX7R)
    out["colour"] = norm_colour(out.get("colour"))
    out["year"] = norm_year(out.get("year"))
    out["odometer_reading"] = norm_odo(out.get("odometer_reading"))
    out["vin_engine_number"] = norm_vin(out.get("vin_engine_number"))

    # normalise odometer_type to exactly what your Airtable single-select expects
    ot = out.get("odometer_type")
    if isinstance(ot, str):
        ot_clean = ot.strip().lower()
        if ot_clean in ("km", "kms", "kilometres", "kilometers"):
            out["odometer_type"] = "Km"
        elif ot_clean in ("miles", "mi"):
            out["odometer_type"] = "Miles"
        else:
            out["odometer_type"] = None

    return out

def mark_intake_needs_clarification(intake_record_id: str, message: str):
    """
    Update the AI Intake record:
    - Status = 'Needs clarification'
    - Clarification needed = message
    """
    payload = {
        "fields": {
            "Status": "Needs clarification",
            "Clarification needed": message
        }
    }

    resp = requests.patch(
        f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_AI_INTAKE_TABLE}/{intake_record_id}",
        headers=AIRTABLE_HEADERS,
        json=payload
    )

    if resp.status_code >= 400:
        print("Failed to mark intake as Needs clarification:", resp.status_code)
        print(resp.text)

    resp.raise_for_status()
    print(f"Marked intake {intake_record_id} as Needs clarification.")


#fetch all bikes
def fetch_all_bikes():
    """
    Fetch ALL bike records from the Bikes table.
    Handles Airtable pagination automatically.
    Returns a list of Airtable record dicts.
    """
    records = []
    offset = None

    while True:
        params = {}
        if offset:
            params["offset"] = offset

        resp = requests.get(
            f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_BIKES_TABLE}",
            headers=AIRTABLE_HEADERS,
            params=params
        )

        if resp.status_code >= 400:
            print("Failed to fetch bikes:", resp.status_code)
            print(resp.text)
            resp.raise_for_status()

        data = resp.json()
        batch = data.get("records", [])
        records.extend(batch)

        offset = data.get("offset")
        if not offset:
            break

    print(f"Fetched {len(records)} bike(s) from Airtable.")
    return records



# Update bike record if required
def update_bike_if_needed(bike_record_id: str, bike_data: dict, existing_fields: dict) -> bool:
    """
    Update bike record:
    - Fill missing VIN / Odo Type / Notes / Colour
    - ALWAYS update odometer reading if intake provides one AND it's different
    - Update VIN if intake VIN exists and Airtable is blank (don’t overwrite existing VIN by default)
    """

    updates = {}

    def set_if_missing(field_name, new_value):
        if new_value is None:
            return
        existing = existing_fields.get(field_name)
        if existing in (None, "", []):
            updates[field_name] = new_value

    # VIN: only fill if missing (safer)
    set_if_missing("VIN / Engine Number", bike_data.get("vin_engine_number"))

    # Odometer Type + Notes: fill if missing
    set_if_missing("Odometer Type", bike_data.get("odometer_type"))

    # We no longer write to Bikes.General Notes here.
    # General Notes is now maintained by update_bike_general_notes_from_intake()

    #raw_notes = bike_data.get("general_notes")
    #if raw_notes:
    #    formatted = format_general_notes(raw_notes)
    #    raw_notes = bike_data.get("general_notes")
    #    if raw_notes:
    #        formatted = format_general_notes(raw_notes)
    #        set_if_missing("General Notes", formatted)



    # Colour: fill if missing (safe)
    # Make sure bike_data["colour"] is already normalised (e.g., "Red", "Blue", etc.)
    set_if_missing("Colour", bike_data.get("colour"))

    # OPTIONAL: If you want to update colour when different (less safe), use this instead:
    # new_colour = bike_data.get("colour")
    # if new_colour:
    #     existing_colour = norm_colour(existing_fields.get("Colour"))
    #     if existing_colour != norm_colour(new_colour):
    #         updates["Colour"] = new_colour

    # Odometer Reading: update if different (common real-world case)
    new_odo = bike_data.get("odometer_reading")
    if new_odo is not None:
        existing_odo = norm_odo(existing_fields.get("Odometer Reading"))
        if existing_odo != new_odo:
            updates["Odometer Reading"] = new_odo

    if not updates:
        return False

    payload = {"fields": updates}
    resp = requests.patch(
        f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_BIKES_TABLE}/{bike_record_id}",
        headers=AIRTABLE_HEADERS,
        json=payload
    )
    resp.raise_for_status()
    print(f"Updated bike {bike_record_id} with: {list(updates.keys())}")
    return True


# find or create a bike record
def find_or_create_bike(bike_data, user_id=None):
    """
    Find an existing bike in Airtable or create a new one.

    Matching priority:
    1) VIN/Engine Number (if provided):
       - Normalise VIN and match exactly.
       - If exactly 1 match -> use it.
       - If >1 match -> AMBIGUOUS -> return None (Needs clarification).
       - If 0 matches -> continue to Make/Model/Year logic.

    2) Make + Model are required for any match or create attempt.
       - If missing -> return None (Needs clarification).

    3) Make + Model + Year (preferred match when Year is present):
       - Find all bikes with same Make+Model+Year.
       - If 1 match -> use it.
       - If multiple matches:
           * If colour provided -> try exact colour match first.
           * If still multiple and odometer provided -> try odometer disambiguation (within tolerance window).
           * If still ambiguous -> return None (Needs clarification).

    4) Make + Model with Year missing:
       - If Make+Model matches multiple bikes:
           * If colour provided -> try exact colour match first.
           * If still multiple and odometer provided -> try odometer disambiguation (within tolerance window).
           * Else -> return None (Needs clarification).
       - If Make+Model matches exactly one bike -> use it.

    Creation guardrails:
    - Only create a new bike if:
        * VIN is provided, OR
        * Year is provided (with Make+Model).
      Otherwise return None (Needs clarification).

    Updates:
    - If an existing bike is found, update new details (odo/VIN/status/notes/colour) via update_bike_if_needed().
    - Set Bikes.'Assigned User' to user_id only if blank (do not overwrite).
    """

    # 0) Normalise input
    bike_data = normalise_bike_data(bike_data)

    make = bike_data.get("make")
    model = bike_data.get("model")
    year = bike_data.get("year")
    colour = bike_data.get("colour")  # text field
    vin = bike_data.get("vin_engine_number")
    odo = bike_data.get("odometer_reading")

    # Normalise colour for matching (text field; keep simple + forgiving)
    def norm_colour_text(v):
        if v is None:
            return None
        s = str(v).strip().lower()
        return s or None

    colour_norm = norm_colour_text(colour)

    # 1) Fetch all bikes once for local matching
    all_bikes = fetch_all_bikes()

    # Helper: assign user if blank (NO overwrite)
    def assign_user_if_blank(bike_id: str, existing_fields: dict):
        if not user_id:
            return
        current = existing_fields.get("Assigned User")
        if isinstance(current, list) and len(current) > 0:
            return  # already assigned, leave it
        patch = {"fields": {"Assigned User": [user_id]}}
        r = requests.patch(
            f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_BIKES_TABLE}/{bike_id}",
            headers=AIRTABLE_HEADERS,
            json=patch
        )
        if not r.ok:
            print("WARNING: Failed to set Assigned User on bike:", r.status_code, r.text)
        else:
            print(f"Set Bikes.Assigned User for {bike_id} -> {user_id}")

    # Helper: pick candidate by colour (exact match on normalised text)
    def filter_by_colour(cands: list[dict]) -> list[dict]:
        if not colour_norm:
            return cands
        matched = []
        for r in cands:
            f = r.get("fields", {})
            r_colour = norm_colour_text(f.get("Colour"))
            if r_colour and r_colour == colour_norm:
                matched.append(r)
        return matched if matched else cands  # if no colour matches, don't eliminate everything

    # Helper: pick candidate by odometer within tolerance
    def filter_by_odo(cands: list[dict], tolerance: int = 2000) -> list[dict]:
        if odo is None:
            return cands
        matched = []
        for r in cands:
            f = r.get("fields", {})
            r_odo = norm_odo(f.get("Odometer Reading"))
            if r_odo is None:
                continue
            if abs(r_odo - odo) <= tolerance:
                matched.append(r)
        return matched if matched else cands  # if no odo matches, don't eliminate everything

    # 2) Strong match by VIN (if provided)
    if vin:
        vin_norm = norm_vin(vin)
        vin_matches = []
        for r in all_bikes:
            f = r.get("fields", {})
            r_vin = norm_vin(f.get("VIN / Engine Number"))
            if r_vin and r_vin == vin_norm:
                vin_matches.append(r)

        if len(vin_matches) == 1:
            bike_id = vin_matches[0]["id"]
            existing_fields = vin_matches[0].get("fields", {})
            update_bike_if_needed(bike_id, bike_data, existing_fields)
            assign_user_if_blank(bike_id, existing_fields)
            print("Found existing bike by VIN with record ID:", bike_id)
            return bike_id

        if len(vin_matches) > 1:
            print(f"Needs clarification: VIN matches {len(vin_matches)} bikes. Add more detail (year/odo/colour).")
            return None
        # No VIN match → continue

    # 3) If we don't have make+model, we can't match and we can't create safely
    if not (make and model):
        print("Needs clarification: make and model are required to find or create a bike.")
        return None

    # 4) Build list of make+model matches (used for year-missing path)
    same_make_model = []
    for r in all_bikes:
        f = r.get("fields", {})
        if norm_make(f.get("Make")) == make and norm_model(f.get("Model")) == model:
            same_make_model.append(r)

    # 5) Year missing case
    if year is None:
        if len(same_make_model) == 0:
            # No existing match. If VIN exists, we can safely create even without year.
            if vin:
                print(f"No existing {make} {model} found and year is missing, but VIN was provided → creating new bike.")
                # fall through to creation section at the bottom (do NOT return None)
            else:
                print(f"Needs clarification: no existing {make} {model} found, and year is missing.")
                return None


        if len(same_make_model) == 1:
            bike_id = same_make_model[0]["id"]
            existing_fields = same_make_model[0].get("fields", {})
            update_bike_if_needed(bike_id, bike_data, existing_fields)
            assign_user_if_blank(bike_id, existing_fields)
            print("Found existing bike by Make+Model with record ID:", bike_id)
            return bike_id

        # Multiple make+model matches → try colour then odo
        candidates = filter_by_colour(same_make_model)
        if len(candidates) > 1:
            candidates = filter_by_odo(candidates, tolerance=2000)

        if len(candidates) == 1:
            bike_id = candidates[0]["id"]
            existing_fields = candidates[0].get("fields", {})
            update_bike_if_needed(bike_id, bike_data, existing_fields)
            assign_user_if_blank(bike_id, existing_fields)
            print("Found existing bike by Make+Model with colour/odo disambiguation. Record ID:", bike_id)
            return bike_id

        # Still ambiguous
        print(
            f"Needs clarification: multiple {make} {model} bikes exist and year is missing. "
            f"Please add year OR odometer OR colour (or VIN/engine)."
        )
        return None

    # 6) Year present case: use Make+Model+Year then disambiguate colour/odo
    candidates = []
    for r in all_bikes:
        f = r.get("fields", {})
        if (
            norm_make(f.get("Make")) == make
            and norm_model(f.get("Model")) == model
            and norm_year(f.get("Year")) == year
        ):
            candidates.append(r)

    if len(candidates) == 1:
        bike_id = candidates[0]["id"]
        existing_fields = candidates[0].get("fields", {})
        update_bike_if_needed(bike_id, bike_data, existing_fields)
        assign_user_if_blank(bike_id, existing_fields)
        print("Found existing bike by Make+Model+Year with record ID:", bike_id)
        return bike_id

    if len(candidates) > 1:
        # Disambiguate by colour first, then odo
        narrowed = filter_by_colour(candidates)
        if len(narrowed) > 1:
            narrowed = filter_by_odo(narrowed, tolerance=2000)

        if len(narrowed) == 1:
            bike_id = narrowed[0]["id"]
            existing_fields = narrowed[0].get("fields", {})
            update_bike_if_needed(bike_id, bike_data, existing_fields)
            assign_user_if_blank(bike_id, existing_fields)
            print("Found existing bike by Make+Model+Year with colour/odo disambiguation. Record ID:", bike_id)
            return bike_id

        print("Needs clarification: multiple bikes match Make+Model+Year and cannot disambiguate (add odo/colour/VIN).")
        return None

    # 7) No match found. Only create if we have YEAR or VIN.
    # (We do have YEAR here, so allowed)
    fields = {
        "Make": make,
        "Model": model,
        "Year": year,
        "Colour": bike_data.get("colour"),
        "VIN / Engine Number": bike_data.get("vin_engine_number"),
        "Status": bike_data.get("status"),
        "Odometer Reading": bike_data.get("odometer_reading"),
        "Odometer Type": bike_data.get("odometer_type") or "Km",
        #"General Notes": format_general_notes(bike_data.get("general_notes")),
    }

    # set Assigned User on new bikes
    if user_id:
        fields["Assigned User"] = [user_id]

    fields = {k: v for k, v in fields.items() if v is not None}

    payload = {"fields": fields}
    resp = requests.post(
        f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_BIKES_TABLE}",
        headers=AIRTABLE_HEADERS,
        json=payload
    )
    if resp.status_code >= 400:
        print("Create bike failed:", resp.status_code)
        print(resp.text)
    resp.raise_for_status()

    created = resp.json()
    bike_id = created["id"]
    print("Created new bike with record ID:", bike_id)
    return bike_id




#Create repairs for bikes
def create_repairs_for_bike(bike_record_id, repairs_list, user_id):
    """
    Create Repair records in Airtable linked to the given bike_record_id.
    repairs_list is parsed['repairs'] from Grok.

    Airtable API LIMITATION:
      - A maximum of 10 records can be created per request
    So we batch the create requests in chunks of 10.

    Expected fields per repair item:
      - repair_name (str)
      - status: "Completed" | "Under Repair" | "Waiting on Parts"
      - completed_where: "Workshop" | "Pre-arrival" | "Unknown" | null (optional; only relevant if Completed)
      - notes (str | null)
      - start_date (optional)
      - completion_date (optional)
    """
    if not bike_record_id:
        print("No bike_record_id provided, skipping repairs creation.")
        return

    if not repairs_list:
        print("No repairs in JSON, nothing to create.")
        return

    table_name = "Repairs"
    table_path = quote(table_name, safe="")
    url = f"{AIRTABLE_API_URL}/{table_path}"

    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }

    allowed_status = {"Completed", "Under Repair", "Waiting on Parts"}
    allowed_completed_where = {"Workshop", "Pre-arrival", "Unknown"}

    records_payload = []
    for r in repairs_list:
        repair_name = (r.get("repair_name") or "").strip()
        if not repair_name:
            continue

        status = (r.get("status") or "").strip()
        if status not in allowed_status:
            # Default for ambiguous/unknown items: treat as work to do
            status = "Under Repair"

        fields = {
            "Repair Name": repair_name,
            "Status": status,
            "Detailed Notes": (r.get("notes") or "").strip(),
            # Link to the Bike – Airtable expects an array of record IDs
            "Bike": [bike_record_id],
        }

        # Changed logic back to find completed_where
        if status == "Completed":
           completed_where = (r.get("completed_where") or "").strip()
           if completed_where not in allowed_completed_where:
               completed_where = "Unknown"
           fields["Completed Where"] = completed_where
           # fields["Completed Where"] = "Workshop"

        if user_id:
            fields["Performed By"] = [user_id]

        # Optional dates (only set if present)
        if r.get("start_date"):
            fields["Start Date"] = r["start_date"]
        if r.get("completion_date"):
            fields["Completion Date"] = r["completion_date"]

        records_payload.append({"fields": fields})

    if not records_payload:
        print("No valid repairs to create.")
        return

    # -----------------------
    # Airtable batching (10 max)
    # -----------------------
    BATCH_SIZE = 10
    total_to_create = len(records_payload)
    created_total = 0

    print(f"\nCreating {total_to_create} repair(s) in Airtable...")

    for i in range(0, total_to_create, BATCH_SIZE):
        batch = records_payload[i:i + BATCH_SIZE]
        payload = {"records": batch}

        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        print(f"Repairs batch {i//BATCH_SIZE + 1} create status:", resp.status_code)

        if not resp.ok:
            print("Error creating repairs:", resp.text)
            return

        data = resp.json()
        created = data.get("records", [])
        created_total += len(created)

    print(f"Created {created_total} repair record(s).")


#default applies to helper function
def build_default_applies_to(parsed_bike: dict) -> str:
    if not parsed_bike:
        return ""
    make = (parsed_bike.get("make") or "").strip()
    model = (parsed_bike.get("model") or "").strip()
    year = parsed_bike.get("year")
    parts = [p for p in [make, model] if p]
    if year:
        parts.append(str(int(year)))
    return " ".join(parts).strip()


#Ceate parts to order for bike
def create_parts_to_order_for_bike(bike_record_id, parts_list, user_id, default_applies_to=None):
    """
    Create 'Parts to Order' records in Airtable.
    If bike_record_id is provided -> link to Bike.
    Else -> write Applies To.
    """
    if not parts_list:
        print("No parts_to_order in JSON, nothing to create.")
        return

    table_name = "Parts to Order"
    url = f"{AIRTABLE_API_URL}/{table_name}"

    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }

    today_str = date.today().isoformat()
    records_payload = []

    for p in parts_list:
        part_name = p.get("part_name")
        if not part_name:
            continue

        applies_to = (p.get("applies_to") or default_applies_to or "").strip()

        fields = {
            "Part Name": part_name,
            "Reason": clean_select(p.get("reason"), ALLOWED_REASON, default="First Assessment"),
            "Priority": clean_select(p.get("priority"), ALLOWED_PRIORITY, default=None),
            "Status": clean_select(p.get("status"), ALLOWED_PART_STATUS, default="To Order"),
            "Notes": p.get("notes") or "",
            "Date Identified": today_str,
        }

        # Link logic:
        if bike_record_id:
            fields["Bike"] = [bike_record_id]
        else:
            # Only set Applies To when there's no bike link
            if applies_to:
                fields["Applies To"] = applies_to

        if user_id:
            fields["Identified By"] = [user_id]

        records_payload.append({"fields": fields})

    if not records_payload:
        print("No valid parts to create.")
        return

    payload = {"records": records_payload}
    print(f"\nCreating {len(records_payload)} part(s) to order in Airtable...")
    resp = requests.post(url, headers=headers, json=payload)
    print("Parts create status:", resp.status_code)

    if not resp.ok:
        print("Error creating parts:", resp.text)
        return

    data = resp.json()
    created = data.get("records", [])
    print(f"Created {len(created)} part(s) to order.")


#Create parts box for bike
def create_parts_box_for_bike(bike_record_id, parts_box_data, user_id):
    """
    Create a Bike Parts Box record linked to the given bike_record_id,
    based on the 'parts_box' object from Grok.
    """
    if not bike_record_id:
        print("No bike_record_id provided, skipping parts box creation.")
        return

    if not parts_box_data:
        print("No parts_box data in JSON, skipping.")
        return

    box_name = parts_box_data.get("box_name")
    location = parts_box_data.get("location")
    contents_summary = parts_box_data.get("contents_summary")

    # If everything is empty/null, don't create anything
    if not (box_name or location or contents_summary):
        print("Parts box data is empty, nothing to create.")
        return

    table_name = "Bike Parts Boxes"  # must match your table name
    url = f"{AIRTABLE_API_URL}/{table_name}"

    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }

    fields = {
        "Bike": [bike_record_id],
        "Box Name": box_name or "Main Parts Box",
    }

    if location:
        fields["Location"] = location
    if contents_summary:
        fields["Contents Summary"] = contents_summary
    if user_id:
        fields["Last Updated By"] = [user_id]

    # Optional timestamp
    try:
        today_str = date.today().isoformat()
        fields["Last Updated Date"] = today_str
    except Exception:
        pass

    payload = {"fields": fields}

    print("\nCreating parts box in Airtable...")
    resp = requests.post(url, headers=headers, json=payload)
    print("Parts box create status:", resp.status_code)

    if not resp.ok:
        print("Error creating parts box:", resp.text)
        return

    data = resp.json()
    rec_id = data.get("id")
    print("Created parts box with record ID:", rec_id)

#check if bike has primary photo already
def bike_has_primary_photo(bike_record_id: str) -> bool:
    table_name = "Photos"
    url = f"{AIRTABLE_API_URL}/{quote(table_name, safe='')}"
    headers = {"Authorization": f"Bearer {AIRTABLE_API_KEY}"}

    # Airtable formula: Bike Link contains this bike AND Primary Image = 1
    # If Bike Link is a linked-record field, it stores record IDs.
    formula = f"AND(FIND('{bike_record_id}', ARRAYJOIN({{Bike Link}})), {{Primary Image}}=1)"

    params = {
        "filterByFormula": formula,
        "maxRecords": 1
    }

    r = requests.get(url, headers=headers, params=params, timeout=30)
    r.raise_for_status()
    data = r.json()
    return len(data.get("records", [])) > 0

def create_photo_records_from_intake(intake_record: dict, bike_record_id: str, user_id):
    """
    Takes an AI Intake record (already fetched from Airtable), reads attachments in 'Intake Media',
    then creates one Photos-table record per attachment linked to the given bike_record_id.

    NEW BEHAVIOUR:
    - If the bike has NO existing Primary Image, the FIRST attachment created from this intake
      will be marked Primary Image = True.
    - Otherwise, none of these will be marked primary.
    """
    intake_fields = intake_record.get("fields", {})
    attachments = intake_fields.get("Intake Media", [])

    if not attachments:
        print("No Intake Media attachments found - skipping photo creation.")
        return []

    # NEW: check if bike already has a primary photo
    already_has_primary = bike_has_primary_photo(bike_record_id)

    created_photo_ids = []

    for i, att in enumerate(attachments, start=1):
        photo_attachment_value = [{
            "url": att.get("url"),
            "filename": att.get("filename")
        }]

        # Optional: if Media Notes / Caption is one caption for the whole intake,
        # it might be nicer to keep it but still make the Photo Name unique.
        base_name = intake_fields.get("Media Notes / Caption") or "Intake photo"
        photo_name = f"{base_name} {i}" if len(attachments) > 1 else base_name

        # NEW: decide if this photo should be primary
        is_primary = (i == 1) and (not already_has_primary)

        photo_payload = {
            "fields": {
                "Photo": photo_attachment_value,
                "Photo Name": photo_name,
                "Bike Link": [bike_record_id],
                "Primary Image": is_primary,  # NEW
            }
        }

        if user_id:
            photo_payload["fields"]["Uploaded By"] = [user_id]

        resp = requests.post(
            f"https://api.airtable.com/v0/{AIRTABLE_BASE_ID}/{AIRTABLE_PHOTOS_TABLE}",
            headers=AIRTABLE_HEADERS,
            json=photo_payload
        )
        resp.raise_for_status()
        created = resp.json()
        created_photo_ids.append(created["id"])

    print(f"Created {len(created_photo_ids)} photo record(s).")
    if (not already_has_primary) and created_photo_ids:
        print("Set first intake photo as Primary Image.")
    return created_photo_ids




# Process intake notes (using Grok API)
def process_intake_notes():
    """
    Fetch AI Intake records with Status='New', process each with Grok,
    and update Airtable with the results.

    BEHAVIOUR:
    - If bike cannot be uniquely identified (bike_id is None):
        * If parts_to_order exists -> create UNASSIGNED parts (no Bike link), using Applies To,
          then mark intake as Processed.
        * Else -> Status = 'Needs clarification' and stop processing that record.

    - If bike_id is found:
        * Create Repairs / Parts / Parts Box / Photos
        * Update Bikes.General Notes by UPSERTING a dated block keyed by AI Intake rec_id
          (append new blocks; replace existing block if reprocessed)
        * Mark intake Processed and link Bike
    """
    table_name = AIRTABLE_AI_INTAKE_TABLE  # "AI Intake"
    table_path = quote(table_name, safe="")
    url = f"{AIRTABLE_API_URL}/{table_path}"

    headers = {
        "Authorization": f"Bearer {AIRTABLE_API_KEY}",
        "Content-Type": "application/json",
    }

    def patch_intake(rec_id: str, fields_to_update: dict):
        r = requests.patch(
            f"{url}/{rec_id}",
            headers=headers,
            json={"fields": fields_to_update},
            timeout=30
        )
        if not r.ok:
            print("\nAirtable PATCH failed")
            print("Status:", r.status_code)
            print("Response:", r.text)
            r.raise_for_status()
        return r.json()

    params = {
        "filterByFormula": "{Status}='New'",
        "maxRecords": 20,
    }

    print("\nChecking AI Intake for new notes...")
    resp = requests.get(url, headers=headers, params=params, timeout=30)
    if not resp.ok:
        print("Error reading AI Intake:", resp.status_code, resp.text)
        return

    records = resp.json().get("records", [])
    if not records:
        print("No new notes found.")
        return

    print(f"Found {len(records)} new intake note(s).")

    for rec in records:
        rec_id = rec["id"]
        fields = rec.get("fields", {})
        note_text = fields.get("Note", "") or ""
        user_id = get_effective_user_id(fields)

        print(f"\nProcessing intake record {rec_id}...")
        patch_intake(rec_id, {"Status": "Processing"})

        # 1) Parse via Grok
        parsed = grok_parse_note(note_text)
        if parsed is None:
            patch_intake(rec_id, {"Status": "Error"})
            continue

        # Extract lists early (we use these even if bike_id is missing)
        repairs_list = parsed.get("repairs", []) or []
        parts_to_order_list = parsed.get("parts_to_order", []) or []
        parts_box_payload = parsed.get("parts_box", {}) or {}
        bike_payload = parsed.get("bike", {}) or {}

        # 2) Find/Create bike (pass user_id so create can set Assigned User)
        bike_id = find_or_create_bike(bike_payload, user_id=user_id)

        # If found/created, ensure assigned user is set if blank (safe/no overwrite)
        if bike_id:
            set_bike_assigned_user_if_blank(bike_id, user_id)

        # ----------------------------
        # Parts-only fallback (no bike match)
        # ----------------------------
        if not bike_id:
            if parts_to_order_list:
                default_applies_to = build_default_applies_to(bike_payload)

                print("No unique bike match, but parts_to_order exists -> creating UNASSIGNED parts...")

                create_parts_to_order_for_bike(
                    bike_record_id=None,
                    parts_list=parts_to_order_list,
                    user_id=user_id,
                    default_applies_to=default_applies_to
                )

                summary = (
                    f"Processed (unassigned parts). "
                    f"Created {len(parts_to_order_list)} part(s). "
                    f"Applies To: {default_applies_to or 'N/A'}"
                )
                patch_intake(rec_id, {
                    "Status": "Processed",
                    "Result Summary": summary,
                })

                print("Finished processing (unassigned parts).")
                continue

            # No parts to order -> needs clarification
            make = (bike_payload.get("make") or "").strip()
            model = (bike_payload.get("model") or "").strip()
            year = bike_payload.get("year")
            odo = bike_payload.get("odometer_reading")
            odo_type = bike_payload.get("odometer_type")
            vin = bike_payload.get("vin_engine_number")

            mm = " ".join([x for x in [make, model] if x]).strip() or "this bike"

            extracted_bits = []
            if year:
                extracted_bits.append(f"year={year}")
            if odo:
                extracted_bits.append(f"odometer={odo} {odo_type or ''}".strip())
            if vin:
                extracted_bits.append("VIN/engine# provided")

            extracted_str = f"I extracted: {', '.join(extracted_bits)}. " if extracted_bits else ""

            clarification_msg = (
                f"Needs clarification: I couldn't uniquely match {mm} to an existing record. "
                f"{extracted_str}"
                "Please update the note with ONE of: (1) Year, (2) VIN/engine number, or "
                "(3) a more specific odometer reading + whether it’s Km or Miles. "
                "Then set Status back to 'New' to reprocess."
            )

            mark_intake_needs_clarification(rec_id, clarification_msg)
            continue

        # ----------------------------
        # Normal path (bike found)
        # ----------------------------
        create_repairs_for_bike(bike_id, repairs_list, user_id)

        default_applies_to = build_default_applies_to(bike_payload)
        create_parts_to_order_for_bike(
            bike_id,
            parts_to_order_list,
            user_id,
            default_applies_to=default_applies_to
        )

        create_parts_box_for_bike(bike_id, parts_box_payload, user_id)
        create_photo_records_from_intake(rec, bike_id, user_id)

        # NEW: Update Bikes.General Notes (append dated block; no duplication on reprocess)
        # This will append a new dated block for new intake records,
        # and replace the block if this same rec_id is reprocessed.
        try:
            update_bike_general_notes_from_intake(
                bike_id=bike_id,
                intake_rec_id=rec_id,
                note_text=note_text,
                repairs_list=repairs_list,
                parts_to_order_list=parts_to_order_list,
                parts_box_payload=parts_box_payload
            )
        except Exception as ex:
            # Don't fail the entire intake processing if notes update has an issue
            print("WARNING: Failed to update Bike General Notes:", ex)

        # Mark Processed
        summary = f"Processed. Bike ID: {bike_id}"
        patch_intake(rec_id, {
            "Status": "Processed",
            "Result Summary": summary,
            "Bike": [bike_id],
        })

        print("Finished processing.")




def grok_parse_note(note_text: str) -> dict | None:
    """
    Sends note_text to Grok using JSON schema and returns parsed JSON (dict).

    Improvements:
      - Retries with exponential backoff on timeouts / transient failures
      - Longer read timeout for long, complex notes
      - Input normalisation to reduce payload size
      - Robust to ```json code fences
      - Best-effort extraction of first {...} JSON object
    """
    if not note_text or not note_text.strip():
        return None

    # Normalise whitespace to reduce payload size / latency
    note_text = " ".join(note_text.strip().split())

    payload = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": note_text},
        ],
        "temperature": 0,
    }

    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    }

    def _strip_code_fences(s: str) -> str:
        s = s.strip()
        # Remove ```json ... ``` or ``` ... ```
        if s.startswith("```"):
            s = re.sub(r"^```[a-zA-Z]*\s*", "", s)
            s = re.sub(r"\s*```$", "", s)
        return s.strip()

    def _extract_first_json_object(s: str) -> str | None:
        """
        Best-effort extraction of the first top-level JSON object from a string.
        Uses a simple brace-balance scan.
        """
        start = s.find("{")
        if start == -1:
            return None
        depth = 0
        for i in range(start, len(s)):
            ch = s[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return s[start : i + 1]
        return None

    max_attempts = 4
    base_sleep = 2

    for attempt in range(1, max_attempts + 1):
        try:
            resp = requests.post(
                API_URL,
                headers=headers,
                json=payload,
                timeout=(10, 180),  # (connect timeout, read timeout)
            )

            # Retryable HTTP statuses
            if resp.status_code in (429, 500, 502, 503, 504):
                raise requests.HTTPError(
                    f"Retryable HTTP {resp.status_code}", response=resp
                )

            resp.raise_for_status()

            content = resp.json()["choices"][0]["message"]["content"]
            content = _strip_code_fences(content)

            # Try direct JSON parse
            try:
                parsed = json.loads(content)
                return parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                # Fallback: extract first {...} block
                candidate = _extract_first_json_object(content)
                if not candidate:
                    print("Grok response did not contain a JSON object.")
                    print("Raw content:", content[:800])
                    return None
                parsed = json.loads(candidate)
                return parsed if isinstance(parsed, dict) else None

        except (requests.Timeout, requests.ConnectionError) as e:
            print(f"Error talking to Grok (attempt {attempt}/{max_attempts}): {e}")

        except requests.HTTPError as e:
            print(f"Grok HTTP error (attempt {attempt}/{max_attempts}): {e}")
            try:
                print("Response text:", resp.text[:800])  # type: ignore
            except Exception:
                pass

        except Exception as e:
            print("Unexpected Grok error:", e)
            try:
                print("Last response text:", resp.text[:800])  # type: ignore
            except Exception:
                pass
            return None

        # Exponential backoff with jitter
        if attempt < max_attempts:
            sleep_s = base_sleep * (2 ** (attempt - 1)) + random.uniform(0, 0.75)
            time.sleep(sleep_s)

    return None



if __name__ == "__main__":
    process_intake_notes()





