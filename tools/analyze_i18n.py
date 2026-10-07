import re
from pathlib import Path

loc_path = Path("apps/windows/Fetih.Desktop/Services/Localization.cs")
if loc_path.exists():
    text = loc_path.read_text(encoding="utf-8")
    keys = re.findall(r'\["([^"]+)"\]\s*=', text)
    print(f"Total keys in Localization.cs: {len(keys)}")
    chat_keys = [k for k in keys if "chat" in k]
    print("Dialog keys:", [k for k in keys if any(x in k for x in ["dialog", "confirm", "cancel", "save", "button"])])
