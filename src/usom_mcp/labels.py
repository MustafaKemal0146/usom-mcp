"""Static fallback labels for USOM code tables.

The authoritative tables come from the API (``/api/address-description/index`` etc.)
and are refreshed during sync; these defaults keep results readable offline and
cover codes added later by passing the raw code through.
"""

from __future__ import annotations

from typing import Final

Labels = dict[str, tuple[str, str]]  # id -> (english, turkish)

CATEGORIES: Final[Labels] = {
    "PH": ("Phishing", "Oltalama"),
    "MD": ("Malware Distribution Domain", "Zararlı Yazılım Barındıran / Yayan Alan Adı"),
    "MI": ("Malware Distribution IP", "Zararlı Yazılım Barındıran / Yayan IP"),
    "MU": ("Malware Distribution URL", "Zararlı Yazılım Barındıran / Yayan URL"),
    "MC": ("Malware Command Center", "Zararlı Yazılım - Komuta Kontrol Merkezi"),
    "BP": ("Financial Phishing", "Bankacılık - Oltalama"),
    "CA": (
        "Cyber Attack (Port Scan, Brute Force etc.)",
        "Siber Saldırı (Port Tarama, Kaba Kuvvet vb.)",
    ),
}

CONNECTION_TYPES: Final[Labels] = {
    "AC": ("APT C&C", "Apt C&C"),
    "BC": ("Botnet C&C", "Botnet C&C"),
    "EK": ("Exploit Kit", "Exploit Kit"),
    "MC": ("Mobile C&C", "Mobil C&C"),
    "MF": ("Malware Download", "Zararlı Dosya İndirme"),
    "MM": ("Mining Malware", "Mining Zararlısı"),
    "OT": ("Other", "Diğer"),
    "PH": ("Phishing", "Oltalama"),
}

SOURCES: Final[Labels] = {
    "US": ("TR-CERT", "USOM"),
    "SO": ("CERT", "SOME"),
    "RS": ("RSA", "RSA"),
    "IH": ("REPORTING", "İHBAR"),
    "SB": ("SGB", "SGB"),
}

DICTIONARY_KINDS: Final[dict[str, Labels]] = {
    "category": CATEGORIES,
    "connection_type": CONNECTION_TYPES,
    "source": SOURCES,
}

#: API endpoint for each dictionary kind
DICTIONARY_ENDPOINTS: Final[dict[str, str]] = {
    "category": "/api/address-description/index",
    "connection_type": "/api/address-connection-type/index",
    "source": "/api/address-source/index",
}
