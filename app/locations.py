from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache

REGIONAL_INDICATOR_OFFSET = 0x1F1E6 - ord("A")


@dataclass(frozen=True)
class LocationInfo:
    code: str
    name: str
    flag: str

    @property
    def display_name(self) -> str:
        if self.code == "XX":
            return "Other"
        return f"{self.flag} {self.name}"


COUNTRY_NAMES: dict[str, str] = {
    "DE": "Germany",
    "NL": "Netherlands",
    "US": "United States",
    "RU": "Russia",
    "GB": "United Kingdom",
    "FI": "Finland",
    "SE": "Sweden",
    "FR": "France",
    "PL": "Poland",
    "TR": "Turkey",
    "SG": "Singapore",
    "JP": "Japan",
    "KZ": "Kazakhstan",
    "UA": "Ukraine",
    "CH": "Switzerland",
    "AT": "Austria",
    "ES": "Spain",
    "IT": "Italy",
    "CA": "Canada",
    "AU": "Australia",
    "IN": "India",
    "BR": "Brazil",
    "KR": "South Korea",
    "AE": "United Arab Emirates",
    "IL": "Israel",
    "NO": "Norway",
    "DK": "Denmark",
    "CZ": "Czech Republic",
    "RO": "Romania",
    "BG": "Bulgaria",
    "GE": "Georgia",
    "AM": "Armenia",
    "HK": "Hong Kong",
    "MD": "Moldova",
    "RS": "Serbia",
    "LV": "Latvia",
    "LT": "Lithuania",
    "EE": "Estonia",
    "IE": "Ireland",
    "PT": "Portugal",
    "GR": "Greece",
    "IS": "Iceland",
    "CY": "Cyprus",
    "HU": "Hungary",
    "SK": "Slovakia",
    "SI": "Slovenia",
    "HR": "Croatia",
    "MX": "Mexico",
    "AR": "Argentina",
    "CL": "Chile",
    "ZA": "South Africa",
    "TH": "Thailand",
    "VN": "Vietnam",
    "ID": "Indonesia",
    "MY": "Malaysia",
    "TW": "Taiwan",
    "BY": "Belarus",
    "UZ": "Uzbekistan",
    "AZ": "Azerbaijan",
    "BE": "Belgium",
    "CO": "Colombia",
    "PE": "Peru",
}

KEYWORD_TO_CODE: dict[str, str] = {
    # Germany
    "germany": "DE", "deutschland": "DE", "германия": "DE", "фрг": "DE",
    "frankfurt": "DE", "франкфурт": "DE", "berlin": "DE", "берлин": "DE",
    "munich": "DE", "мюнхен": "DE", "nuremberg": "DE", "нюрнберг": "DE",
    "dusseldorf": "DE", "дюссельдорф": "DE",
    # Netherlands
    "netherlands": "NL", "holland": "NL", "нидерланды": "NL", "голландия": "NL",
    "amsterdam": "NL", "амстердам": "NL", "rotterdam": "NL", "роттердам": "NL",
    # USA
    "united states": "US", "usa": "US", "сша": "US", "america": "US", "америка": "US",
    "new york": "US", "нью-йорк": "US", "los angeles": "US", "лос-анджелес": "US",
    "chicago": "US", "чикаго": "US", "miami": "US", "майами": "US",
    "dallas": "US", "даллас": "US", "seattle": "US", "сиэтл": "US",
    "silicon valley": "US", "virginia": "US", "вирджиния": "US", "california": "US", "калифорния": "US",
    # Russia
    "russia": "RU", "россия": "RU", "рф": "RU",
    "moscow": "RU", "москва": "RU", "spb": "RU", "спб": "RU", "питер": "RU",
    "saint petersburg": "RU", "санкт-петербург": "RU", "novosibirsk": "RU", "новосибирск": "RU",
    # UK
    "united kingdom": "GB", "great britain": "GB", "uk": "GB",
    "великобритания": "GB", "англия": "GB", "британ": "GB",
    "london": "GB", "лондон": "GB", "manchester": "GB", "манчестер": "GB",
    # Finland
    "finland": "FI", "финляндия": "FI", "helsinki": "FI", "хельсинки": "FI",
    # Sweden
    "sweden": "SE", "швеция": "SE", "stockholm": "SE", "стокгольм": "SE",
    # France
    "france": "FR", "франция": "FR", "paris": "FR", "париж": "FR", "marseille": "FR",
    # Poland
    "poland": "PL", "польша": "PL", "warsaw": "PL", "варшава": "PL",
    # Turkey
    "turkey": "TR", "türkiye": "TR", "турция": "TR", "istanbul": "TR", "стамбул": "TR",
    "ankara": "TR", "анкара": "TR", "izmir": "TR",
    # Singapore
    "singapore": "SG", "сингапур": "SG",
    # Japan
    "japan": "JP", "япония": "JP", "tokyo": "JP", "токио": "JP", "osaka": "JP", "осака": "JP",
    # Kazakhstan
    "kazakhstan": "KZ", "казахстан": "KZ", "almaty": "KZ", "алматы": "KZ", "astana": "KZ", "астана": "KZ",
    # Ukraine
    "ukraine": "UA", "украина": "UA", "kyiv": "UA", "kiev": "UA", "киев": "UA",
    # Switzerland
    "switzerland": "CH", "швейцария": "CH", "zurich": "CH", "цюрих": "CH", "geneva": "CH", "женева": "CH",
    # Austria
    "austria": "AT", "австрия": "AT", "vienna": "AT", "вена": "AT",
    # Spain
    "spain": "ES", "испания": "ES", "madrid": "ES", "мадрид": "ES", "barcelona": "ES", "барселона": "ES",
    # Italy
    "italy": "IT", "италия": "IT", "rome": "IT", "рим": "IT", "milan": "IT", "милан": "IT",
    # Canada
    "canada": "CA", "канада": "CA", "toronto": "CA", "торонто": "CA",
    "montreal": "CA", "монреаль": "CA", "vancouver": "CA", "ванкувер": "CA",
    # Australia
    "australia": "AU", "австралия": "AU", "sydney": "AU", "сидней": "AU",
    "melbourne": "AU", "мельбурн": "AU",
    # India
    "india": "IN", "индия": "IN", "mumbai": "IN", "мумбаи": "IN", "delhi": "IN", "дели": "IN",
    # Brazil
    "brazil": "BR", "бразилия": "BR", "sao paulo": "BR", "сан-паулу": "BR",
    # South Korea
    "korea": "KR", "корея": "KR", "seoul": "KR", "сеул": "KR",
    # UAE
    "uae": "AE", "оаэ": "AE", "dubai": "AE", "дубай": "AE",
    # Israel
    "israel": "IL", "израиль": "IL", "tel aviv": "IL", "тель-авив": "IL",
    # Norway
    "norway": "NO", "норвегия": "NO", "oslo": "NO", "осло": "NO",
    # Denmark
    "denmark": "DK", "дания": "DK", "copenhagen": "DK", "копенгаген": "DK",
    # Czech Republic
    "czech": "CZ", "чехия": "CZ", "prague": "CZ", "прага": "CZ",
    # Romania
    "romania": "RO", "румыния": "RO", "bucharest": "RO", "бухарест": "RO",
    # Bulgaria
    "bulgaria": "BG", "болгария": "BG", "sofia": "BG", "софия": "BG",
    # Georgia
    "georgia": "GE", "грузия": "GE", "tbilisi": "GE", "тбилиси": "GE",
    # Armenia
    "armenia": "AM", "армения": "AM", "yerevan": "AM", "ереван": "AM",
    # Hong Kong
    "hong kong": "HK", "гонконг": "HK",
    # Moldova
    "moldova": "MD", "молдова": "MD", "chisinau": "MD", "кишинев": "MD",
    # Serbia
    "serbia": "RS", "сербия": "RS", "belgrade": "RS", "белград": "RS",
    # Baltic states
    "latvia": "LV", "латвия": "LV", "riga": "LV", "рига": "LV",
    "lithuania": "LT", "литва": "LT", "vilnius": "LT", "вильнюс": "LT",
    "estonia": "EE", "эстония": "EE", "tallinn": "EE", "таллин": "EE",
    # Ireland
    "ireland": "IE", "ирландия": "IE", "dublin": "IE", "дублин": "IE",
    # Portugal
    "portugal": "PT", "португалия": "PT", "lisbon": "PT", "лиссабон": "PT",
    # Greece
    "greece": "GR", "греция": "GR", "athens": "GR", "афины": "GR",
    # Iceland
    "iceland": "IS", "исландия": "IS", "reykjavik": "IS", "рейкьявик": "IS",
    # Cyprus
    "cyprus": "CY", "кипр": "CY",
    # Taiwan
    "taiwan": "TW", "тайвань": "TW", "taipei": "TW",
}

CITY_SUBDOMAIN_TO_CODE: dict[str, str] = {
    "fra": "DE", "fra1": "DE", "fra2": "DE", "ber": "DE", "muc": "DE", "nue": "DE",
    "ams": "NL", "ams1": "NL", "ams2": "NL", "rtm": "NL",
    "lon": "GB", "man": "GB",
    "par": "FR", "mrs": "FR",
    "hel": "FI", "sto": "SE", "waw": "PL", "ist": "TR", "sin": "SG", "sgp": "SG",
    "tyo": "JP", "osa": "JP", "ala": "KZ", "tse": "KZ", "kbp": "UA", "zrh": "CH",
    "vie": "AT", "mad": "ES", "bcn": "ES", "mil": "IT", "rom": "IT", "yyz": "CA",
    "syd": "AU", "mel": "AU", "bom": "IN", "del": "IN", "gru": "BR", "icn": "KR",
    "dxb": "AE", "tlv": "IL", "osl": "NO", "cph": "DK", "prg": "CZ", "buh": "RO",
    "sof": "BG", "tbs": "GE", "evn": "AM", "hkg": "HK", "beg": "RS", "rix": "LV",
    "vno": "LT", "tll": "EE", "dub": "IE", "lis": "PT", "ath": "GR", "tpe": "TW",
    "nyc": "US", "lax": "US", "chi": "US", "mia": "US", "dal": "US", "sea": "US",
    "sfo": "US", "iad": "US", "atl": "US",
    "mow": "RU", "svo": "RU", "dme": "RU", "led": "RU", "ovb": "RU",
}


def iso_to_flag(code: str) -> str:
    code = code.upper().strip()
    if code == "XX":
        return "🌐"
    if len(code) == 2 and code.isalpha():
        return chr(ord(code[0]) + REGIONAL_INDICATOR_OFFSET) + chr(ord(code[1]) + REGIONAL_INDICATOR_OFFSET)
    return "🌐"


def extract_flag_from_text(text: str) -> tuple[str, str] | None:
    # Look for pair of regional indicator symbols
    for i in range(len(text) - 1):
        cp1 = ord(text[i])
        cp2 = ord(text[i + 1])
        if 0x1F1E6 <= cp1 <= 0x1F1FF and 0x1F1E6 <= cp2 <= 0x1F1FF:
            code = chr(cp1 - 0x1F1E6 + ord("A")) + chr(cp2 - 0x1F1E6 + ord("A"))
            flag = text[i : i + 2]
            return code, flag
    return None


@lru_cache(maxsize=2048)
def detect_location(name: str, server: str = "") -> LocationInfo:
    # 1. Check if name contains a flag emoji
    flag_match = extract_flag_from_text(name)
    if flag_match:
        code, flag = flag_match
        name_str = COUNTRY_NAMES.get(code, code)
        return LocationInfo(code=code, name=name_str, flag=flag)

    clean_name = name.lower()

    # 2. Check for explicit bracketed or bounded country codes, e.g. [DE], (NL), " DE ", "US -", "DE_01"
    for code, country_name in COUNTRY_NAMES.items():
        patterns = [
            rf"\[{code}\]",
            rf"\({code}\)",
            rf"(?:^|[\s_\-#|/]){code}(?:[\s_\-#|/0-9]|$)",
        ]
        for pat in patterns:
            if re.search(pat, name, re.IGNORECASE):
                return LocationInfo(code=code, name=country_name, flag=iso_to_flag(code))

    # 3. Check for keywords in profile name (sorted by length descending to match longer keywords first)
    for kw in sorted(KEYWORD_TO_CODE.keys(), key=len, reverse=True):
        if re.search(rf"\b{re.escape(kw)}\b", clean_name, re.IGNORECASE):
            code = KEYWORD_TO_CODE[kw]
            return LocationInfo(code=code, name=COUNTRY_NAMES.get(code, code), flag=iso_to_flag(code))

    # 4. Check server hostname/domain heuristics
    if server:
        clean_server = server.lower().strip()
        # Check TLD (e.g. server.de, proxy.nl, myvpn.fi)
        parts = clean_server.split(".")
        if len(parts) >= 2:
            tld = parts[-1].upper()
            if tld in COUNTRY_NAMES and tld not in {"CO", "IO", "AI", "TO", "CC", "WS", "ME", "TV"}:
                return LocationInfo(code=tld, name=COUNTRY_NAMES[tld], flag=iso_to_flag(tld))

        # Check subdomains or prefixes (e.g. de-1.example.com, fra.node.org, ams-vpn.net)
        subdomains = re.split(r"[.\-_]", clean_server)
        for sub in subdomains:
            sub_up = sub.upper()
            if sub_up in COUNTRY_NAMES and len(sub_up) == 2:
                return LocationInfo(code=sub_up, name=COUNTRY_NAMES[sub_up], flag=iso_to_flag(sub_up))
            if sub in CITY_SUBDOMAIN_TO_CODE:
                code = CITY_SUBDOMAIN_TO_CODE[sub]
                return LocationInfo(code=code, name=COUNTRY_NAMES.get(code, code), flag=iso_to_flag(code))

    return LocationInfo(code="XX", name="Other", flag="🌐")
