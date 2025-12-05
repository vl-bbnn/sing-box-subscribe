import json

import os
import re
from dotenv import load_dotenv
from fastapi import HTTPException
import requests
from urllib.parse import urlparse, unquote
from collections import defaultdict

from fastapi.responses import Response
import tool


def get_iso_from_flag(flag_str):
    """
    Converts a unicode flag emoji (composed of two regional indicator symbols)
    into an ISO 3166-1 alpha-2 country code (e.g., 🇺🇸 -> US).
    """
    try:
        # Regional Indicator Symbol 'A' is U+1F1E6 (127462). ASCII 'A' is 65.
        # The offset is 127462 - 65 = 127397.
        return "".join(chr(ord(c) - 127397) for c in flag_str)
    except ValueError:
        return None


def extract_country_code(remark):
    """
    Extracts country code from the VLESS URL remark (fragment).
    Prioritizes Flag Emojis, then looks for standard ISO strings.
    """
    if not remark:
        return "Unknown"

    # Decode URL-encoded characters (e.g., %20 -> space)
    remark = unquote(remark)

    # 1. Search for Flag Emojis (Regional Indicator Symbols U+1F1E6 to U+1F1FF)
    flag_match = re.search(r"[\U0001F1E6-\U0001F1FF]{2}", remark)
    if flag_match:
        iso_code = get_iso_from_flag(flag_match.group(0))
        if iso_code:
            return iso_code

    # 2. Fallback: Search for explicit text codes (e.g., "US", "DE", "NL")
    # surrounded by boundaries or common delimiters like "US-Server" or "_DE_"
    text_match = re.search(r"\b([A-Z]{2})\b", remark)
    if text_match:
        return text_match.group(1)

    return "Unknown"


def fetch_urls(url: str):
    try:
        print("Downloading configs from ${url}")
        response = requests.get(url)
        response.raise_for_status()

        # Dictionary to store results: Key = ISO Code, Value = List of URLs
        vpn_dict = defaultdict(list)

        lines = response.text.splitlines()
        count = 0

        for line in lines:
            line = line.strip()
            if line.startswith("vless://"):
                # Parse the URL to get the fragment (remark) after '#'
                parsed = urlparse(line)
                remark = parsed.fragment

                # Determine the country
                iso_code = extract_country_code(remark)

                # Group into dictionary
                vpn_dict[iso_code].append(line)
                count += 1

        print(f"Successfully parsed {count} VLESS links.")
        print("-" * 30)

        # Display summary of groupings
        for country, urls in sorted(vpn_dict.items()):
            print(f"[{country}]: {len(urls)} configs")

        # The 'vpn_dict' variable now holds your data structure
        return vpn_dict

    except requests.exceptions.RequestException as e:
        print(f"Error processing request: {e}")


def config(id):
    devices_data = tool.load_json("configs/devices.json")
    device_data = devices_data[id]

    if not device_data:
        return

    if not device_data["urls"]:
        return

    if not device_data["template"]:
        return

    try:
        load_dotenv()
        tool.init_parsers()
        tool.update_providers()
        config = tool.load_json("configs/" + device_data["template"])

        for label in ["WHITE_LISTS_MOBILE", "WHITE_LISTS_CABLE", "BLACK_VLESS_RUS"]:
            link = os.environ.get(label, "")
            if link:
                print(f"link: {link}")
                if link:
                    urls = fetch_urls(link)
                    device_data["urls"].update(urls)

        nodes = tool.process_subscribes(device_data["urls"])
        final_config = tool.combin_to_config(config, nodes)
        return Response(json.dumps(final_config, indent=4))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
