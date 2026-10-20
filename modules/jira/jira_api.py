# -*- coding: utf-8 -*-
import requests
import logging
import urllib3
from os import getenv
from dotenv import load_dotenv

# Загружаем переменные из .env
load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JIRA_URL = getenv("JIRA_URL", "https://***").rstrip('/')
BEARER_TOKEN = getenv("JIRA_TOKENsd")

ATTR_IDS = {
    "Status": int(getenv("JIRA_ATTR_STATUS", 238)),
    "Owner": int(getenv("JIRA_ATTR_OWNER", 2282)),
    "Responsible": int(getenv("JIRA_ATTR_RESPONSIBLE", 186)),
    "IT System": int(getenv("JIRA_ATTR_IT_SYSTEM", 2288))
}

# Инициализируем глобальную сессию для Jira (Keep-Alive)
# Это ускорит запросы к Jira Assets в 5-10 раз
jira_session = requests.Session()
jira_session.verify = False
jira_session.headers.update({
    "Authorization": f"Bearer {BEARER_TOKEN}",
    "X-Atlassian-Token": "no-check",
    "Accept": "application/json",
    "Content-Type": "application/json"
})

def get_jira_asset_info(full_host_input):
    if isinstance(full_host_input, dict):
        full_host_string = full_host_input.get("name") or full_host_input.get("value") or ""
    else:
        full_host_string = str(full_host_input) if full_host_input else ""

    if not full_host_string:
        return {k: "N/A" for k in ["cmdb-Jira-ID", "Owner", "Responsible", "IT System", "Status"]}

    # ИСПРАВЛЕНО: Безопасный пошаговый разбор (без цепочки .split().split())
    try:
        parts_dot = full_host_string.split('.')
        first_part_dot = parts_dot[0] if parts_dot else full_host_string
        parts_space = first_part_dot.split(' ')
        short_name = parts_space[0].strip()
        short_name_escaped = short_name.replace('"', '\\"')
    except Exception:
        short_name = full_host_string
        short_name_escaped = full_host_string.replace('"', '\\"')

    result = {
        "cmdb-Jira-ID": "NOT_FOUND",
        "Owner": "N/A",
        "Responsible": "N/A",
        "IT System": "N/A",
        "Status": "N/A"
    }

    if not BEARER_TOKEN:
        logging.error("JIRA_TOKENsd not found in .env!")
        return result

    search_url = f"{JIRA_URL}/rest/insight/1.0/iql/objects"
    queries = [
        f'objectType = 58 AND Label = "{short_name_escaped}"',
        f'objectType = 58 AND Label LIKE "{short_name_escaped}"',
        f'Label = "{short_name_escaped}"'
    ]

    entries = []

    try:
        for iql in queries:
            params = {"iql": iql, "resultsPerPage": 1}
            try:
                # Переписано на использование общего пула соединений jira_session
                response = jira_session.get(search_url, params=params, timeout=10)
                response.raise_for_status()

                found_entries = response.json().get('objectEntries', [])
                if found_entries:
                    entries = found_entries
                    logging.debug(f"Found object for '{short_name}' using IQL: {iql}")
                    break
            except requests.exceptions.RequestException as req_err:
                logging.warning(f"IQL query failed ({iql}) for {short_name}: {req_err}")
                continue

        if not entries:
            logging.debug(f"Host '{short_name}' not found in Jira Assets")
            return result

        obj_id = entries[0].get('id')
        result["cmdb-Jira-ID"] = obj_id
        attributes = entries[0].get('attributes', [])

        if not attributes:
            detail_url = f"{JIRA_URL}/rest/insight/1.0/object/{obj_id}"
            detail_resp = jira_session.get(detail_url, timeout=10)
            detail_resp.raise_for_status()
            attributes = detail_resp.json().get('attributes', [])

        for col_name, target_attr_id in ATTR_IDS.items():
            for attr in attributes:
                if attr.get('objectTypeAttributeId') == target_attr_id:
                    vals = attr.get('objectAttributeValues', [])
                    if vals:
                        v = vals[0]
                        if v.get('referencedObject'):
                            result[col_name] = v['referencedObject'].get('label', "N/A")
                        elif 'status' in v:
                            result[col_name] = v['status'].get('name', "N/A")
                        else:
                            result[col_name] = v.get('displayValue', "N/A")
        return result
    except Exception as e:
        logging.error(f"General Jira API Error for {short_name}: {e}")
        return result