import requests
import logging
import urllib3
from os import getenv
from dotenv import load_dotenv
from api_mp_vm.mp_vm_variables import * 

# Загружаем переменные из .env
load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

JIRA_URL = getenv("JIRA_URL", "https://sd.nexign.com").rstrip('/')
BEARER_TOKEN = getenv("JIRA_TOKENsd")

ATTR_IDS = {
    "Status": int(getenv("JIRA_ATTR_STATUS", 238)),
    "Owner": int(getenv("JIRA_ATTR_OWNER", 2282)),
    "Responsible": int(getenv("JIRA_ATTR_RESPONSIBLE", 186)),
    "IT System": int(getenv("JIRA_ATTR_IT_SYSTEM", 2288))
}

headers = {
    "Authorization": f"Bearer {BEARER_TOKEN}",
    "X-Atlassian-Token": "no-check",
    "Accept": "application/json",
    "Content-Type": "application/json"
}

def get_jira_asset_info(full_host_input):
    if isinstance(full_host_input, dict):
        full_host_string = full_host_input.get("name") or full_host_input.get("value") or ""
    else:
        full_host_string = str(full_host_input) if full_host_input else ""

    if not full_host_string:
        return {k: "N/A" for k in ["cmdb-Jira-ID", "Owner", "Responsible", "IT System", "Status"]}

    try:
        # Улучшенная очистка: берем только то, что до первой точки или пробела
        short_name = full_host_string.split('.')[0].split(' ')[0].strip()
    except Exception:
        short_name = full_host_string
    
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
    
    # ИЗМЕНЕНИЕ: Используем "=" вместо "LIKE" для точного поиска по Label
    # Это гарантирует, что srv-dwh-uat найдет именно этот сервер, а не базу с похожим именем
    queries = [
        f'objectType = 58 AND Label =ilike "{short_name}"', # Сначала только Virtual Server
        f'Label = "{short_name}"'                      # Если не нашли, ищем по всем типам, но точно по имени
    ]
    
    entries = []
    
    try:
        for iql in queries:
            params = {"iql": iql, "resultsPerPage": 1}
            response = requests.get(search_url, headers=headers, params=params, verify=False, timeout=10)
            response.raise_for_status()
            
            found_entries = response.json().get('objectEntries', [])
            if found_entries:
                entries = found_entries
                logging.debug(f"Found object for '{short_name}' using IQL: {iql}")
                break 
        
        if not entries:
            logging.debug(f"Host '{short_name}' not found in Jira Assets")
            return result
        
        # Берем данные найденного объекта
        obj_id = entries[0].get('id')
        result["cmdb-Jira-ID"] = obj_id
        
        # Чтобы не делать лишний запрос, попробуем взять атрибуты сразу из результатов поиска
        # В objectEntries обычно уже есть массив attributes
        attributes = entries[0].get('attributes', [])
        
        # Если вдруг в поиске атрибутов нет (зависит от версии Insight), делаем доп. запрос
        if not attributes:
            detail_url = f"{JIRA_URL}/rest/insight/1.0/object/{obj_id}"
            detail_resp = requests.get(detail_url, headers=headers, verify=False, timeout=10)
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
        logging.error(f"Jira API Error for {short_name}: {e}")
        return result
