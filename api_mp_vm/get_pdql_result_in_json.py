from json import dump
from os import makedirs
from os.path import exists
from datetime import date
import logging
import requests

from api_mp_vm.get_pdql_token import get_pdql_token
from api_mp_vm.mp_vm_variables import MPVM_HTTPS_VERIFY
from modules.jira.jira_api import get_jira_asset_info

def get_pdql_result_in_json(
    mpvm_base_url, headers, pdql, integration, pdql_query_name, pqql_full_file_name
):
    logging.info("Start module get_pdql_result_in_json()")

    pdql_token = get_pdql_token(mpvm_base_url, headers, pdql)
    if pdql_token is None:
        logging.error(f"ERROR getting the PDQL token from the request: {pdql}")
        return None

    # --- СБОР ДАННЫХ ИЗ MAXPATROL ---
    stop = False
    pdql_data = list()
    offset = 0
    limit = 2000 
    
    while not stop:
        params = {
            "limit": limit,
            "offset": str(offset),
            "pdqlToken": pdql_token,
        }

        try:
            # ТАЙМАУТ 180 СЕКУНД для стабильности на тяжелых запросах
            response = requests.get(
                f"{mpvm_base_url}:443/api/assets_temporal_readmodel/v1/assets_grid/data",
                params=params,
                headers=headers,
                verify=MPVM_HTTPS_VERIFY,
                timeout=180
            )
            
            if response.status_code == 200:
                temp_records = response.json().get("records", [])
                
                # ИСПРАВЛЕНИЕ: Безопасный выход из цикла, если записей больше нет
                if not temp_records:
                    break
                    
                pdql_data += temp_records
                logging.debug(f"{len(pdql_data)} received objects from MP VM")
                
                if len(temp_records) < limit:
                    stop = True
                offset += limit
            else:
                logging.error(f"Error fetching data from MP VM: Status {response.status_code}")
                break
        except Exception as e:
            logging.error(f"Request failed during data fetching: {e}")
            break

    if not pdql_data:
        logging.error(f"No data received for PDQL query: {pqql_full_file_name}")
        return None

    # --- БЛОК ОЧИСТКИ СЛОВАРЕЙ И ОБОГАЩЕНИЯ JIRA ---
    logging.info(f"Cleaning and enriching {len(pdql_data)} records...")
    
    # Кэш для Jira, чтобы не запрашивать один и тот же хост дважды за один запуск
    jira_cache = {}

    for record in pdql_data:
        # 1. Очистка @Host (извлекаем имя из вложенного словаря MPVM)
        host_val = record.get("@Host")
        if isinstance(host_val, dict):
            record["@Host"] = host_val.get("name", "")
        
        # 2. Очистка Vulners (извлекаем название уязвимости ПО)
        vuln_val = record.get("Vulners")
        if isinstance(vuln_val, dict):
            record["Vulners"] = vuln_val.get("name", "")

        # 3. Очистка Host.@NodeVulners (извлекаем название уязвимости ОС)
        os_vuln_field = "Host.@NodeVulners"
        os_vuln_val = record.get(os_vuln_field)
        if isinstance(os_vuln_val, dict):
            record[os_vuln_field] = os_vuln_val.get("name", "")

        # 4. Очистка Статуса ПО (Host.Softs.@Vulners.Status)
        soft_status_field = "Host.Softs.@Vulners.Status"
        soft_status_val = record.get(soft_status_field)
        if isinstance(soft_status_val, dict):
            record[soft_status_field] = soft_status_val.get("value", "")

        # 5. Очистка Статуса ОС (Host.@NodeVulners.Status)
        os_status_field = "Host.@NodeVulners.Status"
        os_status_val = record.get(os_status_field)
        if isinstance(os_status_val, dict):
            record[os_status_field] = os_status_val.get("value", "")

        # 6. ОБОГАЩЕНИЕ ИЗ JIRA (Asset Management)
        host_name_for_jira = record.get("@Host", "")
        if host_name_for_jira:
            # Если хоста нет в кэше — запрашиваем Jira Assets API
            if host_name_for_jira not in jira_cache:
                jira_cache[host_name_for_jira] = get_jira_asset_info(host_name_for_jira)
            
            # Обновляем текущую запись данными из кэша (Owner, IT System и т.д.)
            record.update(jira_cache[host_name_for_jira])
        else:
            record.update({
                "cmdb-Jira-ID": "N/A", "Owner": "-", "Responsible": "-", 
                "IT System": "-", "Status": "-"
            })
    
    logging.info("Cleaning and Enrichment completed")

    # --- СОХРАНЕНИЕ ---
    # Гарантируем корректный путь, добавляя слеш если его нет в integration
    clean_int_path = integration.rstrip('/') + '/'
    data_path = f"files/{clean_int_path}JSONFiles/"
    
    if not exists(data_path):
        makedirs(data_path)

    JSONfile_name = f"{data_path}{pdql_query_name}_{date.today()}.json"
    
    try:
        with open(JSONfile_name, "w", encoding="utf-8") as jsonfile:
            dump(pdql_data, jsonfile, ensure_ascii=False, indent=4)
        logging.info(f"Success write data in {JSONfile_name}")
    except Exception as e:
        logging.error(f"Failed to write JSON file: {e}")
        
    return pdql_data
