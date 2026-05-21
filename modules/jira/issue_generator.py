from datetime import date, timedelta
import json
import logging
import os
from os import getenv
import time
from dotenv import load_dotenv
import requests

# Импорт конфигурационных параметров
from modules.jira.config_jira import FIELD_MAP, SERVICE_DESK_ID, REQUEST_TYPE_ID
from modules.jira.csv_manager import save_vulnerability_csv
from modules.jira.sd_utils import attach_file_to_sd, link_mirror_issues, assign_issue

load_dotenv()

# --- КОНФИГУРАЦИЯ ---
SD_URL = getenv("JIRA_URL", "https://sd.nexign.com").rstrip('/')
SD_TOKEN = getenv("JIRA_TOKENsd")
JIRA_URL = getenv("JIRA_BASE_URL", "https://jira.nexign.com").rstrip('/')
JIRA_TOKEN = getenv("JIRA_TOKEN")
VULN_CONTACTS = getenv("VULN_CONTACTS", "Security Team")
JSON_DIR = "files/jira-pdql/JSONFiles/"

SD_HEADERS = {"Authorization": f"Bearer {SD_TOKEN}", "Content-Type": "application/json", "X-Atlassian-Token": "no-check"}
JIRA_HEADERS = {"Authorization": f"Bearer {JIRA_TOKEN}", "Content-Type": "application/json", "X-Atlassian-Token": "no-check"}

class VulnerabilityIssueManager:
    def __init__(self):
        self.sd_api_url = f"{SD_URL}/rest/servicedeskapi/request"
        self.service_desk_id = SERVICE_DESK_ID
        self.request_type_id = REQUEST_TYPE_ID

    def get_last_week_range(self):
        today = date.today()
        last_mon = (today - timedelta(days=today.weekday() + 7)).strftime("%d.%m.%y")
        last_sun = (today - timedelta(days=today.weekday() + 1)).strftime("%d.%m.%y")
        return last_mon, last_sun

    def process_today_files(self, parent_issue_key):
        today_str = str(date.today())
        all_data = []
        
        if not os.path.exists(JSON_DIR):
            logging.error(f"Directory {JSON_DIR} not found")
            return

        # 1. Сбор данных из JSON файлов
        for f_name in os.listdir(JSON_DIR):
            if today_str in f_name and f_name.endswith(".json"):
                with open(os.path.join(JSON_DIR, f_name), "r", encoding="utf-8") as f:
                    all_data.extend(json.load(f))

        # 2. Группировка по владельцам (Owner)
        grouped = {}
        for rec in all_data:
            owner = rec.get("Owner")
            if rec.get("Status") == "Active" and owner not in [None, "N/A", "-", "NOT_FOUND"]:
                grouped.setdefault(owner, []).append(rec)

        mon, sun = self.get_last_week_range()

        # 3. Цикл создания Service Desk задач для каждого владельца
        for owner, records in grouped.items():
            # Проверяем как стандартные ключи, так и точечные новые ключи из вашего select
            oc_data = [r for r in records if "OsName" in r or "Host.@NodeVulners" in r or "host.@NodeVulners.CVEs" in r]
            po_data = [r for r in records if "SoftwareName" in r or "Vulners" in r]

            # --- СБОР ДАННЫХ ДЛЯ ТАБЛИЦЫ ---
            # Структура: { 'хост': { 'vulns': {set_vulns}, 'it_system': 'Имя системы' } }
            host_table_map = {}
            for r in records:
                # Получаем имя или IP хоста
                host_val = r.get("@Host") or r.get("host.fqdn") or r.get("fqdn") or "Unknown Host"
                it_system_val = r.get("IT System") or "N/A"
                
                if host_val not in host_table_map:
                    host_table_map[host_val] = {
                        "vulns": set(),
                        "it_system": it_system_val
                    }
                
                # --- ЛОГИКА СОВМЕСТИМОСТИ №1: Сбор данных по обычной схеме linux ---
                oc_vuln = r.get("Host.@NodeVulners")
                po_vuln = r.get("Vulners")
                
                if oc_vuln and oc_vuln != "N/A":
                    host_table_map[host_val]["vulns"].add(str(oc_vuln))
                if po_vuln and po_vuln != "N/A":
                    host_table_map[host_val]["vulns"].add(str(po_vuln))

                # --- ЛОГИКА СОВМЕСТИМОСТИ №2: Сбор данных по win схеме ---
                cve_val = r.get("host.@NodeVulners.CVEs")
                patch_val = r.get("host.@nodevulners.Patch")
                
                if cve_val and cve_val != "N/A":
                    # Если у уязвимости есть патч, склеиваем их в одну красивую запись
                    if patch_val and patch_val != "N/A":
                        vuln_entry = f"{cve_val} ({patch_val})"
                    else:
                        vuln_entry = str(cve_val)
                    
                    host_table_map[host_val]["vulns"].add(vuln_entry)

            # --- ОТРИСОВКА WIKI-ТАБЛИЦЫ JIRA (3 колонки) ---
            table_markup = "||Хост||ИТ Система||Уязвимость ОС / ПО||\n"
            
            if host_table_map:
                for host, info in host_table_map.items():
                    # Объединяем названия найденных уязвимостей через тег переноса строки Jira \\
                    vulns = info["vulns"]
                    vuln_string = " \\\\ ".join(sorted(vulns)) if vulns else "См. вложенные файлы"
                    it_system = info["it_system"]
                    
                    table_markup += f"| {host} | {it_system} | {vuln_string} |\n"
            else:
                table_markup += "| Нет данных | N/A | См. вложенные файлы |\n"

            # Итоговое текстовое описание для Jira Service Desk
            desc = (f"Добрый день!\n\n"
                    f"Обнаружены уязвимости за период {mon} - {sun}.\n"
                    f"Объектов: {len(records)} (ОС: {len(oc_data)}, ПО: {len(po_data)}).\n\n"
                    f"{table_markup}\n"
                    f"Детали во вложениях. Контакты: {VULN_CONTACTS}.")

            # Создаем временные файлы отчетов CSV
            files = []
            f_os = save_vulnerability_csv(oc_data, "VULN_OS", owner, today_str)
            f_po = save_vulnerability_csv(po_data, "VULN_SOFT", owner, today_str)
            if f_os: files.append(f_os)
            if f_po: files.append(f_po)

            payload = {
                "requestFieldValues": {
                    "summary": f"Устранение уязвимостей: {owner} за {mon}-{sun}",
                    "description": desc
                },
                "requestTypeId": self.request_type_id,
                "serviceDeskId": self.service_desk_id
            }

            try:
                logging.info(f"Creating task for {owner}...")
                resp = requests.post(self.sd_api_url, json=payload, headers=SD_HEADERS, verify=False, timeout=30)
                
                if resp.status_code == 201:
                    res = resp.json()
                    new_key, new_id = res.get("issueKey"), res.get("issueId")
                    logging.info(f"SUCCESS: {new_key}")

                    # Отправка вложений в SD
                    for f_path in files:
                        attach_file_to_sd(new_key, f_path, SD_URL, SD_TOKEN)
                    
                    # Назначение задачи на группу
                    assign_issue(new_key, "ITD_Service_Group", SD_URL, SD_HEADERS)
                    
                    # Линкование с родительской "зонтичной" задачей
                    if parent_issue_key:
                        link_mirror_issues(parent_issue_key, new_key, new_id, 
                                           SD_URL, JIRA_URL, SD_HEADERS, JIRA_HEADERS)
                        
                    time.sleep(1)
                else:
                    logging.error(f"SD Error: {resp.text}")
            except Exception as e:
                logging.error(f"Process error for {owner}: {e}")
            finally:
                for f in files:
                    if os.path.exists(f): os.remove(f)
