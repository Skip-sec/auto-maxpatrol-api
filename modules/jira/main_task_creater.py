import requests
import os
import logging
import urllib3
from datetime import datetime, timedelta
from dotenv import load_dotenv

# ИМПОРТ ИЗ ТВОЕГО НОВОГО КОНФИГА
from modules.jira.config_jira import PARENT_LINK_KEY 

load_dotenv()
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class JiraTaskCreator:
    def __init__(self):
        base_domain = os.getenv("JIRA_BASE_URL", "https://jira.nexign.com").rstrip('/')
        self.issue_url = f"{base_domain}/rest/api/2/issue"
        self.token = os.getenv("JIRA_TOKEN")
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "X-Atlassian-Token": "no-check"
        }
        self.xlsx_dir = "files/jira-pdql/XLSXFiles"

    def get_last_week_range(self):
        today = datetime.now()
        current_monday = today - timedelta(days=today.weekday())
        last_monday = current_monday - timedelta(days=7)
        last_sunday = current_monday - timedelta(days=1)
        return last_monday.strftime("%d.%m.%y"), last_sunday.strftime("%d.%m.%y")

    def attach_files_to_issue(self, issue_key):
        if not os.path.exists(self.xlsx_dir):
            logging.error(f"Директория {self.xlsx_dir} не найдена")
            return

        today_str = datetime.now().strftime("%Y-%m-%d")
        files_to_upload = [
            os.path.join(self.xlsx_dir, f) for f in os.listdir(self.xlsx_dir)
            if f.endswith('.xlsx') and 
            datetime.fromtimestamp(os.path.getmtime(os.path.join(self.xlsx_dir, f))).strftime("%Y-%m-%d") == today_str
        ]

        if not files_to_upload:
            logging.warning("Файлы для загрузки за сегодня не найдены.")
            return

        attach_url = f"{self.issue_url}/{issue_key}/attachments"
        for file_path in files_to_upload:
            logging.info(f"Uploading attachment: {os.path.basename(file_path)}")
            try:
                with open(file_path, 'rb') as f:
                    files = {'file': (os.path.basename(file_path), f, 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')}
                    response = requests.post(attach_url, headers=self.headers, files=files, verify=False, timeout=30)
                    if response.status_code == 200:
                        logging.info(f"Attached {os.path.basename(file_path)} to {issue_key}")
            except Exception as e:
                logging.error(f"Exception during upload {file_path}: {e}")

    def create_weekly_vulnerability_task(self):
        date_start, date_end = self.get_last_week_range()
        summary_text = f"Устранение уязвимостей найденные за {date_start} - {date_end}"
        
        # ИСПОЛЬЗУЕМ PARENT_LINK_KEY ВЕЗДЕ
        payload = {
            "fields": {
                "project": { "key": "ISP" },
                "issuetype": { "name": "Task" }, 
                "summary": summary_text,
                "priority": { "name": "Medium" },
                # Обновляем кастомное поле значением из конфига
                "customfield_10201": PARENT_LINK_KEY 
            },
            "update": {
                "issuelinks": [
                    {
                        "add": {
                            "type": { "name": "Relate" },
                            "outwardIssue": { "key": PARENT_LINK_KEY }
                        }
                    }
                ]
            }
        }

        headers = self.headers.copy()
        headers.update({"Content-Type": "application/json", "Accept": "application/json"})

        try:
            logging.info(f"Creating main task in Jira. Parent link: {PARENT_LINK_KEY}")
            response = requests.post(self.issue_url, json=payload, headers=headers, verify=False, timeout=20)
            
            if response.status_code == 201:
                issue_key = response.json().get('key')
                logging.info(f"SUCCESS: Main Issue {issue_key} created.")
                self.attach_files_to_issue(issue_key)
                return issue_key
            else:
                logging.error(f"Jira Error {response.status_code}: {response.text}")
                return None
        except Exception as e:
            logging.error(f"Critical error in main task creation: {e}")
            return None
