import logging
import requests
from modules.jira.config_jira import (
    TAG_PROGRESS_60D, 
    TAG_PROGRESS_80D, 
    TAG_PROGRESS_90D, 
    TAGS_IB_COUNTDOWN
)

class ISPTagManager:
    def __init__(self, jira_url, jira_headers):
        self.jira_url = jira_url.rstrip('/')
        self.jira_headers = jira_headers
        # Собираем абсолютно все возможные теги автоматики в один массив для зачистки
        self.all_escalation_tags = [TAG_PROGRESS_60D, TAG_PROGRESS_80D, TAG_PROGRESS_90D] + TAGS_IB_COUNTDOWN

    def add_label_to_issue(self, issue_key, label_name):
        """Добавляет метку (label) в задачу Jira Nexign, сохраняя существующие."""
        url = f"{self.jira_url}/rest/api/2/issue/{issue_key}"
        payload = {
            "update": {
                "labels": [
                    {"add": label_name}
                ]
            }
        }
        try:
            response = requests.put(url, headers=self.jira_headers, json=payload, verify=False, timeout=10)
            if response.status_code == 204:
                logging.info(f"    [TAG MANAGER] Successfully added label '{label_name}' to {issue_key}")
                return True
            else:
                logging.error(f"    [TAG ERROR] Failed to add label to {issue_key}: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logging.error(f"    [TAG EXCEPTION] Error adding label to {issue_key}: {e}")
            return False

    def remove_label_from_issue(self, issue_key, label_name):
        """Удаляет указанную метку из задачи Jira Nexign, не трогая остальные."""
        url = f"{self.jira_url}/rest/api/2/issue/{issue_key}"
        payload = {
            "update": {
                "labels": [
                    {"remove": label_name}
                ]
            }
        }
        try:
            response = requests.put(url, headers=self.jira_headers, json=payload, verify=False, timeout=10)
            if response.status_code == 204:
                logging.info(f"    [TAG MANAGER] Successfully removed label '{label_name}' from {issue_key}")
                return True
            else:
                logging.debug(f"    [TAG MANAGER] Label '{label_name}' not found or could not be removed from {issue_key}")
                return False
        except Exception as e:
            logging.error(f"    [TAG EXCEPTION] Error removing label from {issue_key}: {e}")
            return False

    def clear_all_escalation_tags(self, issue_key):
        """Удаляет вообще все метки просрочки и отсчета ИБ с задачи, когда она вышла из эскалации."""
        for tag in self.all_escalation_tags:
            self.remove_label_from_issue(issue_key, tag)
