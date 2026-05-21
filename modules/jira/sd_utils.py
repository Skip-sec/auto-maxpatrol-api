import requests
import logging
import os
from modules.jira.config_jira import APP_ID_JIRA_SD

def attach_file_to_sd(issue_key, file_path, sd_url, token):
    """Загружает файл в задачу Service Desk через API Jira v2."""
    url = f"{sd_url}/rest/api/2/issue/{issue_key}/attachments"
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Atlassian-Token": "no-check"
    }
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f, 'text/csv')}
            res = requests.post(url, headers=headers, files=files, verify=False, timeout=20)
            if res.status_code == 200:
                logging.info(f"File {os.path.basename(file_path)} attached to {issue_key}")
                return True
            else:
                logging.error(f"Failed to attach {os.path.basename(file_path)}: {res.status_code}")
                return False
    except Exception as e:
        logging.error(f"Attachment error for {file_path}: {e}")
        return False

def assign_issue(issue_key, assignee_login, sd_url, sd_headers):
    """Назначает исполнителя на задачу в Service Desk."""
    url = f"{sd_url}/rest/api/2/issue/{issue_key}/assignee"
    payload = {"name": assignee_login}
    try:
        res = requests.put(url, json=payload, headers=sd_headers, verify=False, timeout=10)
        if res.status_code == 204:
            logging.info(f"Assignee '{assignee_login}' set for {issue_key}")
            return True
        else:
            logging.error(f"Assignment failed for {issue_key}: {res.status_code}")
            return False
    except Exception as e:
        logging.error(f"Assignment error for {issue_key}: {e}")
        return False

def link_mirror_issues(parent_key, child_key, child_id, sd_url, jira_url, sd_headers, jira_headers):
    """Создает зеркальные удаленные связи между двумя инстансами Jira."""
    
    # 1. Ссылка из Service Desk на Основную задачу (ISP)
    url_sd = f"{sd_url}/rest/api/2/issue/{child_key}/remotelink"
    payload_sd = {
        "globalId": f"system={jira_url}&id={parent_key}",
        "relationship": "causes",
        "object": {
            "url": f"{jira_url}/browse/{parent_key}",
            "title": f"{parent_key}",
            "summary": "Основная задача по устранению уязвимостей",
            "icon": {"url16x16": f"{jira_url}/favicon.ico"}
        }
    }
    
    # 2. Ссылка из Jira ISP на задачу в Service Desk
    url_jira = f"{jira_url}/rest/api/2/issue/{parent_key}/remotelink"
    payload_jira = {
        "globalId": f"appId={APP_ID_JIRA_SD}&issueId={child_id}",
        "application": {
            "type": "com.atlassian.jira",
            "name": "Jira SD"
        },
        "relationship": "has child",
        "object": {
            "url": f"{sd_url}/browse/{child_key}",
            "title": f"{child_key}",
            "summary": "Персональная задача владельца",
            "icon": {"url16x16": f"{sd_url}/favicon.ico"}
        }
    }
    
    try:
        # Отправка в SD
        res_sd = requests.post(url_sd, json=payload_sd, headers=sd_headers, verify=False, timeout=10)
        # Отправка в Jira ISP
        res_jira = requests.post(url_jira, json=payload_jira, headers=jira_headers, verify=False, timeout=10)
        
        if res_sd.status_code in [200, 201] and res_jira.status_code in [200, 201]:
            logging.info(f"Mirror links created: {child_key} <-> {parent_key}")
            return True
        else:
            logging.error(f"Linking failed. SD: {res_sd.status_code}, Jira: {res_jira.status_code}")
            return False
    except Exception as e:
        logging.error(f"Critical error during linking {child_key} and {parent_key}: {e}")
        return False
