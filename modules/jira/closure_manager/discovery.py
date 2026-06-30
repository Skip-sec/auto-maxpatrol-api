import requests
import logging
from datetime import datetime
from modules.jira.config_jira import (
    PARENT_LINK_KEY, 
    STATUS_TO_VERIFY, 
    STATUS_WAITING_SUPPORT, 
    APP_ID_JIRA_SD
)

class JiraDiscovery:
    def __init__(self, jira_url, jira_headers, sd_url, sd_headers):
        self.jira_url = jira_url.rstrip('/')
        self.sd_url = sd_url.rstrip('/')
        self.jira_headers = jira_headers
        self.sd_headers = sd_headers

    def get_weekly_isp_tasks(self):
        """Получает список еженедельных задач (ISP-XXX), привязанных к главной (ISP-856)."""
        url = f"{self.jira_url}/rest/api/2/issue/{PARENT_LINK_KEY}"
        try:
            resp = requests.get(url, headers=self.jira_headers, verify=False, timeout=20)
            resp.raise_for_status()
            links = resp.json().get('fields', {}).get('issuelinks', [])
            return [l.get('inwardIssue', {}).get('key') for l in links 
                    if l.get('inwardIssue', {}).get('key', '').startswith('ISP-')]
        except Exception as e:
            logging.error(f"Discovery Error (ISP lookup): {e}")
            return []

    def get_sd_tasks_from_isp(self, isp_key):
        """Находит ключи задач Service Desk (SD-XXX) через Remote Links в еженедельной задаче."""
        url = f"{self.jira_url}/rest/api/2/issue/{isp_key}/remotelink"
        try:
            resp = requests.get(url, headers=self.jira_headers, verify=False, timeout=15)
            resp.raise_for_status()
            return [l.get('object', {}).get('title') for l in resp.json() 
                    if APP_ID_JIRA_SD in l.get('globalId', '') and l.get('object', {}).get('title', '').startswith('SD-')]
        except Exception as e:
            logging.error(f"Discovery Error (SD lookup for {isp_key}): {e}")
            return []

    def filter_ready_tasks(self, sd_tasks):
        """Фильтрует задачи, оставляя только те, что в статусе 'User Action'."""
        ready_info = {}
        for key in list(set(sd_tasks)):
            url = f"{self.sd_url}/rest/api/2/issue/{key}?fields=status,updated"
            try:
                resp = requests.get(url, headers=self.sd_headers, verify=False, timeout=15)
                resp.raise_for_status()
                fields = resp.json().get('fields', {})
                status_name = fields.get('status', {}).get('name', '')
                updated_str = fields.get('updated')
                
                if status_name.lower() == STATUS_TO_VERIFY.lower() and updated_str:
                    updated_dt = datetime.strptime(updated_str[:19], '%Y-%m-%dT%H:%M:%S')
                    ready_info[key] = updated_dt
            except Exception as e:
                logging.error(f"Status check error for {key}: {e}")
        return ready_info

    def filter_support_tasks(self, sd_tasks):
        """
        Находит задачи в статусе 'Waiting for support' для последующей проверки
        на предмет превышения лимита в 60 дней.
        """
        support_info = {}
        for key in list(set(sd_tasks)):
            url = f"{self.sd_url}/rest/api/2/issue/{key}?fields=status,updated"
            try:
                resp = requests.get(url, headers=self.sd_headers, verify=False, timeout=15)
                resp.raise_for_status()
                fields = resp.json().get('fields', {})
                status_name = fields.get('status', {}).get('name', '')
                updated_str = fields.get('updated')
                
                if status_name.lower() == STATUS_WAITING_SUPPORT.lower() and updated_str:
                    updated_dt = datetime.strptime(updated_str[:19], '%Y-%m-%dT%H:%M:%S')
                    support_info[key] = updated_dt
            except Exception as e:
                logging.error(f"Support status check error for {key}: {e}")
        return support_info

    def check_admin_warning(self, sd_key, admin_login):
        """
        Проверяет, является ли последний комментарий в задаче 
        предупреждением от администратора о закрытии.
        """
        # Запрашиваем только 1 последний комментарий, отсортированный по дате создания (новые сверху)
        url = f"{self.sd_url}/rest/api/2/issue/{sd_key}/comment?orderBy=-created&maxResults=1"
        warning_text = "Обращаем внимание, что в случае, если ответ от Вас не поступит в течение 7 рабочих дней, то обращение будет закрыто."
        
        try:
            resp = requests.get(url, headers=self.sd_headers, verify=False, timeout=10)
            resp.raise_for_status()
            comments = resp.json().get('comments', [])
            
            if not comments:
                return False
                
            last_comment = comments[0]
            # Получаем логин автора (name) или его отображаемое имя (displayName)
            author = last_comment.get('author', {}).get('name', '')
            body = last_comment.get('body', '')
            
            # Сравниваем автора и ищем вхождение текста предупреждения
            if author == admin_login and warning_text in body:
                return True
                
            return False
        except Exception as e:
            logging.error(f"Error checking comments for {sd_key}: {e}")
            return False

    def is_closed_without_ib_answer(self, sd_key, admin_login):
        """
        Проверяет, была ли задача принудительно закрыта системой без ответа ИБ.
        """
        # Запрашиваем данные по задаче, включая статус и комментарии
        url = f"{self.sd_url}/rest/api/2/issue/{sd_key}?fields=status,comment"
        try:
            resp = requests.get(url, headers=self.sd_headers, verify=False, timeout=10)
            if resp.status_code != 200:
                return False
                
            issue_data = resp.json()
            
            # Проверяем статус задачи (убеждаемся, что она закрыта)
            status_name = issue_data.get("fields", {}).get("status", {}).get("name", "")
            if status_name != "Closed":
                return False
                
            # Универсальное извлечение комментариев: проверяем оба возможных пути в JSON
            comments = []
            if "fields" in issue_data and "comment" in issue_data["fields"]:
                comments = issue_data["fields"]["comment"].get("comments", [])
            else:
                comments = issue_data.get("comments", [])

            if not comments:
                logging.info(f"    [CLOSED CHECK] В задаче {sd_key} не найдено комментариев.")
                return False

            admin_warning_found = False
            ib_answered_after_warning = False
            auto_close_triggered = False

            # Перебираем комментарии в хронологическом порядке
            for comment in comments:
                author = comment.get('author', {}).get('name', '')
                body = comment.get('body', '')

                # 1. Поиск предупреждения от ИБ (Администратора)
                if author == admin_login and "Обращаем внимание" in body:
                    admin_warning_found = True
                    ib_answered_after_warning = False  # Ищем ответ строго ПОСЛЕ
                    auto_close_triggered = False
                    continue

                if admin_warning_found:
                    body_lower = body.lower()
                    # 2. Поиск системного текста автоматического закрытия
                    if author == admin_login and ("completed automatically" in body_lower or "service regulations" in body_lower):
                        auto_close_triggered = True
                        continue

                    # 3. Любой живой комментарий не от Admin и не от бота расценивается как ответ ИБ
                    if author != admin_login:
                        ib_answered_after_warning = True

            # Выводим подробный статус разбора в лог, чтобы сразу увидеть причину
            logging.info(f"    [CLOSED CHECK FOR {sd_key}] Warning: {admin_warning_found}, AutoClose: {auto_close_triggered}, IB Answered: {ib_answered_after_warning}")

            if admin_warning_found and auto_close_triggered and not ib_answered_after_warning:
                return True

        except Exception as e:
            logging.error(f"Error executing advanced closed check for {sd_key}: {e}")
            
        return False
