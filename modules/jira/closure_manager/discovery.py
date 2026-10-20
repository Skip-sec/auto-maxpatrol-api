# -*- coding: utf-8 -*-
import requests
import logging
from datetime import datetime
from modules.jira.config_jira import (
    PARENT_LINK_KEY,
    STATUS_TO_VERIFY,
    STATUS_WAITING_SUPPORT,
    APP_ID_JIRA_SD
)

logger = logging.getLogger(__name__)

class JiraDiscovery:
    def __init__(self, jira_url, jira_headers, sd_url, sd_headers):
        self.jira_url = jira_url.rstrip('/')
        self.sd_url = sd_url.rstrip('/')
        
        # Настраиваем переиспользование сессий для ускорения Remote Links и комментов
        self.jira_session = requests.Session()
        self.jira_session.verify = False
        self.jira_session.headers.update(jira_headers)
        
        self.sd_session = requests.Session()
        self.sd_session.verify = False
        self.sd_session.headers.update(sd_headers)

    def get_weekly_isp_tasks(self):
        """Получает список еженедельных задач (ISP-XXX), привязанных к главной (ISP-856)."""
        url = f"{self.jira_url}/rest/api/2/issue/{PARENT_LINK_KEY}"
        try:
            resp = self.jira_session.get(url, timeout=20)
            resp.raise_for_status()
            links = resp.json().get('fields', {}).get('issuelinks', [])
            return [l.get('inwardIssue', {}).get('key') for l in links 
                    if l.get('inwardIssue', {}).get('key', '').startswith('ISP-')]
        except Exception as e:
            logger.error(f"Discovery Error (ISP lookup): {e}")
            return []

    def get_sd_tasks_from_isp(self, isp_key):
        """Находит ключи задач Service Desk (SD-XXX) через Remote Links."""
        url = f"{self.jira_url}/rest/api/2/issue/{isp_key}/remotelink"
        try:
            resp = self.jira_session.get(url, timeout=15)
            resp.raise_for_status()
            return [l.get('object', {}).get('title') for l in resp.json() 
                    if APP_ID_JIRA_SD in l.get('globalId', '') and 
                    l.get('object', {}).get('title', '').startswith('SD-')]
        except Exception as e:
            logger.error(f"Discovery Error (SD lookup for {isp_key}): {e}")
            return []

    def _fetch_tasks_batch_via_jql(self, sd_tasks: list, target_statuses: list) -> list:
        """
        ВНУТРЕННИЙ МЕТОД ОПТИМИЗАЦИИ:
        Выполняет ОДИН агрегированный JQL-запрос для пакета задач вместо сотен циклов.
        """
        if not sd_tasks:
            return []
            
        unique_keys = list(set(sd_tasks))
        # Формируем JQL: key IN ("SD-1", "SD-2") AND status IN ("User action", "Pending")
        keys_str = ", ".join(f'"{k}"' for k in unique_keys)
        statuses_str = ", ".join(f'"{s}"' for s in target_statuses)
        jql = f"key IN ({keys_str}) AND status IN ({statuses_str})"
        
        search_url = f"{self.sd_url}/rest/api/2/search"
        payload = {
            "jql": jql,
            "maxResults": len(unique_keys),
            "fields": ["status", "updated"]
        }
        
        try:
            # Отправляем POST-запрос в поисковое API Jira
            resp = self.sd_session.post(search_url, json=payload, timeout=30)
            resp.raise_for_status()
            return resp.json().get("issues", [])
        except Exception as e:
            logger.error(f"Failed to execute batch JQL discovery search: {e}")
            return []

    def filter_ready_tasks(self, sd_tasks):
        """Оптимизированный поиск задач в статусе 'User Action' через 1 JQL-запрос."""
        ready_info = {}
        issues = self._fetch_tasks_batch_via_jql(sd_tasks, [STATUS_TO_VERIFY])
        
        for issue in issues:
            key = issue.get("key")
            updated_str = issue.get("fields", {}).get("updated")
            if updated_str and key:
                ready_info[key] = datetime.strptime(updated_str[:19], '%Y-%m-%dT%H:%M:%S')
        return ready_info

    def filter_support_tasks(self, sd_tasks):
        """Оптимизированный поиск задач в статусе 'Waiting for support' через 1 JQL-запрос."""
        support_info = {}
        issues = self._fetch_tasks_batch_via_jql(sd_tasks, [STATUS_WAITING_SUPPORT])
        
        for issue in issues:
            key = issue.get("key")
            updated_str = issue.get("fields", {}).get("updated")
            if updated_str and key:
                support_info[key] = datetime.strptime(updated_str[:19], '%Y-%m-%dT%H:%M:%S')
        return support_info

    def get_biweekly_support_tasks(self, sd_tasks):
        """Оптимизированный воскресный сбор задач в статусах Support или Pending через 1 JQL-запрос."""
        issues = self._fetch_tasks_batch_via_jql(sd_tasks, [STATUS_WAITING_SUPPORT, "Pending"])
        return [issue.get("key") for issue in issues if issue.get("key")]

    def check_admin_warning(self, sd_key, admin_login):
        """Проверяет, является ли последний комментарий в задаче предупреждением от администратора."""
        url = f"{self.sd_url}/rest/api/2/issue/{sd_key}/comment?orderBy=-created&maxResults=1"
        warning_text = "Обращаем внимание, что в случае, если ответ от Вас не поступит в течение 7 рабочих дней, то обращение будет закрыто."
        try:
            resp = self.sd_session.get(url, timeout=10)
            resp.raise_for_status()
            comments = resp.json().get('comments', [])
            if not comments:
                return False
            last_comment = comments[0]
            author = last_comment.get('author', {}).get('name', '')
            body = last_comment.get('body', '')
            return author == admin_login and warning_text in body
        except Exception as e:
            logger.error(f"Error checking comments for {sd_key}: {e}")
            return False

    def is_closed_without_ib_answer(self, sd_key, admin_login):
        """Проверяет, была ли задача принудительно закрыта системой без ответа ИБ."""
        url = f"{self.sd_url}/rest/api/2/issue/{sd_key}?fields=status,comment"
        try:
            resp = self.sd_session.get(url, timeout=10)
            if resp.status_code != 200:
                return False
            issue_data = resp.json()
            status_name = issue_data.get("fields", {}).get("status", {}).get("name", "")
            if status_name != "Closed":
                return False
                
            comments = issue_data.get("fields", {}).get("comment", {}).get("comments", [])
            if not comments:
                return False
                
            admin_warning_found = False
            ib_answered_after_warning = False
            auto_close_triggered = False
            
            for comment in comments:
                author = comment.get('author', {}).get('name', '')
                body = comment.get('body', '')
                if author == admin_login and "Обращаем внимание" in body:
                    admin_warning_found = True
                    ib_answered_after_warning = False
                    auto_close_triggered = False
                    continue
                if admin_warning_found:
                    body_lower = body.lower()
                    if author == admin_login and ("completed automatically" in body_lower or "service regulations" in body_lower):
                        auto_close_triggered = True
                        continue
                    if author != admin_login:
                        ib_answered_after_warning = True
                        
            return admin_warning_found and auto_close_triggered and not ib_answered_after_warning
        except Exception as e:
            logger.error(f"Error executing advanced closed check for {sd_key}: {e}")
            return False