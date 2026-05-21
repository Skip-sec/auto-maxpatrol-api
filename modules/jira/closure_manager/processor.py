import csv
import io
from io import StringIO
import logging
import requests

class JiraProcessor:
    def __init__(self, jira_url, jira_headers, sd_url, sd_headers):
        self.jira_url = jira_url.rstrip('/')
        self.sd_url = sd_url.rstrip('/')
        self.jira_headers = jira_headers
        self.sd_headers = sd_headers

    def get_task_data(self, sd_key):
        """Скачивает CSV из задачи и извлекает ID уязвимостей."""
        url = f"{self.sd_url}/rest/api/2/issue/{sd_key}?fields=attachment"
        vuln_ids = set()
        try:
            resp = requests.get(url, headers=self.sd_headers, verify=False, timeout=15)
            resp.raise_for_status()
            
            attachments = resp.json().get('fields', {}).get('attachment', [])
            for attach in attachments:
                fname = attach.get('filename', '').lower()
                # Ищем отчеты по маске имени
                if (fname.startswith('vuln_') or fname.startswith('vulnerabilities')) and fname.endswith('.csv'):
                    file_resp = requests.get(attach['content'], headers=self.sd_headers, verify=False, timeout=20)
                    # Читаем CSV с учетом BOM (utf-8-sig)
                    reader = csv.DictReader(StringIO(file_resp.content.decode('utf-8-sig')), delimiter=';')
                    
                    # ИСПРАВЛЕНО: Теперь ищем заголовки на русском языке, так как csv_manager.py
                    # переименовывает технические теги в "ID (ОС)" и "ID уязвимости (ПО)"
                    target_cols = [c for c in (reader.fieldnames or []) 
                                   if c in ["ID (ОС)", "ID уязвимости (ПО)"]]
                    
                    # Резервный поиск на случай, если файлы пришли из старых запусков
                    if not target_cols:
                        target_cols = [c for c in (reader.fieldnames or []) 
                                       if "vulners.id" in c.lower() or "nodevulners.id" in c.lower()]
                    
                    for row in reader:
                        for col in target_cols:
                            val = row.get(col)
                            if val and val not in ["N/A", "-", ""]:
                                vuln_ids.add(val)
                                
            return list(vuln_ids)
        except Exception as e:
            logging.error(f"Processor: CSV error for {sd_key}: {e}")
            return []

    def change_issue_status(self, issue_key, transition_id, comment=None):
        """Смена статуса в Jira SD с предварительным добавлением комментария."""
        # 1. Добавляем комментарий отдельным запросом для надежности
        if comment:
            comment_url = f"{self.sd_url}/rest/api/2/issue/{issue_key}/comment"
            try:
                requests.post(comment_url, json={"body": comment}, headers=self.sd_headers, verify=False, timeout=10)
                logging.info(f"Comment successfully added to {issue_key}")
            except Exception as e:
                logging.error(f"Processor: Error adding comment to {issue_key}: {e}")

        # 2. Выполняем переход по Workflow
        url = f"{self.sd_url}/rest/api/2/issue/{issue_key}/transitions"
        payload = {"transition": {"id": transition_id}}
        try:
            resp = requests.post(url, json=payload, headers=self.sd_headers, verify=False, timeout=15)
            if resp.status_code == 204:
                logging.info(f"SUCCESS: {issue_key} moved with transition {transition_id}")
                return True
            else:
                logging.error(f"FAILED: {issue_key} transition error: {resp.text}")
        except Exception as e:
            logging.error(f"Processor: Critical error on transition {issue_key}: {e}")
        return False

    def add_isp_comment(self, isp_key, message):
        """Добавляет технический комментарий в родительскую задачу ISP (Core)."""
        url = f"{self.jira_url}/rest/api/2/issue/{isp_key}/comment"
        try:
            resp = requests.post(url, json={"body": message}, headers=self.jira_headers, verify=False, timeout=10)
            if resp.status_code == 201:
                logging.info(f"Alert successfully sent to {isp_key}")
        except Exception as e:
            logging.error(f"Processor: Failed to alert {isp_key}: {e}")

    def generate_reject_message(self, fixed, total):
        """Формирует текст сообщения при частичном устранении уязвимостей."""
        return (
            f"Автоматическая проверка: исправлено только {fixed} из {total}. Возвращаю задачу в работу.\n\n"
            "Если вы уверены, что всё исправлено, проверьте, удалены ли из системы артефакты, "
            "в рамках которых была обнаружена уязвимость. Пример: обновили Microsoft Defender, "
            "применили к нему новые базы, но старые файлы/библиотеки остались в системе и детектируются сканером.\n\n"
            "Если вы не понимаете причину — переведите задачу в статус User action. Обязательно используя пункт 'Нужна информация от пользователя'. "
            "Первый освободившийся инженер ИБ проведет анализ и свяжется с вами.\n\n"
            "В случае, если уязвимость устраняется в рамках ITP или другого тикета, просим оставить задачу в статусе Pending."
        )
