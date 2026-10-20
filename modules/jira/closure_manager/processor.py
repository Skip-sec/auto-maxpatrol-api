# -*- coding: utf-8 -*- 
import csv 
import logging 
from io import StringIO 
import requests 
import time 

# Импортируем конфигурационные ID переходов
from modules.jira.config_jira import ( 
    TRANSITION_ID_SUPPORT_TO_USER_ACTION, 
    TRANSITION_ID_USER_ACTION_TO_CLOSED 
) 

logger = logging.getLogger(__name__) 

class JiraProcessor: 
    def __init__(self, jira_url, jira_headers, sd_url, sd_headers): 
        self.jira_url = jira_url.rstrip('/') 
        self.sd_url = sd_url.rstrip('/') 
 
        # ОПТИМИЗАЦИЯ: Использование единых сессий для утилизации Keep-Alive коннектов
        self.jira_session = requests.Session() 
        self.jira_session.verify = False 
        self.jira_session.headers.update(jira_headers) 
 
        self.sd_session = requests.Session() 
        self.sd_session.verify = False 
        self.sd_session.headers.update(sd_headers) 

    def get_task_data(self, sd_key): 
        """Скачивает CSV из задачи и извлекает ID уязвимостей с автоматической очисткой памяти."""
        url = f"{self.sd_url}/rest/api/2/issue/{sd_key}?fields=attachment" 
        vuln_ids = set() 
 
        try: 
            resp = self.sd_session.get(url, timeout=15) 
            resp.raise_for_status() 
 
            attachments = resp.json().get('fields', {}).get('attachment', []) 
            for attach in attachments: 
                fname = attach.get('filename', '').lower() 
 
                # Ищем отчеты по маске имени
                if (fname.startswith('vuln_') or fname.startswith('vulnerabilities')) and fname.endswith('.csv'): 
                    file_resp = self.sd_session.get(attach['content'], timeout=20) 
                    file_resp.raise_for_status() 
 
                    # ИСПРАВЛЕНО: Безопасный контекстный менеджер StringIO для предотвращения утечек памяти
                    csv_content = file_resp.content.decode('utf-8-sig') 
                    with StringIO(csv_content) as string_io: 
                        reader = csv.DictReader(string_io, delimiter=';') 
 
                        # Поиск заголовков на русском языке
                        target_cols = [c for c in (reader.fieldnames or []) if c in ["ID (ОС)", "ID уязвимости (ПО)"]]
 
                        # Резервный поиск на случай, если файлы пришли из старых запусков
                        if not target_cols: 
                            target_cols = [c for c in (reader.fieldnames or []) if "vulners.id" in c.lower() or "nodevulners.id" in c.lower()] 
 
                        for row in reader: 
                            for col in target_cols: 
                                val = row.get(col) 
                                if val and val not in ["N/A", "-", ""]: 
                                    vuln_ids.add(val) 
 
            return list(vuln_ids) 
        except Exception as e: 
            logger.error(f"Processor: CSV extraction error for task {sd_key}: {e}") 
            return [] 

    def change_issue_status(self, issue_key, transition_id, comment=None): 
        """ 
        Безопасная смена статуса для дефолтных переходов Jira SD.
        Передает комментарий прямо ВНУТРИ перехода для прохождения экранов валидации обязательных полей.
        """ 
        url_transition = f"{self.sd_url}/rest/api/2/issue/{issue_key}/transitions" 
 
        # Строим тело запроса перехода
        payload_transition = { 
            "transition": { 
                "id": str(transition_id) 
            } 
        } 
 
        # Если передан комментарий, внедряем его прямо в тело перехода (для валидации экранов Jira) 
        if comment: 
            payload_transition["update"] = { 
                "comment": [ 
                    { 
                        "add": { 
                            "body": comment 
                        } 
                    } 
                ] 
            } 
 
        try: 
            resp_trans = self.sd_session.post(url_transition, json=payload_transition, timeout=15) 
 
            # Резервный адаптер под тип данных (если Jira требует строго integer ID) 
            if resp_trans.status_code == 400: 
                logger.warning(f" [JIRA ADAPT] String transition ID failed with 400. Retrying with integer ID for {issue_key}...") 
                try: 
                    payload_transition["transition"]["id"] = int(transition_id) 
                    resp_trans = self.sd_session.post(url_transition, json=payload_transition, timeout=15) 
                except ValueError: 
                    pass 

            resp_trans.raise_for_status() 
            logger.info(f"SUCCESS: Status changed for {issue_key} via transition {transition_id} with validation comment.") 
            return True 
 
        except requests.exceptions.HTTPError as http_err: 
            logger.error(f"Jira API error response for {issue_key}: {http_err} - Response text: {http_err.response.text}") 
        except Exception as e: 
            logger.error(f"Critical error on transition sequence for {issue_key}: {e}") 
 
            return False 

    def change_issue_status_with_reject(self, issue_key, transition_id, reject_comment): 
        """
        Безопасный сценарий частичного устранения (Reject).
        Сначала публикует детальный комментарий-инструкцию в тикет, 
        и только затем возвращает задачу в работу по ID 51.
        """
        url_comment = f"{self.sd_url}/rest/api/2/issue/{issue_key}/comment"
        url_transition = f"{self.sd_url}/rest/api/2/issue/{issue_key}/transitions"
        
        try:
            # Шаг 1: Публикуем большой текстовый комментарий с инструкциями
            if reject_comment:
                payload_comment = {"body": reject_comment}
                resp_comment = self.sd_session.post(url_comment, json=payload_comment, timeout=15)
                resp_comment.raise_for_status()
                logger.info(f" [REJECT FLOW] Step 1: Instruction comment added to {issue_key}")

            # Пауза 1 секунда для синхронизации внутренних индексов Jira
            time.sleep(1)

            # Шаг 2: Нажимаем кнопку "Return to work" (Передаем ID 51)
            payload_transition = { 
                "transition": { 
                    "id": str(transition_id)
                } 
            }
            resp_trans = self.sd_session.post(url_transition, json=payload_transition, timeout=15)
            
            # Адаптер типа данных на случай, если Jira потребует числовое ID
            if resp_trans.status_code == 400:
                try:
                    payload_transition["transition"]["id"] = int(transition_id)
                    resp_trans = self.sd_session.post(url_transition, json=payload_transition, timeout=15)
                except ValueError:
                    pass

            resp_trans.raise_for_status()
            logger.info(f"SUCCESS [REJECT FLOW]: {issue_key} successfully returned to work via transition {transition_id}")
            return True

        except requests.exceptions.HTTPError as http_err:
            logger.error(f"Jira Reject Flow HTTP Error for {issue_key}: {http_err} - Response: {http_err.response.text}")
        except Exception as e:
            logger.error(f"Critical error on reject sequence for {issue_key}: {e}")
            
        return False

    def process_biweekly_success_close(self, sd_key): 
        """Выполняет последовательный автоматический перевод задачи в статус Closed.""" 
        logger.info(f"Starting biweekly auto-close sequence for {sd_key}") 
 
        step1_comment = "Автоматическая проверка ИБ: Инициирован процесс верификации и закрытия задачи."
        step1_success = self.change_issue_status(sd_key, TRANSITION_ID_SUPPORT_TO_USER_ACTION, comment=step1_comment) 
 
        if not step1_success: 
            logger.error(f"Aborting close sequence for {sd_key}: Step 1 (To User Action) failed.") 
            return False 
 
        close_comment = ( 
            "Автоматическая проверка ИБ: Задача успешно закрыта, так как при пересканировании "
            "в системе MaxPatrol VM данные уязвимости были отмечены как устраненные."
        ) 
 
        return self.change_issue_status(sd_key, TRANSITION_ID_USER_ACTION_TO_CLOSED, comment=close_comment) 

    def add_isp_comment(self, isp_key, message): 
        """Добавляет технический комментарий в родительскую задачу ISP (Core).""" 
        url = f"{self.jira_url}/rest/api/2/issue/{isp_key}/comment" 
        try: 
            resp = self.jira_session.post(url, json={"body": message}, timeout=10) 
            if resp.status_code == 201: 
                logger.info(f"Alert successfully sent to core umbrella issue {isp_key}") 
        except Exception as e: 
            logger.error(f"Processor: Failed to alert parent task {isp_key}: {e}") 

    def generate_reject_message(self, fixed, total): 
        """Формирует текст сообщения при частичном устранении уязвимостей."""
        return ( 
            f"Автоматическая проверка: исправлено только {fixed} из {total}. Возвращаю задачу в работу.\n\n" 
            "Если вы уверены, что всё исправлено, проверьте, удалены ли из системы артефакты, "
            "в рамках которых была обнаружена уязвимость. Пример: обновили Microsoft Defender, "
            "применили к нему новые базы, но старые файлы/библиотеки остались в системе и детектируются сканером.\n\n" 
            "Если вы не понимаете причину — переведите задачу в статус User action, обязательно используя пункт "
            "'Нужна информация от пользователя'. Первый освободившийся инженер ИБ проведет анализ и свяжется с вами.\n\n" 
            "В случае, если уязвимость устраняется в рамках ITP или другого тикета, просим оставить задачу в статусе Pending."
        )
