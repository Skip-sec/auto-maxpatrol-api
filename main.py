# -*- coding: utf-8 -*-
from datetime import date, datetime
from time import time
import logging
import os
from os import mkdir, remove, stat, getenv, walk
from os.path import join, exists
from dotenv import load_dotenv

# Импорт главного модуля MP VM
from api_mp_vm.main_api_mp_vm import main_api_mp_vm
# Импорт модулей Jira
from modules.jira.main_task_creater import JiraTaskCreator
from modules.jira.issue_generator import VulnerabilityIssueManager
from modules.jira.closure_manager import VulnerabilityClosureManager

load_dotenv()

def del_old_files(dir_path):
    """Удаляет файлы старше 90 дней."""
    if not exists(dir_path):
        return
    logging.info(f"Start module del_old_files({dir_path})")
    three_months_ago = time() - (90 * 86400)
    for root, dirs, files in walk(dir_path):
        for file in files:
            file_path = join(root, file)
            try:
                if stat(file_path).st_mtime <= three_months_ago:
                    remove(file_path)
            except Exception as e:
                logging.error(f"Error deleting file {file_path}: {e}")

if __name__ == "__main__":
    if not exists("logs"):
        mkdir("logs")

    start_time = datetime.now()

    # Настройка логирования
    logging.basicConfig(
        level=logging.INFO,
        filename="logs/log_" + str(date.today()) + ".log",
        filemode="a",
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )

    # Дублируем логи в консоль для GitLab CI/CD
    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)

    logging.info("--- Start Global Script ---")

    # 1. ЕЖЕДНЕВНЫЙ БЛОК: Автопроверка и эскалация (Feedback Loop)
    # Работает быстро, делает только точечные запросы по конкретным ID в MaxPatrol
    logging.info("Starting Daily Feedback Loop (Task Verification & Escalation)...")
    try:
        j_headers = {
            "Authorization": f"Bearer {getenv('JIRA_TOKEN')}",
            "Content-Type": "application/json"
        }
        s_headers = {
            "Authorization": f"Bearer {getenv('JIRA_TOKENsd')}",
            "Content-Type": "application/json"
        }
        
        closure_manager = VulnerabilityClosureManager(
            getenv("JIRA_BASE_URL"), j_headers,
            getenv("JIRA_URL"), s_headers
        )
        closure_manager.run_workflow()
    except Exception as e:
        logging.error(f"Critical error during closure verification: {e}")

    # 2. ПОНЕДЕЛЬНИЧНЫЙ БЛОК: Сбор данных (ETL) и создание новых задач
    # Запускает тяжелые PDQL-запросы из intergrations/***/***
    if datetime.now().weekday() == 0:
        logging.info("Today is Monday. Starting Full ETL and Jira Task Creation...")
        
        if main_api_mp_vm():
            logging.info("API MP VM ETL: OK")
            try:
                jira_manager = JiraTaskCreator()
                parent_issue_key = jira_manager.create_weekly_vulnerability_task()

                if parent_issue_key:
                    logging.info(f"Weekly Jira task created successfully: {parent_issue_key}")
                    issue_manager = VulnerabilityIssueManager()
                    issue_manager.process_today_files(parent_issue_key)
                else:
                    logging.error("Failed to create main weekly Jira task. Personal tasks skipped.")
            except Exception as e:
                logging.error(f"Critical error during Jira task creation: {e}")
        else:
            logging.error("Monday ETL failed. New task creation aborted.")
    else:
        logging.info("Today is not Monday. Full ETL and new tasks creation skipped.")

    # 3. ОЧИСТКА (Выполняется ежедневно)
    del_old_files("logs/")
    del_old_files("files/")

    logging.info(f"End script. Total running time = {datetime.now() - start_time}")
