import logging
from datetime import datetime
from modules.jira.config_jira import (
    MAX_WAIT_DAYS, 
    MAX_SUPPORT_WAIT_DAYS,
    TRANSITION_ID_CLOSE, 
    TRANSITION_ID_PENDING
)

from .discovery import JiraDiscovery
from .validator import MPVMValidator
from .processor import JiraProcessor

class VulnerabilityClosureManager:
    def __init__(self, jira_url, jira_headers, sd_url, sd_headers):
        self.discovery = JiraDiscovery(jira_url, jira_headers, sd_url, sd_headers)
        self.validator = MPVMValidator()
        self.processor = JiraProcessor(jira_url, jira_headers, sd_url, sd_headers)

    def run_workflow(self):
        logging.info("--- Starting Refactored Verification Workflow (v3.5 - Verbose Debug) ---")
        
        isp_list = self.discovery.get_weekly_isp_tasks()
        logging.info(f"Step 1: Found {len(isp_list)} weekly ISP umbrella tasks.")
        
        admin_login = "Admin" # Логин администратора для проверки предупреждений
        
        # Словари для накопления отчетов по каждой ISP
        stuck_reports = {}      # User Action > 14 дней
        escalation_reports = {} # Waiting for support > 60 дней
        action_reports = {}     # Успешные действия (Close/Reject) за сегодня
        admin_alerts = {}       # Предупреждения от Admin

        for isp in isp_list:
            sd_keys = self.discovery.get_sd_tasks_from_isp(isp)
            logging.info(f"  > ISP {isp}: Found {len(sd_keys)} linked SD tickets.")
            
            if not sd_keys:
                continue

            if isp not in action_reports:
                action_reports[isp] = []

            # 1. ПРОВЕРКА ПРЕДУПРЕЖДЕНИЙ ОТ ADMIN
            keys_to_skip = set()
            for key in sd_keys:
                if self.discovery.check_admin_warning(key, admin_login):
                    logging.warning(f"    [SKIP] {key}: Admin warning found. Skipping vulnerability check.")
                    if isp not in admin_alerts: admin_alerts[isp] = []
                    admin_alerts[isp].append(f"* {key} (Требуется ответ ИБ, проверка MPVM пропущена)")
                    keys_to_skip.add(key)

            # Фильтруем задачи, исключая алерты
            tasks_for_verification = [k for k in sd_keys if k not in keys_to_skip]

            # 2. ОБРАБОТКА СТАТУСА "USER ACTION" (FEEDBACK LOOP)
            ready_tasks_info = self.discovery.filter_ready_tasks(tasks_for_verification)
            logging.info(f"  > ISP {isp}: {len(ready_tasks_info)} tickets in 'User Action' status.")

            if ready_tasks_info:
                current_isp_ids = set()
                task_to_ids = {}
                for key in ready_tasks_info:
                    ids = self.processor.get_task_data(key)
                    task_to_ids[key] = ids
                    current_isp_ids.update(ids)

                # Запрос статусов в MaxPatrol VM
                mpvm_data = self.validator.check_mpvm_status(list(current_isp_ids))

                for key, task_update_time in ready_tasks_info.items():
                    ids = task_to_ids.get(key, [])
                    if not ids: continue
                    
                    result = self.validator.evaluate_vulnerabilities(ids, mpvm_data, task_update_time)

                    if result['status'] == 'WAIT':
                        # ТЕПЕРЬ МЫ ВИДИМ ПРИЧИНУ ОЖИДАНИЯ В ЛОГАХ
                        logging.info(f"    [WAIT] {key}: Scan is older than Jira action. Jira: {result['update_date']}, MPVM: {result['audit_date']}.")
                        
                        if result['wait_days'] >= MAX_WAIT_DAYS:
                            logging.info(f"    [STUCK] {key}: Waiting for scan > {MAX_WAIT_DAYS} days.")
                            if isp not in stuck_reports: stuck_reports[isp] = []
                            stuck_reports[isp].append(f"* {key} (User Action с: {result['update_date']}, Скан: {result['audit_date']})")
                    
                    elif result['status'] == 'READY_TO_CLOSE':
                        logging.info(f"    [CLOSE] {key}: All FIXED. Audit confirmed.")
                        msg = "Автоматическая проверка: все уязвимости исправлены. Закрываю задачу."
                        if self.processor.change_issue_status(key, TRANSITION_ID_CLOSE, msg):
                            action_reports[isp].append(f"✅ *{key}*: Автоматически закрыта (все исправлено)")
                    
                    elif result['status'] == 'REJECT':
                        logging.info(f"    [REJECT] {key}: {result['fixed']}/{result['total']} fixed.")
                        msg = self.processor.generate_reject_message(result['fixed'], result['total'])
                        if self.processor.change_issue_status(key, TRANSITION_ID_PENDING, msg):
                            action_reports[isp].append(f"❌ *{key}*: Возвращена владельцу (исправлено {result['fixed']} из {result['total']})")

            # 3. МОНИТОРИНГ СТАТУСА "WAITING FOR SUPPORT" (ESCALATION)
            support_tasks = self.discovery.filter_support_tasks(tasks_for_verification)
            logging.info(f"  > ISP {isp}: {len(support_tasks)} tickets in 'Waiting for support' status.")
            
            for key, updated_dt in support_tasks.items():
                days_in_support = (datetime.now() - updated_dt).days
                if days_in_support >= MAX_SUPPORT_WAIT_DAYS:
                    logging.warning(f"    [ESCALATE] {key}: Stuck in support.")
                    if isp not in escalation_reports: escalation_reports[isp] = []
                    escalation_reports[isp].append(f"* {key} (В поддержке с: {updated_dt.strftime('%Y-%m-%d')}, Дней: {days_in_support})")

        # --- 4. ОТПРАВКА СВОДНЫХ ОТЧЕТОВ ---
        logging.info("Step 4: Posting summary reports to ISP tasks...")

        for isp_key, alerts in admin_alerts.items():
            admin_msg = "⚠️ *ВНИМАНИЕ (ИБ)!* Необходимо дать ответ в SD (администратор закроет тикет через 7 дней):\n" + "\n".join(alerts)
            self.processor.add_isp_comment(isp_key, admin_msg)

        for isp_key, actions in action_reports.items():
            if actions:
                summary_msg = "🤖 *Дневной отчет автоматики по проверке SD-задач:*\n" + "\n".join(actions)
                self.processor.add_isp_comment(isp_key, summary_msg)

        for isp_key, stuck_list in stuck_reports.items():
            alert_msg = "⚠️ *Внимание ИБ!* Задачи зависли в 'User Action' > 14 дней:\n" + "\n".join(stuck_list)
            self.processor.add_isp_comment(isp_key, alert_msg)

        for isp_key, esc_list in escalation_reports.items():
            esc_msg = "🚨 *Эскалация ИБ!* Задачи находятся в статусе 'Waiting for support' более 60 дней:\n" + "\n".join(esc_list)
            self.processor.add_isp_comment(isp_key, esc_msg)
            
        logging.info("--- Verification Workflow Finished ---")
