import logging
from datetime import datetime
from modules.jira.config_jira import (
    MAX_WAIT_DAYS, 
    MAX_SUPPORT_WAIT_DAYS,
    TRANSITION_ID_CLOSE, 
    TRANSITION_ID_PENDING,
    ADMIN_LOGIN,
    ESCALATION_TARGET_DAYS,
    TAGS_IB_COUNTDOWN,
    TAG_PROGRESS_60D,
    TAG_PROGRESS_80D,
    TAG_PROGRESS_90D,
    TAG_CLOSED_NO_ANSWER
)

from .discovery import JiraDiscovery
from .validator import MPVMValidator
from .processor import JiraProcessor
from .tags_isp import ISPTagManager

class VulnerabilityClosureManager:
    def __init__(self, jira_url, jira_headers, sd_url, sd_headers):
        self.discovery = JiraDiscovery(jira_url, jira_headers, sd_url, sd_headers)
        self.validator = MPVMValidator()
        self.processor = JiraProcessor(jira_url, jira_headers, sd_url, sd_headers)
        self.tag_manager = ISPTagManager(jira_url, jira_headers)

    def run_workflow(self):
        logging.info("--- Starting Refactored Verification Workflow (v4.4 - Detailed Closed Report) ---")
        
        isp_list = self.discovery.get_weekly_isp_tasks()
        logging.info(f"Step 1: Found {len(isp_list)} weekly ISP umbrella tasks.")
        
        # Словари для накопления отчетов по каждой ISP
        stuck_reports = {}      
        escalation_reports = {} 
        action_reports = {}     
        admin_alerts = {}       
        
        # Словари для накопления актуальных тегов по каждой ISP на текущий запуск
        isp_escalation_tags = {} 
        isp_ib_countdown_tags = {}
        
        # ИСПРАВЛЕНО: Словарь теперь будет хранить СПИСКИ строк (ключей задач SD) вместо True
        isp_closed_without_answer_tags = {} 

        for isp in isp_list:
            sd_keys = self.discovery.get_sd_tasks_from_isp(isp)
            logging.info(f"  > ISP {isp}: Found {len(sd_keys)} linked SD tickets.")
            
            if not sd_keys:
                continue

            if isp not in action_reports:
                action_reports[isp] = []

            # 1. ПРОВЕРКА ПРЕДУПРЕЖДЕНИЙ ОТ ADMIN И РЕГЛАМЕНТНЫХ АВТОЗАКРЫТИЙ
            keys_to_skip = set()
            for key in sd_keys:
                # Проверяем, не закрыла ли система тикет по регламенту втихую без ответа ИБ
                if self.discovery.is_closed_without_ib_answer(key, ADMIN_LOGIN):
                    logging.warning(f"    [CRITICAL REGULATION CLOSE] {key} was closed by system without IB response!")
                    
                    # ИСПРАВЛЕНО: Инициализируем список для ISP, если его еще нет, и добавляем туда ключ проблемного тикета SD
                    if isp not in isp_closed_without_answer_tags:
                        isp_closed_without_answer_tags[isp] = []
                    isp_closed_without_answer_tags[isp].append(key)

                    keys_to_skip.add(key)  # Исключаем закрытую задачу из дальнейших проверок MPVM
                    continue

                # Проверка активных предупреждений в незакрытых задачах
                comment_dt = self.discovery.check_admin_warning(key, ADMIN_LOGIN)
                if comment_dt:
                    if isinstance(comment_dt, bool): 
                        comment_dt = datetime.now()
                        
                    logging.warning(f"    [SKIP] {key}: Admin warning found. Skipping vulnerability check.")
                    
                    if isp not in admin_alerts: 
                        admin_alerts[isp] = []
                    admin_alerts[isp].append(f"* {key} (Требуется ответ ИБ, проверка MPVM пропущена)")
                    keys_to_skip.add(key)
                    
                    # Вычисляем обратный отсчет дней для ИБ
                    days_passed = (datetime.now() - comment_dt).days
                    days_left = 7 - days_passed
                    
                    if days_left < 1: days_left = 1
                    elif days_left > 7: days_left = 7
                        
                    current_tag = f"ИБ_{days_left}_дней"
                    
                    if isp not in isp_ib_countdown_tags:
                        isp_ib_countdown_tags[isp] = current_tag
                    else:
                        old_days = int(isp_ib_countdown_tags[isp].split('_'))
                        if days_left < old_days:
                            isp_ib_countdown_tags[isp] = current_tag

            # Фильтруем задачи, исключая алерты и закрытые регламентом инциденты
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

                mpvm_data = self.validator.check_mpvm_status(list(current_isp_ids))

                for key, task_update_time in ready_tasks_info.items():
                    ids = task_to_ids.get(key, [])
                    if not ids: continue
                    
                    result = self.validator.evaluate_vulnerabilities(ids, mpvm_data, task_update_time)

                    if result['status'] == 'WAIT':
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
                
                if days_in_support >= 60:
                    if days_in_support < 80:
                        tag_name = TAG_PROGRESS_60D
                    elif days_in_support < 90:
                        tag_name = TAG_PROGRESS_80D
                    else:
                        tag_name = TAG_PROGRESS_90D
                    isp_escalation_tags[isp] = tag_name

                if days_in_support in ESCALATION_TARGET_DAYS:
                    logging.warning(f"    [ESCALATE REPORT TRIGGER] {key}: Exactly {days_in_support} days stuck.")
                    if isp not in escalation_reports: 
                        escalation_reports[isp] = []
                    
                    if days_in_support == 60:
                        stage = "⚠️ ПЕРВИЧНАЯ (60 дней)"
                    elif days_in_support == 80:
                        stage = "🚨 КРИТИЧЕСКАЯ (80 дней)"
                    else:
                        stage = "🔥 ФИНАЛЬНАЯ (90 дней)"
                        
                    escalation_reports[isp].append(f"* {key} [{stage}] (В поддержке с: {updated_dt.strftime('%Y-%m-%d')})")

        # --- 4. ОТПРАВКА СВОДНЫХ ОТЧЕТОВ И ПРАВИЛА ДЛЯ ТЕГОВ ---
        logging.info("Step 4: Posting summary reports to ISP tasks...")

        for isp_key in isp_list:
            # --- Управление меткой регламентного закрытия без ответа ---
            if isp_key in isp_closed_without_answer_tags and isp_closed_without_answer_tags[isp_key]:
                self.tag_manager.add_label_to_issue(isp_key, TAG_CLOSED_NO_ANSWER)
                
                # Объединяем список найденных закрытых задач через запятую
                closed_issues_str = ", ".join(isp_closed_without_answer_tags[isp_key])
                msg = f"🚨 *КРИТИЧЕСКИЙ АЛЕРТ АВТОМАТИКИ!* Связанные инциденты SD были автоматически закрыты системой по регламенту БЕЗ ответа ИБ-персонала. Требуется ручной аудит связей по задачам: {closed_issues_str}."
                self.processor.add_isp_comment(isp_key, msg)
            else:
                self.tag_manager.remove_label_from_issue(isp_key, TAG_CLOSED_NO_ANSWER)

            # --- Умное управление метками обратного отсчета ИБ_X_дней ---
            if isp_key in isp_ib_countdown_tags:
                target_ib_tag = isp_ib_countdown_tags[isp_key]
                for tag in TAGS_IB_COUNTDOWN:
                    if tag != target_ib_tag: 
                        self.tag_manager.remove_label_from_issue(isp_key, tag)
                self.tag_manager.add_label_to_issue(isp_key, target_ib_tag)
                
                if isp_key in admin_alerts and admin_alerts[isp_key]:
                    alerts = admin_alerts[isp_key]
                    admin_msg = f"⚠️ *ВНИМАНИЕ (ИБ)!* Необходимо дать ответ в SD:\n" + "\n".join(alerts)
                    self.processor.add_isp_comment(isp_key, admin_msg)
            else:
                for tag in TAGS_IB_COUNTDOWN: 
                    self.tag_manager.remove_label_from_issue(isp_key, tag)

            # --- Умное управление метками длительной просрочки (60d, 80d, 90d) ---
            if isp_key in isp_escalation_tags:
                target_tag = isp_escalation_tags[isp_key]
                for tag in self.tag_manager.all_escalation_tags:
                    if tag in [TAG_PROGRESS_60D, TAG_PROGRESS_80D, TAG_PROGRESS_90D] and tag != target_tag:
                        self.tag_manager.remove_label_from_issue(isp_key, tag)
                self.tag_manager.add_label_to_issue(isp_key, target_tag)
            else:
                for tag in [TAG_PROGRESS_60D, TAG_PROGRESS_80D, TAG_PROGRESS_90D]:
                    self.tag_manager.remove_label_from_issue(isp_key, tag)

        # Отчеты об автоматических действиях (Close / Reject) за день
        for isp_key, actions in action_reports.items():
            if actions:
                summary_msg = "🤖 *Дневной отчет автоматики по проверке SD-задач:*\n" + "\n".join(actions)
                self.processor.add_isp_comment(isp_key, summary_msg)

        # Отчет по задачам, зависшим в User Action > 14 дней
        for isp_key, stuck_list in stuck_reports.items():
            if stuck_list:
                alert_msg = "⚠️ *Внимание ИБ!* Задачи зависли в 'User Action' > 14 дней:\n" + "\n".join(stuck_list)
                self.processor.add_isp_comment(isp_key, alert_msg)

        # Отчет по критическим эскалациям (Отправится только если сегодня ровно 60, 80 или 90 дней)
        for isp_key, esc_list in escalation_reports.items():
            if esc_list:  
                esc_msg = "🚨 *Эскалация ИБ!* Зафиксированы задачи, требующие немедленного контроля:\n" + "\n".join(esc_list)
                self.processor.add_isp_comment(isp_key, esc_msg)
            
        logging.info("--- Verification Workflow Finished ---")

