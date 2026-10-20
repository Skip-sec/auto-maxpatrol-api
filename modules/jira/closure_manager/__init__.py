# -*- coding: utf-8 -*-
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

logger = logging.getLogger(__name__)

class VulnerabilityClosureManager:
    def __init__(self, jira_url, jira_headers, sd_url, sd_headers):
        self.discovery = JiraDiscovery(jira_url, jira_headers, sd_url, sd_headers)
        self.validator = MPVMValidator()
        self.processor = JiraProcessor(jira_url, jira_headers, sd_url, sd_headers)
        self.tag_manager = ISPTagManager(jira_url, jira_headers)

    def run_workflow(self, is_biweekly=False):
        if is_biweekly:
            logger.info("--- Starting Refactored Verification Workflow (v4.5 - BIWEEKLY SUPPORT/PENDING CHECK) ---")
        else:
            logger.info("--- Starting Refactored Verification Workflow (v4.5 - Detailed Closed Report) ---")

        isp_list = self.discovery.get_weekly_isp_tasks()
        logger.info(f"Step 1: Found {len(isp_list)} weekly ISP umbrella tasks.")

        stuck_reports = {}
        escalation_reports = {}
        action_reports = {}
        admin_alerts = {}

        isp_escalation_tags = {}
        isp_ib_countdown_tags = {}
        isp_closed_without_answer_tags = {}

        for isp in isp_list:
            sd_keys = self.discovery.get_sd_tasks_from_isp(isp)
            logger.info(f" > ISP {isp}: Found {len(sd_keys)} linked SD tickets.")

            if not sd_keys:
                continue

            if isp not in action_reports:
                action_reports[isp] = []

            keys_to_skip = set()
            for key in sd_keys:
                # 1. Проверка скрытых закрытий тикетов без ответа ИБ
                if self.discovery.is_closed_without_ib_answer(key, ADMIN_LOGIN):
                    logger.warning(f" [CRITICAL REGULATION CLOSE] {key} was closed by system without IB response!")
                    if isp not in isp_closed_without_answer_tags:
                        isp_closed_without_answer_tags[isp] = []
                    isp_closed_without_answer_tags[isp].append(key)
                    keys_to_skip.add(key)
                    continue

                # 2. Проверка предупреждений от Admin в незакрытых задачах
                comment_dt = self.discovery.check_admin_warning(key, ADMIN_LOGIN)
                if comment_dt:
                    if isinstance(comment_dt, bool):
                        comment_dt = datetime.now()

                    logger.warning(f" [SKIP] {key}: Admin warning found. Skipping vulnerability check.")
                    if isp not in admin_alerts:
                        admin_alerts[isp] = []
                    admin_alerts[isp].append(f"* {key} (Требуется ответ ИБ, проверка MPVM пропущена)")
                    keys_to_skip.add(key)

                    # Вычисление дедлайна обратного отсчета для тегов ИБ
                    days_passed = (datetime.now() - comment_dt).days
                    days_left = max(1, min(7, 7 - days_passed))
                    current_tag = f"ИБ_{days_left}_дней"

                    if isp not in isp_ib_countdown_tags:
                        isp_ib_countdown_tags[isp] = current_tag
                    else:
                        old_days = int(isp_ib_countdown_tags[isp].split('_')[1])
                        if days_left < old_days:
                            isp_ib_countdown_tags[isp] = current_tag

            tasks_for_verification = [k for k in sd_keys if k not in keys_to_skip]

            # ================= РАЗВЕТВЛЕНИЕ РЕЖИМОВ РАБОТЫ =================
            if is_biweekly:
                biweekly_tasks = self.discovery.get_biweekly_support_tasks(tasks_for_verification)
                logger.info(f" > ISP {isp}: {len(biweekly_tasks)} tickets found in 'Waiting for support' / 'Pending' status.")

                if biweekly_tasks:
                    current_isp_ids = set()
                    task_to_ids = {}

                    for key in biweekly_tasks:
                        ids = self.processor.get_task_data(key)
                        task_to_ids[key] = ids
                        current_isp_ids.update(ids)

                    mpvm_data = self.validator.check_mpvm_status(list(current_isp_ids))

                    for key in biweekly_tasks:
                        ids = task_to_ids.get(key, [])
                        if not ids:
                            continue

                        result = self.validator.evaluate_vulnerabilities(ids, mpvm_data, task_update_time=None, is_biweekly=True)

                        if result['status'] == 'READY_TO_CLOSE':
                            logger.info(f" [BIWEEKLY CLOSE] {key}: All FIXED. Launching chain transition.")
                            if self.processor.process_biweekly_success_close(key):
                                action_reports[isp].append(f"✅ *{key}*: Автоматически закрыта из Поддержки/Pending (все уязвимости устранены в MP VM)")
                        else:
                            logger.info(f" [BIWEEKLY SKIP] {key}: Vulnerabilities still active ({result.get('fixed', 0)}/{result.get('total', 0)} fixed). Keeping state.")
            else:
                ready_tasks_info = self.discovery.filter_ready_tasks(tasks_for_verification)
                logger.info(f" > ISP {isp}: {len(ready_tasks_info)} tickets in 'User Action' status.")

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
                        if not ids:
                            continue

                        result = self.validator.evaluate_vulnerabilities(ids, mpvm_data, task_update_time, is_biweekly=False)
                        if result['status'] == 'WAIT':
                            logger.info(f" [WAIT] {key}: Scan is older than Jira action.")
                            if result['wait_days'] >= MAX_WAIT_DAYS:
                                if isp not in stuck_reports:
                                    stuck_reports[isp] = []
                                stuck_reports[isp].append(f"* {key} (User Action с: {result['update_date']}, Скан: {result['audit_date']})")

                        elif result['status'] == 'READY_TO_CLOSE':
                            logger.info(f" [CLOSE] {key}: All FIXED. Audit confirmed.")
                            msg = "Автоматическая проверка: все уязвимости исправлены. Закрываю задачу."
                            if self.processor.change_issue_status(key, TRANSITION_ID_CLOSE, msg):
                                action_reports[isp].append(f"✅ *{key}*: Автоматически закрыта (все исправлено)")

                        elif result['status'] == 'REJECT':
                            logger.info(f" [REJECT] {key}: {result['fixed']}/{result['total']} fixed.")
                            msg = self.processor.generate_reject_message(result['fixed'], result['total'])
                            if self.processor.change_issue_status_with_reject(key, TRANSITION_ID_PENDING, msg):
                                action_reports[isp].append(f"❌ *{key}*: Возвращена владельцу (исправлено {result['fixed']} из {result['total']})")

                # Мониторинг просрочек в Waiting for Support (только в Daily)
                support_tasks = self.discovery.filter_support_tasks(tasks_for_verification)
                logger.info(f" > ISP {isp}: {len(support_tasks)} tickets in 'Waiting for support' status.")

                for key, updated_dt in support_tasks.items():
                    days_in_support = (datetime.now() - updated_dt).days

                    if days_in_support >= 60:
                        tag_name = TAG_PROGRESS_60D if days_in_support < 80 else (TAG_PROGRESS_80D if days_in_support < 90 else TAG_PROGRESS_90D)
                        isp_escalation_tags[isp] = tag_name

                        if days_in_support in ESCALATION_TARGET_DAYS:
                            if isp not in escalation_reports:
                                escalation_reports[isp] = []
                            stage = "⚠️ ПЕРВИЧНАЯ (60 дней)" if days_in_support == 60 else ("🚨 КРИТИЧЕСКАЯ (80 дней)" if days_in_support == 80 else "🔥 ФИНАЛЬНАЯ (90 дней)")
                            escalation_reports[isp].append(f"* {key} [{stage}] (В поддержке с: {updated_dt.strftime('%Y-%m-%d')})")
        # ================= ЭТАП 4: СИНХРОНИЗАЦИЯ ТЕГОВ И КОММЕНТАРИЕВ В ISP =================
        logger.info("Step 4: Posting summary reports to ISP tasks...")
        for isp_key in isp_list:
            if isp_key in isp_closed_without_answer_tags and isp_closed_without_answer_tags[isp_key]:
                self.tag_manager.add_label_to_issue(isp_key, TAG_CLOSED_NO_ANSWER)
                closed_issues_str = ", ".join(isp_closed_without_answer_tags[isp_key])
                msg = f"🚨 *КРИТИЧЕСКИЙ АЛЕРТ АВТОМАТИКИ!* Связанные инциденты SD были автоматически закрыты системой по регламенту БЕЗ ответа ИБ. Требуется ручной аудит: {closed_issues_str}."
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
            else:
                for tag in TAGS_IB_COUNTDOWN:
                    self.tag_manager.remove_label_from_issue(isp_key, tag)

            # --- Публикация алертов по комментариям администратора ---
            if isp_key in admin_alerts and admin_alerts[isp_key]:
                self.processor.add_isp_comment(
                    isp_key, 
                    f"⚠️ *ВНИМАНИЕ (ИБ)!* Необходимо дать ответ в SD:\n" + "\n".join(admin_alerts[isp_key])
                )

            # --- Умное управление метками длительной просрочки (60d, 80d, 90d) ---
            if isp_key in isp_escalation_tags:
                target_tag = isp_escalation_tags[isp_key]
                for tag in [TAG_PROGRESS_60D, TAG_PROGRESS_80D, TAG_PROGRESS_90D]:
                    if tag != target_tag:
                        self.tag_manager.remove_label_from_issue(isp_key, tag)
                self.tag_manager.add_label_to_issue(isp_key, target_tag)
            else:
                for tag in [TAG_PROGRESS_60D, TAG_PROGRESS_80D, TAG_PROGRESS_90D]:
                    self.tag_manager.remove_label_from_issue(isp_key, tag)

            # --- Публикация отчетов об автоматических действиях (Close / Reject) ---
            if isp_key in action_reports and action_reports[isp_key]:
                header = (
                    "🤖 *Отчет автоматики по двухнедельной очистке 'Waiting for support' / 'Pending':*\n" 
                    if is_biweekly else 
                    "🤖 *Дневной отчет автоматики по проверке SD-задач:*\n"
                )
                self.processor.add_isp_comment(isp_key, header + "\n".join(action_reports[isp_key]))

            # --- Публикация отчетов по задачам, зависшим в User Action > 14 дней ---
            if not is_biweekly and isp_key in stuck_reports and stuck_reports[isp_key]:
                self.processor.add_isp_comment(
                    isp_key, 
                    "⚠️ *Внимание ИБ!* Задачи зависли в 'User Action' > 14 дней:\n" + "\n".join(stuck_reports[isp_key])
                )
            # --- Публикация отчетов по критическим эскалациям (60, 80, 90 дней) ---
            if isp_key in escalation_reports and escalation_reports[isp_key]:
                self.processor.add_isp_comment(
                    isp_key, 
                    "🚨 *Эскалация ИБ!* Зафиксированы задачи, требующие немедленного контроля:\n" + "\n".join(escalation_reports[isp_key])
                )
        logger.info("--- Verification Workflow Finished ---")