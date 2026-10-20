# -*- coding: utf-8 -*-
import logging
from datetime import datetime
from api_mp_vm.client import MaxPatrolVMClient
from api_mp_vm.mp_vm_variables import mpvm_base_url, MPVM_HTTPS_VERIFY
from pathlib import Path

logger = logging.getLogger(__name__)

class MPVMValidator:
    def __init__(self):
        self.base_dir = Path(__file__).resolve().parents[3] 
        self.pdql_template_path = self.base_dir / "intergrations" / "jira-check" / "check_vuln_status.pdql"
        self.client = MaxPatrolVMClient(base_url=mpvm_base_url, verify_ssl=MPVM_HTTPS_VERIFY)
        self.is_authenticated = False

    def _ensure_auth(self) -> bool:
        """Ленивая авторизация сессии клиента."""
        if not self.is_authenticated:
            self.is_authenticated = self.client.authenticate()
        return self.is_authenticated

    def check_mpvm_status(self, all_vuln_ids):
        """Запрашивает статус уязвимостей в MP VM через /export и парсит CSV-ответ."""
        if not all_vuln_ids:
            return {}

        if not self._ensure_auth():
            logger.error("Validator: MPVM Auth failed")
            return {}

        try:
            if not self.pdql_template_path.exists():
                logger.error(f"Template path missing: {self.pdql_template_path}")
                return {}

            template = self.pdql_template_path.read_text(encoding="utf-8")
            
            # Подставляем ID в оригинальный PDQL-шаблон со всеми квадратными скобками [{ids}]
            pdql = template.replace("{ids}", ", ".join([f"'{i}'" for i in all_vuln_ids]))
            
            # 1. Получаем токен (POST /assets_grid)
            pdql_token = self.client.get_pdql_token(pdql)
            if not pdql_token:
                return {}

            # 2. Получаем сырой CSV-текст (GET /assets_grid/export)
            csv_data = self.client.fetch_grid_data(pdql_token)
            if not csv_data:
                return {}

            status_results = {}
            
            # 3. Парсим CSV-строки в памяти с помощью StringIO
            from io import StringIO
            import csv
            
            with StringIO(csv_data) as f:
                # В зависимости от вашей локали разделитель может быть ',' или ';' 
                # На скриншоте Postman разделитель — точка с запятой (;)
                reader = csv.DictReader(f, delimiter=';')
                
                for row in reader:
                    # Чистим имена колонок от возможных кавычек, которые добавляет экспорт
                    clean_row = {k.strip('"'): v.strip('"') for k, v in row.items() if k}
                    
                    # Извлекаем значения на основе заголовков из вашего Postman
                    v_status = clean_row.get("host.@vulners.status")
                    v_id = clean_row.get("host.@vulners.id")
                    v_audit = clean_row.get("host.@audittime")

                    if v_id:
                        audit_dt = None
                        if v_audit and v_audit != "null":
                            try:
                                # Парсим ISO-таймштамп вида 2026-10-18T07:38:45Z
                                audit_dt = datetime.strptime(v_audit[:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S')
                            except Exception:
                                pass
                                
                        status_results[str(v_id)] = {
                            "status": str(v_status).lower() if v_status else None,
                            "audit_time": audit_dt
                        }
                        
            return status_results

        except Exception as e:
            logger.error(f"Validator: Error compiling CSV data from export endpoint: {e}")
            return {}

    def evaluate_vulnerabilities(self, ids, mpvm_data, task_update_time, is_biweekly=False):
        """Сравнивает время аудита уязвимости сканером с временем обновления в Jira и возвращает вердикт."""
        fixed_count = 0
        waiting_scan = False
        latest_audit_found = None

        for v_id in ids:
            info = mpvm_data.get(str(v_id))
            if not info:
                continue

            if info["audit_time"]:
                if latest_audit_found is None or info["audit_time"] > latest_audit_found:
                    latest_audit_found = info["audit_time"]

            # Если это обычная проверка (User action), валидируем время Time-Sync
            if not is_biweekly and task_update_time:
                if info["audit_time"] and info["audit_time"] < task_update_time:
                    waiting_scan = True
                    break

            if info["status"] == "fixed":
                fixed_count += 1

        if not is_biweekly and waiting_scan and task_update_time:
            wait_days = (datetime.now() - task_update_time).days
            return {
                'status': 'WAIT',
                'wait_days': wait_days,
                'update_date': task_update_time.strftime('%Y-%m-%d'),
                'audit_date': latest_audit_found.strftime('%Y-%m-%d') if latest_audit_found else "Нет данных"
            }

        if fixed_count == len(ids) and len(ids) > 0:
            return {'status': 'READY_TO_CLOSE'}

        return {
            'status': 'REJECT',
            'fixed': fixed_count,
            'total': len(ids)
        }
