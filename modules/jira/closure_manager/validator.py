import logging
import requests
from datetime import datetime
from api_mp_vm.vm_authentication import vm_authentificate
from api_mp_vm.get_pdql_token import get_pdql_token
from api_mp_vm.mp_vm_variables import mpvm_base_url

class MPVMValidator:
    def __init__(self):
        self.pdql_template_path = "intergrations/jira-check/check_vuln_status.pdql"

    def check_mpvm_status(self, all_vuln_ids):
        """Запрашивает актуальный статус и время аудита уязвимостей в MP VM."""
        if not all_vuln_ids:
            return {}

        token = vm_authentificate(mpvm_base_url)
        if not token:
            logging.error("Validator: Auth failed")
            return {}

        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        
        try:
            with open(self.pdql_template_path, 'r') as f:
                template = f.read()
            
            # Подставляем ID в PDQL шаблон
            pdql = template.replace("{ids}", ", ".join([f"'{i}'" for i in all_vuln_ids]))
            pdql_token = get_pdql_token(mpvm_base_url, headers, pdql)
            
            if not pdql_token:
                return {}

            url = f"{mpvm_base_url}:443/api/assets_temporal_readmodel/v1/assets_grid/data"
            resp = requests.get(url, params={"limit": 5000, "pdqlToken": pdql_token}, headers=headers, verify=False)
            resp.raise_for_status()

            status_results = {}
            for rec in resp.json().get('records', []):
                # Проверяем ключи для ОС и ПО
                v_id = rec.get("host.@vulners.id") or rec.get("host.softs.@vulners.id")
                raw_status = rec.get("host.@vulners.status") or rec.get("host.softs.@vulners.status")
                v_status = raw_status.get("value") if isinstance(raw_status, dict) else raw_status
                v_audit = rec.get("host.@audittime")
                
                if v_id:
                    audit_dt = datetime.strptime(v_audit[:19].replace('T', ' '), '%Y-%m-%d %H:%M:%S') if v_audit else None
                    status_results[v_id] = {
                        "status": str(v_status).lower() if v_status else None, 
                        "audit_time": audit_dt
                    }
            return status_results
            
        except Exception as e:
            logging.error(f"Validator: MPVM API Error: {e}")
            return {}

    def evaluate_vulnerabilities(self, ids, mpvm_data, task_update_time):
        """Сравнивает время аудита с временем в Jira и возвращает вердикт."""
        fixed_count = 0
        waiting_scan = False
        latest_audit_found = None

        for v_id in ids:
            info = mpvm_data.get(v_id)
            if not info:
                continue
            
            # Отслеживаем дату последнего сканирования для отчета ИБ
            if info["audit_time"]:
                if latest_audit_found is None or info["audit_time"] > latest_audit_found:
                    latest_audit_found = info["audit_time"]

            # Если аудит в MP был ДО того, как задачу перевели в User Action
            if info["audit_time"] and info["audit_time"] < task_update_time:
                waiting_scan = True
                break
            
            if info["status"] == "fixed":
                fixed_count += 1

        # Формируем объект результата для __init__.py
        wait_days = (datetime.now() - task_update_time).days if waiting_scan else 0
        
        if waiting_scan:
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
