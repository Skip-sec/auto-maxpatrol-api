# -*- coding: utf-8 -*- 
import json
import logging
import pandas as pd
from pathlib import Path
from datetime import date
from typing import List, Dict, Any, Optional
from api_mp_vm.models import MPVMRecord
from modules.jira.jira_api import get_jira_asset_info

logger = logging.getLogger(__name__)

class MPVMPipelineService:
    """Сервис трансформации (Transform), обогащения (Enrich) и экспорта данных (Load)."""

    def __init__(self):
        self.jira_cache: Dict[str, Dict[str, Any]] = {}

    def _extract_short_host_name(self, host_name: str) -> str:
        """Безопасное извлечение короткого имени хоста для кэша Jira."""
        if not host_name:
            return ""
        # Разделяем по точкам, берем первый кусок, делим по пробелам, берем первый кусок.
        return host_name.split('.')[0].split(' ')[0].strip()

    def enrich_and_clean(self, raw_records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Конвейер валидации через Pydantic и обогащения данными из Jira Assets."""
        logger.info(f"Starting parsing and enrichment of {len(raw_records)} records...")
        processed_data = []

        for raw_item in raw_records:
            # 1. Валидация и парсинг внутренней структуры MP VM через Pydantic
            model = MPVMRecord.model_validate(raw_item)
            record_dict = model.to_flat_dict()
            
            # 2. Обогащение Jira Assets
            host_name = record_dict.get("host", "")
            if host_name:
                short_name = self._extract_short_host_name(host_name)
                if short_name not in self.jira_cache:
                    try:
                        self.jira_cache[short_name] = get_jira_asset_info(host_name)
                    except Exception as e:
                        logger.error(f"Jira API enrichment failed for {host_name}: {e}")
                        self.jira_cache[short_name] = {}

                # Накатываем данные из кэша Jira или дефолты, если кэш пуст
                jira_info = self.jira_cache[short_name]
                if jira_info:
                    record_dict.update(jira_info)
                else:
                    record_dict.update({
                        "cmdb-Jira-ID": "N/A", "Owner": "-", "Responsible": "-",
                        "IT System": "-", "Status": "-"
                    })
            processed_data.append(record_dict)

        logger.info("Enrichment phase completed successfully.")
        return processed_data

    def save_output_files(self, data: List[Dict[str, Any]], integration_name: str, query_name: str) -> bool:
        """Сохранение обработанного пакета в единую директорию jira-pdql (JSON, CSV, XLSX)."""
        if not data:
            logger.warning("No data to save.")
            return False

        today = date.today()
        # ИСПРАВЛЕНО: Принудительно направляем поток файлов в единую папку jira-pdql
        base_dir = Path("/opt/auto-maxpatrol-api/files/jira-pdql")
        
        # Оставляем красивую идиоматическую генерацию имен через Pathlib
        paths = {
            "json": base_dir / "JSONFiles" / f"{query_name}_{today}.json",
            "csv": base_dir / "CSVFiles" / f"{query_name}_{today}.csv",
            "xlsx": base_dir / "XLSXFiles" / f"{query_name}_{today}.xlsx"
        }

        try:
            # Автоматически проверяем и создаем подпапки (JSONFiles, CSVFiles, XLSXFiles), если их нет
            for p in paths.values():
                p.parent.mkdir(parents=True, exist_ok=True)

            # 1. Сериализация JSON
            with open(paths["json"], "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=4)

            # 2. Сериализация CSV & XLSX через Pandas
            df = pd.DataFrame(data)
            df.to_csv(paths["csv"], sep=';', index=False, encoding='utf-8-sig')
            df.to_excel(paths["xlsx"], index=False)

            logger.info(f"Successfully serialized ETL artifacts for query '{query_name}' to {base_dir}")
            return True
        except Exception as e:
            logger.error(f"Failed to save ETL artifacts down to disk: {e}")
            return False