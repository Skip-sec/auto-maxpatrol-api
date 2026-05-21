import csv
import logging
import os
# Импортируем маппинг полей из конфига
from modules.jira.config_jira import FIELD_MAP

def save_vulnerability_csv(data, prefix, owner, date_str):
    """
    Формирует CSV файл из списка словарей.
    Включает ТОЛЬКО те колонки, которые явно описаны в FIELD_MAP.
    """
    if not data:
        logging.debug(f"No data to save for {prefix} (Owner: {owner})")
        return None

    # Генерируем имя файла
    fname = f"{prefix}_{owner}_{date_str}.csv"
    
    try:
        # 1. Выбираем только те ключи из FIELD_MAP, которые РЕАЛЬНО присутствуют в данных.
        # Это исключает появление пустых колонок, если в этой пачке нет данных по ПО или ОС.
        active_original_keys = []
        for key in FIELD_MAP.keys():
            if any(key in record for record in data):
                active_original_keys.append(key)

        # 2. Создаем список красивых заголовков на русском языке
        field_names = [FIELD_MAP[key] for key in active_original_keys]

        # 3. Трансформируем данные: переименовываем и СТРОГО фильтруем лишнее
        human_readable_data = []
        for record in data:
            new_record = {}
            for key in active_original_keys:
                # Берем значение из записи, если его нет — пишем "N/A" или пустую строку
                value = record.get(key, "N/A")
                new_key = FIELD_MAP[key]
                new_record[new_key] = value
            human_readable_data.append(new_record)

        # 4. Записываем файл
        # utf-8-sig добавляет BOM для корректного отображения кириллицы в Excel
        with open(fname, 'w', newline='', encoding='utf-8-sig') as f:
            writer = csv.DictWriter(
                f, 
                fieldnames=field_names, 
                delimiter=';', 
                extrasaction='ignore' # Игнорирует любые поля, не вошедшие в fieldnames
            )
            
            writer.writeheader()
            writer.writerows(human_readable_data)
            
        logging.info(f"CSV created: {fname} ({len(human_readable_data)} records) with whitelisted headers only.")
        return fname

    except Exception as e:
        logging.error(f"Failed to create CSV {fname}: {e}")
        if os.path.exists(fname):
            os.remove(fname)
        return None
