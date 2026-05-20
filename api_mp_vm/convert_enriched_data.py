import pandas as pd
import logging
from datetime import date
from os import makedirs
from os.path import exists

def convert_json_to_others(data, integration, query_name):
    df = pd.DataFrame(data)
    base_path = f"files/{integration}/"
    today = str(date.today())

    # Сохраняем CSV (с разделителем ; как вы просили)
    csv_path = f"{base_path}CSVFiles/"
    if not exists(csv_path): makedirs(csv_path)
    csv_file = f"{csv_path}{query_name}_{today}.csv"
    df.to_csv(csv_file, sep=';', index=False, encoding='utf-8-sig')

    # Сохраняем XLSX
    xlsx_path = f"{base_path}XLSXFiles/"
    if not exists(xlsx_path): makedirs(xlsx_path)
    xlsx_file = f"{xlsx_path}{query_name}_{today}.xlsx"
    df.to_excel(xlsx_file, index=False)

    logging.info(f"Successfully converted data to CSV and XLSX for {query_name}")
