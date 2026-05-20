from datetime import date
import logging
import requests
from os import makedirs
from os.path import exists
from modules.api_mp_vm.convert_xlsx_from_csv import convert_xlsx_from_csv
from modules.api_mp_vm.get_pdql_token import get_pgql_token
from modules.api_mp_vm.mp_vm_variables import MPVM_HTTPS_VERIFY


def get_pdql_result_in_csv(
    mpvm_base_url, headers, pdql, integration, pdql_query_name, pqql_full_file_name
):
    logging.info("Start module get_pdql_result_in_csv()")

    pdql_token = get_pgql_token(mpvm_base_url, headers, pdql)
    if pdql_token == None:
        logging.error(f"ERROR getting the PDQL token from the request:{pdql}")
        return None

    params = {
        "pdqlToken": pdql_token,
    }
    try:
        url = mpvm_base_url + ":443/api/assets_temporal_readmodel/v1/assets_grid/export"
        response = requests.get(
            url,
            params=params,
            headers=headers,
            verify=MPVM_HTTPS_VERIFY,
        )
        logging.debug(f"Success connection to url MP VM {url}")
    except (ConnectionError, requests.exceptions.ConnectionError):
        logging.error(f"ERROR connection to url MP VM {url}")
        return None
    logging.debug(f"Responce sample = {response.text[:255]}")

    pdql_data = response.text
    logging.info("Success PDQL query")
    logging.debug(f"CSV example from PDQL: {pdql_data[0]}")

    if pdql_data == None:
        logging.error(
            f"ERROR executing a PDQL query from a file: {pqql_full_file_name}"
        )
        return

    logging.info(
        "The data from the PDQL query has been received. Writing data to a CSV-file"
    )

    data_path = "files/"
    if not exists(data_path):
        makedirs(data_path)
        logging.debug(f"MKDIR {data_path}")

    data_path += integration
    if not exists(data_path):
        makedirs(data_path)
        logging.debug(f"MKDIR {data_path}")

    data_path += "CSVFiles/"
    if not exists(data_path):
        makedirs(data_path)
        logging.debug(f"MKDIR {data_path}")

    CSVfile_name = data_path + pdql_query_name + "_" + str(date.today()) + ".csv"
    with open(CSVfile_name, "w", encoding="utf-8") as csv:
        csv.write(response.text)
    logging.info(f"Success write data in {CSVfile_name}")

    data_path = str(data_path).replace("CSVFiles", "XLSXFiles")
    if not exists(data_path):
        makedirs(data_path)
        logging.debug(f"MKDIR {data_path}")
    XLSXfile_name = data_path + pdql_query_name + "_" + str(date.today()) + ".xlsx"

    convert_xlsx_from_csv(CSVfile_name, XLSXfile_name)
