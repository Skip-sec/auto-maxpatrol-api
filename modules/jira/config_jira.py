FIELD_MAP = {
    "@Host": "Имя и IP-адрес",
    "host.fqdn": "FQDN",
    "OsName": "ОС",
    "OsVersion": "Версия ОС",
    "IT System": "ИТ Система",
    "Owner": "Владелец (Owner)",
    "Responsible": "Ответственный",
    
    "host.@NodeVulners.CVEs": "Список CVE",
    "Host.@NodeVulners.CVSS3Score": "CVSS (ОС)",
    "Host.@NodeVulners": "Уязвимость ОС",
    "Host.@NodeVulners.DiscoveryTime": "Обнаружено (ОС)",
    "Host.@NodeVulners.Status": "Статус (ОС)",
    "Host.@NodeVulners.HowToFix": "Решение (ОС)",
    "Host.@NodeVulners.Id": "ID (ОС)",
    "host.@nodevulners.Patch": "Патч/KB",

    "SoftwareName": "Программное обеспечение",
    "SoftwareVersion": "Версия ПО",
    "SoftwarePath": "Путь к ПО",
    "Vulners": "Уязвимость ПО",
    "Host.Softs.@Vulners.CVSS3Score": "CVSS (ПО)",
    "Host.Softs.@Vulners.HowToFix": "Решение (ПО)",
    "Host.Softs.@Vulners.Status": "Статус (ПО)",
    "Host.Softs.@Vulners.DiscoveryTime": "Обнаружено (ПО)",
    "Host.Softs.@Vulners.Id": "ID уязвимости (ПО)",

    "cmdb-Jira-ID": "ID в CMDB",
    "Status": "Статус хоста"
}

SERVICE_DESK_ID = "4"
REQUEST_TYPE_ID = "500"
APP_ID_JIRA_SD = "301eba08-3835-33fd-927b-f4932f6b2794"
PARENT_LINK_KEY = "ISP-***"


# Статус, который мы ищем для проверки
STATUS_TO_VERIFY = "User action" 
# Количество дней, которое задача должна провисеть в статусе перед проверкой
VERIFY_AFTER_DAYS = 7 
MAX_WAIT_DAYS = 14

#работы со статусами SD задач
TRANSITION_ID_CLOSE = "61"    # Accept -> статус Closed
TRANSITION_ID_PENDING = "51"  # Return to work -> статус Waiting for support

MAX_SUPPORT_WAIT_DAYS = 60  # Порог для эскалации задач Waiting for support
STATUS_WAITING_SUPPORT = "Waiting for support"
