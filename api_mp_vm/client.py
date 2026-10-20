# -*- coding: utf-8 -*- 
import logging
import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from os import getenv
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

class MaxPatrolVMClient:
    
    def __init__(self, base_url: str, verify_ssl: bool = False):
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl
        
        # Настройка ретраев
        retries = Retry(
            total=5,
            backoff_factor=1,  # Сон между попытками: 1s, 2s, 4s, 8s...
            status_forcelist=[500, 502, 503, 504],
            raise_on_status=False
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retries))
        
    def authenticate(self) -> bool:
        """Аутентификация в Identity Service MaxPatrol (порт 3334)."""
        url = f"{self.base_url}:3334/connect/token"
        payload = {
            "username": getenv("MPVM_USER"),
            "password": getenv("MPVM_PASSWORD"),
            "client_id": "mpx",
            "client_secret": getenv("MPVM_CLIENT_SECRET"),
            "grant_type": "password",
            "response_type": "id_token",
            "scope": "mpx.api",
        }
        try:
            response = self.session.post(url, data=payload, timeout=30)
            response.raise_for_status()
            token = response.json().get("access_token")
            if not token:
                raise ValueError("Access token fields missing in response.")
                
            # Обновляем дефолтные заголовки сессии для всех будущих запросов
            self.session.headers.update({
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/json;charset=UTF-8"
            })
            logger.info("Successfully authenticated in MaxPatrol VM.")
            return True
        except Exception as e:
            logger.critical(f"MaxPatrol VM Authentication Failed: {e}")
            return False

    def get_pdql_token(self, pdql_query: str) -> Optional[str]:
        """Регистрация PDQL запроса и получение временного токена транзакции."""
        url = f"{self.base_url}:443/api/assets_temporal_readmodel/v1/assets_grid"
        json_data = {
            "pdql": pdql_query,
            "selectedGroupIds": [],
            "additionalFilterParameters": {"groupIds": [], "assetIds": []},
            "includeNestedGroups": True,
            "utcOffset": "+03:00",
        }
        try:
            response = self.session.post(url, json=json_data, timeout=30)
            response.raise_for_status()
            token = response.json().get("token")
            logger.debug(f"PDQL Token successfully received: {token}")
            return token
        except Exception as e:
            logger.error(f"Failed to get PDQL token: {e}")
            return None

    def fetch_grid_data(self, pdql_token: str, limit: int = 1000) -> str:
        url = f"{self.base_url}:443/api/assets_temporal_readmodel/v1/assets_grid/export"
        params = {"pdqlToken": pdql_token}
        
        try:
            logger.info(f"Sending GET request to /export for token: {pdql_token}")
            # Увеличиваем timeout до 120 секунд, так как экспорт собирается ~42 секунды
            response = self.session.get(url, params=params, timeout=600)
            response.raise_for_status()
            
            # Возвращаем текстовое содержимое CSV-ответа
            csv_text = response.text
            logger.info(f"Successfully received CSV export snapshot ({len(csv_text)} bytes).")
            return csv_text
            
        except Exception as e:
            logger.error(f"Failed to fetch assets grid export data: {e}")
            return ""