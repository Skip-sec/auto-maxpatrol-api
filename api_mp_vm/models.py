# -*- coding: utf-8 -*- 
from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any, List

class MPVMRecord(BaseModel):
    """Модель валидации и автоматической очистки сырой записи MaxPatrol VM."""
    host_raw: Any = Field(alias="@Host", default=None)
    vulners_raw: Any = Field(alias="Vulners", default=None)
    node_vuln_raw: Any = Field(alias="Host.@NodeVulners", default=None)
    soft_status_raw: Any = Field(alias="Host.Softs.@Vulners.Status", default=None)
    os_status_raw: Any = Field(alias="Host.@NodeVulners.Status", default=None)
    
    # Сюда будут складываться очищенные плоские данные
    host: str = ""
    vulners: str = ""
    node_vulners: str = ""
    soft_status: str = ""
    os_status: str = ""
    
    # Позволяет модели принимать дополнительные динамические поля от MP VM
    model_config = {"extra": "allow", "populate_by_name": True}

    @field_validator("host", mode="before")
    def _extract_host(cls, v, info):
        raw = info.data.get("host_raw")
        return raw.get("name", "") if isinstance(raw, dict) else str(raw or "")

    @field_validator("vulners", mode="before")
    def _extract_vulners(cls, v, info):
        raw = info.data.get("vulners_raw")
        return raw.get("name", "") if isinstance(raw, dict) else str(raw or "")

    @field_validator("node_vulners", mode="before")
    def _extract_node_vuln(cls, v, info):
        raw = info.data.get("node_vuln_raw")
        return raw.get("name", "") if isinstance(raw, dict) else str(raw or "")

    @field_validator("soft_status", mode="before")
    def _extract_soft_status(cls, v, info):
        raw = info.data.get("soft_status_raw")
        return raw.get("value", "") if isinstance(raw, dict) else str(raw or "")

    @field_validator("os_status", mode="before")
    def _extract_os_status(cls, v, info):
        raw = info.data.get("os_status_raw")
        return raw.get("value", "") if isinstance(raw, dict) else str(raw or "")

    def to_flat_dict(self) -> Dict[str, Any]:
        """Экспорт в плоский словарь, готовый для Pandas DataFrame и Jira."""
        data = self.model_dump(by_alias=False)
        # Удаляем временные сырые поля
        for raw_key in ["host_raw", "vulners_raw", "node_vuln_raw", "soft_status_raw", "os_status_raw"]:
            data.pop(raw_key, None)
        return data
