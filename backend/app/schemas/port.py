"""Port Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class PortOut(BaseModel):
    """Port response."""
    id: uuid.UUID
    host_id: str
    port_number: int
    protocol: str
    state: str
    service_name: str | None
    service_version: str | None
    service_product: str | None
    service_extra_info: str | None
    service_cpe: str | None
    scripts_output: str | None
    banner: str | None
    discovered_at: datetime

    model_config = {"from_attributes": True}
