#!/usr/bin/env python3
# Copyright 2026 Canonical Ltd.
# See LICENSE file for licensing details.

"""File containing config helper functions and classes."""

import pydantic

from constants import MICROOVN_VALID_RISKS


class MicroovnConfig(pydantic.BaseModel):
    """Config class for managing the microovn risk config option."""

    microovn_risk: str = pydantic.Field("edge")

    @pydantic.field_validator("microovn_risk")
    @classmethod
    def validate_risk(cls, risk: str):
        """Ensure risk is a valid risk."""
        risk_parts = risk.split("/")
        if risk_parts[0] not in MICROOVN_VALID_RISKS:
            raise ValueError(
                risk + " not a valid risk, valid risks are: " + ", ".join(MICROOVN_VALID_RISKS)
            )
        if len(risk_parts) > 2:
            raise ValueError(risk + " has too many parts, should at most be risk/branch")
        if len(risk_parts) > 1 and risk_parts[1] == "":
            raise ValueError("risk branch cannot be an empty string")
        return risk
