"""Config flow: pick a device found on the LAN, enter its local key."""
from __future__ import annotations

import asyncio
from typing import Any

import voluptuous as vol

from homeassistant.config_entries import ConfigFlow, ConfigFlowResult
from homeassistant.const import CONF_HOST, CONF_NAME
from homeassistant.helpers.selector import (
    SelectOptionDict,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import (
    CONF_DEVICE_ID,
    CONF_LOCAL_KEY,
    CONF_PRODUCT_KEY,
    CONF_PROTOCOL_VERSION,
    DOMAIN,
)
from .protocol import SUPPORTED_VERSIONS, TuyaAuthError, TuyaError, probe

MANUAL = "manual"


class TuyaHomeConfigFlow(ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._found: dict[str, dict[str, Any]] = {}
        self._chosen: dict[str, Any] = {}

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        if user_input is not None:
            choice = user_input["device"]
            if choice != MANUAL:
                info = self._found[choice]
                self._chosen = {
                    CONF_DEVICE_ID: choice,
                    CONF_HOST: info["ip"],
                    CONF_PROTOCOL_VERSION: str(info.get("version", "3.4")),
                    CONF_PRODUCT_KEY: info.get("productKey"),
                }
            return await self.async_step_device()

        from . import async_get_discovery  # noqa: PLC0415 (avoid import cycle)

        discovery = await async_get_discovery(self.hass, warm_up=True)
        configured = {entry.unique_id for entry in self._async_current_entries()}
        self._found = {
            dev_id: info for dev_id, info in discovery.devices.items() if dev_id not in configured
        }
        options = [
            SelectOptionDict(value=dev_id, label=f"{dev_id} — {info['ip']} (v{info.get('version', '?')})")
            for dev_id, info in sorted(self._found.items(), key=lambda kv: kv[1]["ip"])
        ]
        options.append(SelectOptionDict(value=MANUAL, label="Enter manually"))
        schema = vol.Schema(
            {
                vol.Required("device"): SelectSelector(
                    SelectSelectorConfig(options=options, mode=SelectSelectorMode.LIST)
                )
            }
        )
        return self.async_show_form(
            step_id="user",
            data_schema=schema,
            description_placeholders={"count": str(len(self._found))},
        )

    async def async_step_device(self, user_input: dict[str, Any] | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            data = {**self._chosen, **user_input}
            await self.async_set_unique_id(data[CONF_DEVICE_ID])
            self._abort_if_unique_id_configured()
            if len(data[CONF_LOCAL_KEY].encode()) != 16:
                errors[CONF_LOCAL_KEY] = "invalid_key_length"
            else:
                try:
                    await probe(
                        data[CONF_DEVICE_ID],
                        data[CONF_LOCAL_KEY],
                        data[CONF_PROTOCOL_VERSION],
                        data[CONF_HOST],
                    )
                except TuyaAuthError:
                    errors["base"] = "invalid_auth"
                except TuyaError:
                    errors["base"] = "no_status"
                except (OSError, asyncio.TimeoutError):
                    errors["base"] = "cannot_connect"
                else:
                    title = data.pop(CONF_NAME)
                    return self.async_create_entry(title=title, data=data)

        chosen = self._chosen
        schema = vol.Schema(
            {
                vol.Required(CONF_NAME, default=chosen.get(CONF_DEVICE_ID, "Tuya")): str,
                vol.Required(CONF_DEVICE_ID, default=chosen.get(CONF_DEVICE_ID, "")): str,
                vol.Required(CONF_HOST, default=chosen.get(CONF_HOST, "")): str,
                vol.Required(CONF_LOCAL_KEY): str,
                vol.Required(
                    CONF_PROTOCOL_VERSION, default=chosen.get(CONF_PROTOCOL_VERSION, "3.4")
                ): vol.In(SUPPORTED_VERSIONS),
            }
        )
        if user_input is not None:
            schema = self.add_suggested_values_to_schema(schema, user_input)
        return self.async_show_form(step_id="device", data_schema=schema, errors=errors)
