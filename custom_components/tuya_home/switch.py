"""Relay switches: boolean DPs 1..6 (switch_1 .. switch_6)."""
from __future__ import annotations

from typing import Any

from homeassistant.components.switch import SwitchDeviceClass, SwitchEntity
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import TuyaHomeConfigEntry
from .entity import TuyaHomeEntity
from .protocol import TuyaError

SWITCH_DPS = ("1", "2", "3", "4", "5", "6")


async def async_setup_entry(
    hass: HomeAssistant, entry: TuyaHomeConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    device = entry.runtime_data
    dps = [dp for dp in SWITCH_DPS if isinstance(device.dps.get(dp), bool)]
    async_add_entities(TuyaHomeSwitch(entry, device, dp, multi=len(dps) > 1) for dp in dps)


class TuyaHomeSwitch(TuyaHomeEntity, SwitchEntity):
    _attr_device_class = SwitchDeviceClass.SWITCH

    def __init__(self, entry, device, dp: str, multi: bool) -> None:
        super().__init__(entry, device, dp)
        # single relay -> entity takes the device name
        self._attr_name = f"Switch {dp}" if multi else None

    @property
    def is_on(self) -> bool | None:
        value = self._device.dps.get(self._dp)
        return value if isinstance(value, bool) else None

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._set(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._set(False)

    async def _set(self, value: bool) -> None:
        try:
            await self._device.set_dps({self._dp: value})
        except (TuyaError, OSError, TimeoutError) as err:
            raise HomeAssistantError(f"{self._device.device_id}: {err}") from err
