"""Base entity bound to one DP of a Tuya Home device."""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity

from .const import CONF_PRODUCT_KEY, DOMAIN
from .protocol import TuyaDevice


class TuyaHomeEntity(Entity):
    _attr_has_entity_name = True
    _attr_should_poll = False

    def __init__(self, entry: ConfigEntry, device: TuyaDevice, dp: str) -> None:
        self._device = device
        self._dp = dp
        self._attr_unique_id = f"{device.device_id}_{dp}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.device_id)},
            name=entry.title,
            manufacturer="Tuya",
            model=entry.data.get(CONF_PRODUCT_KEY),
            sw_version=f"protocol {device.version}",
        )

    @property
    def available(self) -> bool:
        return self._device.available and self._dp in self._device.dps

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._device.add_listener(self.async_write_ha_state))
