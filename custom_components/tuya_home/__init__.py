"""Tuya Home — local-only control of Tuya Wi-Fi devices (protocol 3.3/3.4/3.5)."""
from __future__ import annotations

import asyncio
import time

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import Event, HomeAssistant
from homeassistant.exceptions import ConfigEntryNotReady

from .const import (
    CONF_DEVICE_ID,
    CONF_LOCAL_KEY,
    CONF_PROTOCOL_VERSION,
    DATA_DISCOVERY,
    DISCOVERY_WARMUP,
    DOMAIN,
)
from .discovery import TuyaDiscovery
from .protocol import TuyaDevice

PLATFORMS = [Platform.SWITCH, Platform.SENSOR]

type TuyaHomeConfigEntry = ConfigEntry[TuyaDevice]


async def async_get_discovery(hass: HomeAssistant, warm_up: bool = False) -> TuyaDiscovery:
    """Shared passive UDP listener (one per HA instance)."""
    data = hass.data.setdefault(DOMAIN, {})
    discovery: TuyaDiscovery | None = data.get(DATA_DISCOVERY)
    if discovery is None:
        discovery = TuyaDiscovery()
        await discovery.start()
        data[DATA_DISCOVERY] = discovery

        def _stop(_: Event) -> None:
            discovery.close()

        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _stop)
    if warm_up:
        remaining = DISCOVERY_WARMUP - (time.monotonic() - discovery.started_at)
        if remaining > 0:
            await asyncio.sleep(remaining)
    return discovery


async def async_setup_entry(hass: HomeAssistant, entry: TuyaHomeConfigEntry) -> bool:
    discovery = await async_get_discovery(hass)
    device_id = entry.data[CONF_DEVICE_ID]

    def resolve_host() -> str | None:
        """Follow the device if DHCP gave it a new IP."""
        host = discovery.host_of(device_id)
        if host and host != entry.data[CONF_HOST]:
            hass.config_entries.async_update_entry(entry, data={**entry.data, CONF_HOST: host})
        return host

    device = TuyaDevice(
        device_id,
        entry.data[CONF_LOCAL_KEY],
        entry.data[CONF_PROTOCOL_VERSION],
        entry.data[CONF_HOST],
        host_resolver=resolve_host,
    )
    entry.async_create_background_task(hass, device.run(), f"{DOMAIN} {device_id}")

    try:
        await asyncio.wait_for(device.wait_available(), 20)
    except TimeoutError as err:
        await device.stop()
        raise ConfigEntryNotReady(f"{device_id} unavailable: {device.last_error}") from err

    entry.runtime_data = device
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: TuyaHomeConfigEntry) -> bool:
    unloaded = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unloaded:
        await entry.runtime_data.stop()
    return unloaded
