"""Metering sensors (standard Tuya socket DPs): current, power, voltage."""
from __future__ import annotations

from dataclasses import dataclass

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import UnitOfElectricCurrent, UnitOfElectricPotential, UnitOfPower
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import TuyaHomeConfigEntry
from .entity import TuyaHomeEntity


@dataclass(frozen=True, kw_only=True)
class TuyaHomeSensorDescription(SensorEntityDescription):
    scale: float = 1.0


SENSORS: tuple[TuyaHomeSensorDescription, ...] = (
    TuyaHomeSensorDescription(
        key="18",  # cur_current, mA
        name="Current",
        device_class=SensorDeviceClass.CURRENT,
        native_unit_of_measurement=UnitOfElectricCurrent.MILLIAMPERE,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    TuyaHomeSensorDescription(
        key="19",  # cur_power, W * 10
        name="Power",
        device_class=SensorDeviceClass.POWER,
        native_unit_of_measurement=UnitOfPower.WATT,
        state_class=SensorStateClass.MEASUREMENT,
        scale=0.1,
    ),
    TuyaHomeSensorDescription(
        key="20",  # cur_voltage, V * 10
        name="Voltage",
        device_class=SensorDeviceClass.VOLTAGE,
        native_unit_of_measurement=UnitOfElectricPotential.VOLT,
        state_class=SensorStateClass.MEASUREMENT,
        scale=0.1,
    ),
)


async def async_setup_entry(
    hass: HomeAssistant, entry: TuyaHomeConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    device = entry.runtime_data
    async_add_entities(
        TuyaHomeSensor(entry, device, desc)
        for desc in SENSORS
        if isinstance(device.dps.get(desc.key), (int, float))
    )


class TuyaHomeSensor(TuyaHomeEntity, SensorEntity):
    entity_description: TuyaHomeSensorDescription

    def __init__(self, entry, device, description: TuyaHomeSensorDescription) -> None:
        super().__init__(entry, device, description.key)
        self.entity_description = description

    @property
    def native_value(self) -> float | None:
        value = self._device.dps.get(self._dp)
        if not isinstance(value, (int, float)):
            return None
        scale = self.entity_description.scale
        return value if scale == 1 else round(value * scale, 2)
