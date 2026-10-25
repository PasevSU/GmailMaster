"""Read-only operational sensor; no message content stored in HA state."""
from homeassistant.components.sensor import SensorEntity
from .const import DOMAIN

async def async_setup_entry(hass, entry, async_add_entities):
    runtime = hass.data[DOMAIN][entry.entry_id]
    sensor = GmailNewMailSensor(runtime)
    runtime.sensor = sensor
    async_add_entities([sensor])

class GmailNewMailSensor(SensorEntity):
    _attr_has_entity_name = True
    _attr_name = "New mail detected"
    _attr_icon = "mdi:email-alert-outline"
    def __init__(self, runtime):
        self.runtime = runtime
        self._attr_unique_id = f"{runtime.entry.entry_id}_new_mail"
    @property
    def native_value(self):
        return self.runtime.new_count
    @property
    def extra_state_attributes(self):
        return {"last_check":self.runtime.last_check,
                "last_new_mail":self.runtime.last_new_mail,
                "last_result":self.runtime.last_result,
                "history_initialized":bool(self.runtime.history_id),
                "last_error":self.runtime.last_error}
