import voluptuous as vol
from homeassistant import config_entries
from .const import DOMAIN, DEFAULT_RULES, DEFAULT_TOKEN

class GmailRulesConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        schema = vol.Schema({vol.Required("rules_path", default=DEFAULT_RULES): str,
                             vol.Required("token_path", default=DEFAULT_TOKEN): str,
                             vol.Required("interval_minutes", default=15): vol.All(vol.Coerce(int), vol.Range(min=5, max=1440)),
                             vol.Required("dry_run", default=True): bool})
        if user_input is not None:
            await self.async_set_unique_id(user_input["token_path"])
            self._abort_if_unique_id_configured()
            return self.async_create_entry(title="PasevSU Gmail Rules", data=user_input)
        return self.async_show_form(step_id="user", data_schema=schema)

    @staticmethod
    def async_get_options_flow(config_entry):
        return GmailRulesOptionsFlow(config_entry)

class GmailRulesOptionsFlow(config_entries.OptionsFlow):
    def __init__(self, config_entry):
        self._entry = config_entry

    async def async_step_init(self, user_input=None):
        current = {**self._entry.data, **self._entry.options}
        schema = vol.Schema({vol.Required("rules_path", default=current["rules_path"]): str,
                             vol.Required("token_path", default=current["token_path"]): str,
                             vol.Required("interval_minutes", default=current["interval_minutes"]): vol.All(vol.Coerce(int), vol.Range(min=5, max=1440)),
                             vol.Required("dry_run", default=current["dry_run"]): bool})
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)
        return self.async_show_form(step_id="init", data_schema=schema)
