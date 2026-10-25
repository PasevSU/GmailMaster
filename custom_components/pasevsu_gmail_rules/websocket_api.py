import voluptuous as vol
from homeassistant.components import websocket_api
from .const import DOMAIN
from .gmail_client import list_messages, list_labels, get_message
from .artifact_inspector import inspect_message, raw_digest, attachment_digest

@websocket_api.websocket_command({vol.Required("type"): "pasevsu_gmail/list", vol.Required("entry_id"): str,
    vol.Optional("label", default="INBOX"): str, vol.Optional("query", default=""): str,
    vol.Optional("page_token"): str})
@websocket_api.async_response
async def ws_list(hass, connection, msg):
    try:
        if not connection.user.is_admin:
            connection.send_error(msg["id"], "unauthorized", "Administrator required")
            return
        runtime = hass.data[DOMAIN][msg["entry_id"]]
        data = await hass.async_add_executor_job(runtime.list_page, msg["label"], msg["query"], msg.get("page_token"))
        connection.send_result(msg["id"], data)
    except Exception as exc: connection.send_error(msg["id"], "gmail_error", str(exc))

@websocket_api.websocket_command({vol.Required("type"): "pasevsu_gmail/labels", vol.Required("entry_id"): str})
@websocket_api.async_response
async def ws_labels(hass, connection, msg):
    try:
        if not connection.user.is_admin:
            connection.send_error(msg["id"], "unauthorized", "Administrator required")
            return
        runtime = hass.data[DOMAIN][msg["entry_id"]]
        data = await hass.async_add_executor_job(runtime.labels)
        connection.send_result(msg["id"], data)
    except Exception as exc: connection.send_error(msg["id"], "gmail_error", str(exc))

@websocket_api.websocket_command({vol.Required("type"): "pasevsu_gmail/inspect", vol.Required("entry_id"): str,
    vol.Required("message_id"): str})
@websocket_api.async_response
async def ws_inspect(hass, connection, msg):
    try:
        if not connection.user.is_admin:
            connection.send_error(msg["id"], "unauthorized", "Administrator required")
            return
        runtime = hass.data[DOMAIN][msg["entry_id"]]
        data = await hass.async_add_executor_job(runtime.inspect, msg["message_id"])
        connection.send_result(msg["id"], data)
    except Exception as exc: connection.send_error(msg["id"], "gmail_error", str(exc))

@websocket_api.websocket_command({vol.Required("type"): "pasevsu_gmail/digest", vol.Required("entry_id"): str,
    vol.Required("message_id"): str, vol.Optional("attachment_id"): str})
@websocket_api.async_response
async def ws_digest(hass, connection, msg):
    try:
        if not connection.user.is_admin:
            connection.send_error(msg["id"], "unauthorized", "Administrator required")
            return
        runtime = hass.data[DOMAIN][msg["entry_id"]]
        data = await hass.async_add_executor_job(runtime.digest, msg["message_id"], msg.get("attachment_id"))
        connection.send_result(msg["id"], data)
    except Exception as exc: connection.send_error(msg["id"], "gmail_error", str(exc))

def register(hass):
    websocket_api.async_register_command(hass, ws_list)
    websocket_api.async_register_command(hass, ws_labels)
    websocket_api.async_register_command(hass, ws_inspect)
    websocket_api.async_register_command(hass, ws_digest)
    websocket_api.async_register_command(hass, ws_status)

@websocket_api.websocket_command({vol.Required("type"): "pasevsu_gmail/status", vol.Required("entry_id"): str})
@websocket_api.async_response
async def ws_status(hass, connection, msg):
    if not connection.user.is_admin:
        connection.send_error(msg["id"], "unauthorized", "Administrator required")
        return
    runtime=hass.data[DOMAIN].get(msg["entry_id"])
    if runtime is None:
        connection.send_error(msg["id"],"not_found","Integration unavailable")
        return
    connection.send_result(msg["id"], {"new_count":runtime.new_count,"last_check":runtime.last_check,
       "last_new_mail":runtime.last_new_mail,"last_error":runtime.last_error,
       "last_result":runtime.last_result,"history_initialized":bool(runtime.history_id)})
