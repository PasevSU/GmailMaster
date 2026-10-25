"""Gmail event-aware polling: Gmail historyId is the change sensor."""
import logging
from datetime import timedelta, datetime, timezone
from googleapiclient.errors import HttpError
from homeassistant.helpers.event import async_track_time_interval
from homeassistant.helpers.storage import Store
from .const import DOMAIN
from .gmail_client import service_from_token, list_messages, list_labels, get_message, profile, history_since, list_recent_ids, get_thread
from .artifact_inspector import inspect_message, raw_digest, attachment_digest
from .rules_engine import load_rules, run_new_messages, evaluate_lifecycle
from . import websocket_api

_LOGGER = logging.getLogger(__name__)
PLATFORMS = ["sensor"]

class Runtime:
    def __init__(self,hass,entry):
        self.hass,self.entry=hass,entry
        self.store=Store(hass,1,f"{DOMAIN}_{entry.entry_id}_lifecycle")
        self.cursor_store=Store(hass,1,f"{DOMAIN}_{entry.entry_id}_cursor")
        self.state={};self.history_id=None;self.last_result={}
        self.new_count=0;self.last_check=None;self.last_new_mail=None;self.last_error=None
        self.sensor=None;self._running=False;self.recovery_required=False
    @property
    def settings(self): return {**self.entry.data,**self.entry.options}
    def _service(self): return service_from_token(self.settings["token_path"])
    def list_page(self,label,query,token):
        service=self._service(); result=list_messages(service,label,query,token)
        rows=[]
        for x in result.get("messages",[]):
            m=get_message(service,x["id"],"metadata")
            headers=m.get("payload",{}).get("headers",[])
            h=lambda name:next((a.get("value","") for a in headers if a.get("name","").lower()==name),"")
            rows.append({"id":m["id"],"thread_id":m.get("threadId"),"date":h("date"),
              "from":h("from"),"to":h("to"),"subject":h("subject"),
              "labels":m.get("labelIds",[]),"size":m.get("sizeEstimate",0)})
        return {"messages":rows,"next_page_token":result.get("nextPageToken")}
    def labels(self): return list_labels(self._service())
    def inspect(self,mid): return inspect_message(get_message(self._service(),mid,"full"))
    def thread(self,thread_id):
        return get_thread(self._service(),thread_id)
    def raw_details(self,mid):
        from .artifact_inspector import raw_message_details
        return raw_message_details(get_message(self._service(),mid,"raw"))
    def digest(self,mid,aid=None):
        service=self._service()
        return attachment_digest(service,mid,aid) if aid else raw_digest(get_message(service,mid,"raw"))
    def poll_sync(self):
        service=self._service()
        latest = str(profile(service)["historyId"])
        if self.history_id is None:
            return {"cursor":latest,"initialized":True,"new_ids":[]}
        if latest==self.history_id:
            return {"cursor":latest,"initialized":False,"new_ids":[]}
        try:
            cursor,ids=history_since(service,self.history_id)
        except HttpError as exc:
            if exc.resp.status==404:
                # Cursor expired: do not claim that no messages arrived.
                return {"cursor":self.history_id,"cursor_expired":True,"new_ids":[],"recovery_required":True}
            raise
        return {"cursor":cursor,"new_ids":ids}
    def process_sync(self,ids,life_only=False):
        service=self._service();rules=load_rules(self.settings["rules_path"])
        outcome={"new":0,"matched":0,"modified":0,"dry_run":self.settings.get("dry_run",True)}
        if ids and not life_only:
            outcome=run_new_messages(service,rules,self.state,ids,self.settings.get("dry_run",True))
        if life_only:
            outcome.update(evaluate_lifecycle(service,rules,self.state,self.settings.get("dry_run",True)))
        return outcome
    async def poll(self,_now=None):
        if self._running:return
        self._running=True
        try:
            result=await self.hass.async_add_executor_job(self.poll_sync)
            ids=result.get("new_ids",[])
            self.new_count=len(ids)
            self.last_check=datetime.now(timezone.utc).isoformat()
            self.recovery_required=bool(result.get("recovery_required"))
            if self.recovery_required:
                self.last_error="Gmail history cursor expired; manual reconciliation required. Cursor preserved."
                return
            self.last_error=None
            if ids:
                # Process before advancing cursor. Failed processing is retried next poll.
                self.last_result=await self.hass.async_add_executor_job(self.process_sync,ids)
                self.last_new_mail=self.last_check
                if not self.settings.get("dry_run",True): await self.store.async_save(self.state)
            self.history_id=result["cursor"]
            await self.cursor_store.async_save({"history_id":self.history_id})
            if ids:self.hass.bus.async_fire(f"{DOMAIN}_new_mail",{"entry_id":self.entry.entry_id,"count":len(ids)})
        except Exception as exc:
            self.last_error=str(exc)
            _LOGGER.exception("Gmail history polling failed")
        finally:
            if self.sensor:self.sensor.async_write_ha_state()
            self._running=False
    async def recover(self):
        """Explicit bounded backfill: never silently reset an expired cursor."""
        if self._running: raise RuntimeError("Gmail monitor busy")
        self._running=True
        try:
            def collect():
                service=self._service()
                before=str(profile(service)["historyId"])
                ids=list_recent_ids(service)
                return before,ids
            before,ids=await self.hass.async_add_executor_job(collect)
            self.last_result=await self.hass.async_add_executor_job(self.process_sync,ids)
            if not self.settings.get("dry_run",True):await self.store.async_save(self.state)
            self.history_id=before
            await self.cursor_store.async_save({"history_id":before})
            self.recovery_required=False
            self.last_error=None
            return {"reconciled":len(ids),"cursor":before,"result":self.last_result}
        finally:
            self._running=False
            if self.sensor:self.sensor.async_write_ha_state()
    async def daily_lifecycle(self,_now=None):
        if self._running:return
        self._running=True
        try:
            self.last_result=await self.hass.async_add_executor_job(self.process_sync,[],True)
            if not self.settings.get("dry_run",True):await self.store.async_save(self.state)
        except Exception as exc:
            self.last_error=str(exc);_LOGGER.exception("Lifecycle check failed")
        finally:
            if self.sensor:self.sensor.async_write_ha_state()
            self._running=False

async def async_setup(hass,config):
    hass.data.setdefault(DOMAIN,{})
    websocket_api.register(hass)
    return True

async def async_setup_entry(hass,entry):
    runtime=Runtime(hass,entry)
    runtime.state=await runtime.store.async_load() or {}
    cursor=await runtime.cursor_store.async_load() or {}
    runtime.history_id=cursor.get("history_id")
    hass.data.setdefault(DOMAIN,{})[entry.entry_id]=runtime
    await hass.config_entries.async_forward_entry_setups(entry,PLATFORMS)
    async def on_change(hass,entry):await hass.config_entries.async_reload(entry.entry_id)
    entry.async_on_unload(entry.add_update_listener(on_change))
    entry.async_on_unload(async_track_time_interval(hass,runtime.poll,timedelta(minutes=runtime.settings["interval_minutes"])))
    entry.async_on_unload(async_track_time_interval(hass,runtime.daily_lifecycle,timedelta(hours=24)))
    entry.async_create_background_task(hass, runtime.poll(), "Initial Gmail history check")
    return True

async def async_unload_entry(hass,entry):
    await hass.config_entries.async_unload_platforms(entry,PLATFORMS)
    hass.data[DOMAIN].pop(entry.entry_id,None)
    return True
