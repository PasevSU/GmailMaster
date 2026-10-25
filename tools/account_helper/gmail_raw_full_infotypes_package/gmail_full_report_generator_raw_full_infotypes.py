#!/usr/bin/env python3
"""Gmail API full-message headers report. Requires google-api-python-client, google-auth-oauthlib."""
import argparse, base64, datetime as dt, html, json, os, pathlib, sys, time, hashlib, re
from email import policy
from email.parser import BytesParser
from email.utils import parsedate_to_datetime

SCOPES=['https://www.googleapis.com/auth/gmail.readonly']
def service_for(credentials, token):
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from google.auth.transport.requests import Request
    from googleapiclient.discovery import build
    creds=Credentials.from_authorized_user_file(str(token),SCOPES) if token.exists() else None
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
    if not creds or not creds.valid:
        if not credentials.exists(): raise FileNotFoundError(f'Missing Google OAuth desktop credentials: {credentials}')
        creds=InstalledAppFlow.from_client_secrets_file(str(credentials),SCOPES).run_local_server(port=0)
    token.parent.mkdir(parents=True,exist_ok=True)
    token.write_text(creds.to_json(),encoding='utf-8')
    try: os.chmod(token,0o600)
    except OSError: pass
    return build('gmail','v1',credentials=creds,cache_discovery=False)

def call(request,tries=6):
    from googleapiclient.errors import HttpError
    for attempt in range(tries):
        try: return request.execute()
        except HttpError as exc:
            if exc.resp.status not in (429,500,502,503,504) or attempt==tries-1: raise
            time.sleep(min(2**attempt,30))

def build_query(args):
    parts=[]
    if args.query: parts.append(args.query)
    if args.email:
        addr=args.email.strip()
        if any(x in addr for x in ' {}()\r\n"'): raise ValueError('Email address contains invalid characters')
        parts.append('{from:'+addr+' to:'+addr+' cc:'+addr+' bcc:'+addr+'}')
    return ' '.join(parts)

def collect(api, query, include_spam_trash):
    ids=[]; token=None
    while True:
        kwargs=dict(userId='me',maxResults=500,includeSpamTrash=include_spam_trash)
        if query: kwargs['q']=query
        if token: kwargs['pageToken']=token
        page=call(api.users().messages().list(**kwargs))
        ids.extend(x['id'] for x in page.get('messages',[]))
        token=page.get('nextPageToken')
        print(f'Found {len(ids)} messages...',file=sys.stderr)
        if not token: break
    return list(dict.fromkeys(ids))

def timestamp(message,headers):
    try: return int(message['internalDate'])
    except (KeyError,ValueError,TypeError):
        for h in headers:
            if h.get('name','').lower()=='date':
                try: return int(parsedate_to_datetime(h['value']).timestamp()*1000)
                except (ValueError,TypeError,OverflowError): pass
    return 0

def fetch_all(api,ids,mode,raw_dir):
    messages=[];errors=[]
    if mode in ('raw','both'): raw_dir.mkdir(parents=True,exist_ok=True)
    for i,msgid in enumerate(ids,1):
        try:
            full=None;raw_bytes=None
            if mode in ('full','both'):
                full=call(api.users().messages().get(userId='me',id=msgid,format='full'))
            if mode in ('raw','both'):
                obj=call(api.users().messages().get(userId='me',id=msgid,format='raw'))
                encoded=obj['raw'];raw_bytes=base64.urlsafe_b64decode(encoded+'='*(-len(encoded)%4))
                (raw_dir/(msgid+'.eml')).write_bytes(raw_bytes)
            if raw_bytes is not None:
                parsed=BytesParser(policy=policy.default).parsebytes(raw_bytes)
                # For the visual header report, parse the raw header block preserving order,
                # repeated fields and folded line breaks; no header reordering.
                match=re.search(br'\r?\n\r?\n',raw_bytes)
                header_bytes=raw_bytes[:match.start()] if match else raw_bytes
                headers=[]
                for line in re.split(br'\r?\n',header_bytes):
                    if line[:1] in (b' ',b'\t') and headers:
                        headers[-1]['value']+='\n'+line.decode('utf-8','replace')
                    elif b':' in line:
                        name,value=line.split(b':',1)
                        headers.append({'name':name.decode('ascii','replace'),'value':value.decode('utf-8','replace').lstrip(' \t')})
                objmeta=full if full is not None else obj
            else:
                headers=full.get('payload',{}).get('headers',[])
                objmeta=full
            messages.append({'id':msgid,'threadId':objmeta.get('threadId',''),
                'timestamp':timestamp(objmeta,headers),'headers':headers,
                'snippet':full.get('snippet','') if full else '',
                'labelIds':objmeta.get('labelIds',[]),
                'raw_sha256':hashlib.sha256(raw_bytes).hexdigest() if raw_bytes is not None else None,
                'raw_file':str(raw_dir/(msgid+'.eml')) if raw_bytes is not None else None,
                'full_payload':full if mode in ('full','both') else None})
        except Exception as exc:errors.append({'id':msgid,'error':str(exc)})
        if i%50==0 or i==len(ids):print(f'Fetched {i}/{len(ids)}; failures={len(errors)}',file=sys.stderr)
    messages.sort(key=lambda m:(-m['timestamp'],m['id']))
    return messages,errors

CSS='''
:root{color-scheme:dark;font-family:Segoe UI,Arial,sans-serif}*{box-sizing:border-box}body{margin:0;background:#101827;color:#e9eef8}main{max-width:1250px;margin:auto;padding:24px}header{position:sticky;top:0;background:#172337;padding:14px;z-index:3;border-bottom:1px solid #43516a}header .controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center}input,button{font:inherit;padding:10px;border-radius:6px;border:1px solid #71809a}input{flex:1;min-width:220px;background:#fff;color:#111}button{background:#2666c6;color:#fff;cursor:pointer}.message{width:100%;margin:0 0 14px;background:#1b293d;border:1px solid #41516b;border-radius:8px;overflow:hidden;break-inside:auto}.summary{padding:14px;cursor:pointer;display:grid;grid-template-columns:150px minmax(0,1fr);gap:8px}.subject{font-weight:700;overflow-wrap:anywhere}.meta{font-size:12px;color:#bdd1f3;overflow-wrap:anywhere}.details{padding:0 14px 14px}table{width:100%;table-layout:fixed;border-collapse:collapse}th,td{border:1px solid #45536b;padding:8px;vertical-align:top;text-align:left;overflow-wrap:anywhere;word-break:break-word}th{width:22%;background:#243952;color:#fff}td{white-space:pre-wrap}h1{margin:0 0 10px}.count{padding:8px 0;color:#bdd1f3}code{overflow-wrap:anywhere}.hidden{display:none!important}.exclude-btn{background:#703344;font-size:12px;padding:6px 10px;margin:7px 0}.excluded-note{color:#f8b9c1}
@page{size:A4;margin:14mm 12mm}@media print{*{color-adjust:exact;-webkit-print-color-adjust:exact}body{background:white;color:black}header,.screen-only{display:none!important}main{max-width:none;padding:0}.message{background:white;color:black;border:1px solid #999;border-radius:0;margin:0 0 7mm;break-inside:auto}.summary{background:#f1f4f8;color:black;padding:7px}.meta{color:#333}.details{display:block!important;padding:0 7px 7px}th{background:#eee!important;color:#111!important}th,td{border-color:#aaa;font-size:8pt;padding:4px}tr{break-inside:avoid}a{color:black}}
'''
JS='''
const items=[...document.querySelectorAll('.message')];
const search=document.getElementById('search'),count=document.getElementById('count');const excludedTitles=new Set();
function filter(){const q=search.value.trim().toLocaleLowerCase();let n=0;for(const el of items){const ok=(!q||el.dataset.search.includes(q))&&!excludedTitles.has(el.dataset.subject);el.classList.toggle('hidden',!ok);if(ok)n++}count.textContent=`Показани: ${n} / ${items.length}`}
search.addEventListener('input',filter);
function excludeSubject(btn){const title=btn.closest('.message').dataset.subject;if(!confirm('Скриване на всички имейли с тази точна тема?\\n'+title))return;excludedTitles.add(title);filter();}
function exportExclusions(){const lines=[...excludedTitles].map(x=>'  - '+JSON.stringify(x));const text='exclude_subjects:\\n'+lines.join('\\n')+'\\n';const blob=new Blob([text],{type:'text/yaml;charset=utf-8'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='excluded_subjects.yaml';a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000)}
filter();
function printReport(){const shown=items.filter(x=>!x.classList.contains('hidden'));const old=shown.map(x=>x.querySelector('details').open);shown.forEach(x=>x.querySelector('details').open=true);window.print();setTimeout(()=>shown.forEach((x,i)=>x.querySelector('details').open=old[i]),1500)}
'''
def render(messages,errors,query,catalog=None):
    blocks=[]
    for idx,m in enumerate(messages,1):
        headers=m['headers']
        def value(key): return next((h.get('value','') for h in headers if h.get('name','').lower()==key), '')
        date=dt.datetime.fromtimestamp(m['timestamp']/1000,dt.timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC') if m['timestamp'] else 'Unknown'
        subject=value('subject') or '(без тема)'
        rows=''.join('<tr><th>'+html.escape(h.get('name',''))+'</th><td>'+html.escape(h.get('value',''))+'</td></tr>' for h in headers)
        # Search only metadata to avoid massive repeated strings in DOM.
        search=' '.join([subject,value('from'),value('to'),value('cc'),value('bcc'),value('message-id'),date]).lower()
        blocks.append(f'<article class="message" data-search="{html.escape(search,quote=True)}" data-subject="{html.escape(subject.strip().casefold(),quote=True)}"><details><summary class="summary"><span>#{idx} · {html.escape(date)}</span><span><span class="subject">{html.escape(subject)}</span><br><span class="meta">От: {html.escape(value("from"))} · До: {html.escape(value("to"))}</span></span></summary><div class="details"><button class="exclude-btn screen-only" type="button" onclick="excludeSubject(this)">Скрий всички с тази тема</button><p class="meta">Gmail ID: <code>{html.escape(m["id"])}</code> · Thread: <code>{html.escape(m["threadId"])}</code></p><table><tbody>{rows}</tbody></table></div></details></article>')
    if catalog:
        catalog_json=json.dumps(catalog,ensure_ascii=False).replace('<','\\u003c')
        blocks.insert(0, '<section class="screen-only" style="padding:12px;border:1px solid #456;margin-bottom:18px"><h2>Google Sensitive Data Protection — infoType каталог</h2><p>Каталогът е справочен: не се извършва автоматично DLP сканиране.</p><input id="infotype-search" placeholder="Търси infoType или чувствителност" oninput="filterInfoTypes()"><div id="infotype-count"></div><div style="max-height:270px;overflow:auto"><table id="infotype-table"><thead><tr><th>InfoType</th><th>Sensitivity</th></tr></thead><tbody>'+''.join('<tr><td>'+html.escape(k)+'</td><td>'+html.escape(v)+'</td></tr>' for k,v in catalog.get('sensitivity',{}).items())+'</tbody></table></div><details><summary>Групи infoTypes</summary><pre style="white-space:pre-wrap">'+html.escape(json.dumps(catalog.get('groups',{}),ensure_ascii=False,indent=2))+'</pre></details></section>')
    error_note=f'<p class="screen-only">Неуспешно извлечени: {len(errors)}. Проверете JSON журнала.</p>' if errors else ''
    return '<!doctype html><html lang="bg"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gmail — пълен отчет</title><style>'+CSS+'</style></head><body><header><div class="controls"><input id="search" type="search" placeholder="Филтър: адрес, тема, Message-ID, дата" aria-label="Филтър"><button onclick="printReport()">Печат / PDF</button><button onclick="exportExclusions()">Изтегли изключените теми (YAML)</button></div><div id="count" class="count"></div></header><main><h1>Gmail — пълен отчет</h1><p>Gmail API филтър: <code>'+html.escape(query or '(всички достъпни съобщения)')+'</code>. Подредба: най-новите първи. Показани са заглавките от Gmail API.</p>'+error_note+''.join(blocks)+'</main><script>'+JS+'''\nfunction filterInfoTypes(){const q=document.getElementById('infotype-search').value.toLowerCase();const rows=[...document.querySelectorAll('#infotype-table tbody tr')];let n=0;for(const r of rows){const show=r.textContent.toLowerCase().includes(q);r.style.display=show?'':'none';if(show)n++}document.getElementById('infotype-count').textContent=n+' / '+rows.length;}if(document.getElementById('infotype-search'))filterInfoTypes();\n'''+ '</script></body></html>'

def load_excluded_subjects(path):
    """Read exact subject exclusions from filters.yaml without requiring PyYAML."""
    if not path or not path.exists():
        return []
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("Install PyYAML: pip install pyyaml") from exc
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    values = data.get("exclude_subjects", [])
    if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
        raise ValueError("exclude_subjects must be a YAML list of strings")
    return [v.strip().casefold() for v in values if v.strip()]

def subject_of(message):
    return next((h.get("value", "") for h in message["headers"]
                 if h.get("name", "").casefold() == "subject"), "")

def main():
    p=argparse.ArgumentParser(description='Fetch all matching Gmail messages, newest first, with printable HTML')
    p.add_argument('--credentials',type=pathlib.Path,default=pathlib.Path('credentials.json'))
    p.add_argument('--token',type=pathlib.Path,default=pathlib.Path('gmail_token.json'))
    p.add_argument('--email',help='Include messages where this address is sender, To, Cc or Bcc')
    p.add_argument('--query',default='',help='Additional Gmail search expression')
    p.add_argument('--include-spam-trash',action='store_true')
    p.add_argument('--output',type=pathlib.Path,default=pathlib.Path('gmail_full_report.html'))
    p.add_argument('--mode',choices=('raw','full','both'),default='both',help='Gmail extraction mode; both is recommended')
    p.add_argument('--raw-dir',type=pathlib.Path,default=pathlib.Path('gmail_raw_eml'))
    p.add_argument('--infotypes-catalog',type=pathlib.Path,default=pathlib.Path(__file__).with_name('google_infotypes_catalog.json'))
    p.add_argument('--filters', type=pathlib.Path, default=pathlib.Path('filters.yaml'),
                   help='YAML file containing exclude_subjects')
    args=p.parse_args()
    query=build_query(args)
    if args.filters.exists():
        import yaml
        cfg=yaml.safe_load(args.filters.read_text(encoding='utf-8')) or {}
        opts=cfg.get('gmail',{})
        if isinstance(opts,dict):
            args.mode=opts.get('mode',args.mode)
            if args.mode not in ('raw','full','both'):raise ValueError('gmail.mode must be raw, full or both')
            if opts.get('include_spam_trash') is True:args.include_spam_trash=True
            if opts.get('raw_dir'):args.raw_dir=pathlib.Path(opts['raw_dir'])
    api=service_for(args.credentials,args.token)
    ids=collect(api,query,args.include_spam_trash)
    messages,errors=fetch_all(api,ids,args.mode,args.raw_dir)
    excluded=load_excluded_subjects(args.filters)
    original_count=len(messages)
    messages=[m for m in messages if subject_of(m).strip().casefold() not in excluded]
    print(f'Excluded {original_count-len(messages)} messages by exact subject.',file=sys.stderr)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    catalog=json.loads(args.infotypes_catalog.read_text(encoding='utf-8')) if args.infotypes_catalog.exists() else None
    args.output.write_text(render(messages,errors,query,catalog),encoding='utf-8')
    # Full API payload is stored separately; the original raw EML is never reconstructed from it.
    if args.mode in ('full','both'):
        full_dir=args.output.parent/'gmail_full_json';full_dir.mkdir(parents=True,exist_ok=True)
        for m in messages:
            if m['full_payload'] is not None:
                (full_dir/(m['id']+'.json')).write_text(json.dumps(m['full_payload'],ensure_ascii=False,indent=2),encoding='utf-8')
    manifest=[{'id':m['id'],'timestamp':m['timestamp'],'raw_sha256':m['raw_sha256'],'raw_file':m['raw_file']} for m in messages]
    args.output.with_suffix('.manifest.json').write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding='utf-8')
    log=args.output.with_suffix('.fetch_log.json')
    log.write_text(json.dumps({'query':query,'listed':len(ids),'fetched':len(messages),'mode':args.mode,'excluded_by_subject':original_count-len(messages),'errors':errors},indent=2,ensure_ascii=False),encoding='utf-8')
    print(f'Wrote {args.output} ({len(messages)} emails). Log: {log}')
    if errors: sys.exit(2)
if __name__=='__main__': main()
