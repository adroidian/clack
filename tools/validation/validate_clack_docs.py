#!/usr/bin/env python3
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / 'specs' / 'fixtures'
CAPS = {"discover","store-only","direct-send","wake","reply","tools","admin"}
PRIORITIES = {"low","normal","high","urgent"}
STAGES = {"accepted","policy-checked","routed","stored","delivered","woke","responded","failed"}
HARNESS_TYPES = {"hermes","claude-code","openclaw","unknown"}
TRUST_CLASSES = {"core-private","peer-aaron","cross-human","unknown"}
ROUTE_KINDS = {
    "local-http","clack-http","filedrop","store-only","hermes-wake",
    "openclaw-hook","relay","lakebed-dead-drop","tailscale-http",
    "p2p-libp2p","p2p-iroh","unknown"
}
ROUTE_STATUSES = {"active","stale","unreachable"}
HEARTBEAT_PROOF_KINDS = {"heartbeat","delivery","wake-output","health-check"}
SECRET_FIELD_NAMES = {"token","secret","password","apiKey","api_key","anthropic_token","hooksToken","publicKey"}

def load(name):
    return json.loads((FIXTURES / name).read_text(encoding='utf-8'))

def is_agent_uri(v):
    return isinstance(v, str) and v.startswith('agent://') and len(v) > len('agent://')

def validate_envelope(e):
    errors=[]
    required=['clackVersion','id','from','to','topic','priority','createdAt','ttlSeconds','capabilityRequested','idempotencyKey','payload']
    for k in required:
        if k not in e: errors.append(f'missing {k}')
    if e.get('clackVersion') != '2.0-draft': errors.append('bad clackVersion')
    if not is_agent_uri(e.get('from')): errors.append('from must be agent://')
    if not is_agent_uri(e.get('to')): errors.append('to must be agent://')
    if e.get('priority') not in PRIORITIES: errors.append('bad priority')
    if e.get('capabilityRequested') not in CAPS: errors.append('bad capabilityRequested')
    if not isinstance(e.get('ttlSeconds'), int) or e.get('ttlSeconds', 0) <= 0: errors.append('ttlSeconds must be positive integer')
    payload=e.get('payload')
    if not isinstance(payload, dict): errors.append('payload must be object')
    else:
        for k in ['type','contentType','body']:
            if k not in payload: errors.append(f'payload missing {k}')
    return errors

def validate_receipt(r):
    errors=[]
    required=['receiptVersion','receiptId','messageId','from','to','stage','ok','reason','at','proof']
    for k in required:
        if k not in r: errors.append(f'missing {k}')
    if r.get('receiptVersion') != '1.0-draft': errors.append('bad receiptVersion')
    if not is_agent_uri(r.get('from')): errors.append('from must be agent://')
    if not is_agent_uri(r.get('to')): errors.append('to must be agent://')
    if r.get('stage') not in STAGES: errors.append('bad stage')
    if not isinstance(r.get('ok'), bool): errors.append('ok must be boolean')
    if r.get('stage') == 'failed' and r.get('ok') is not False: errors.append('failed stage must ok=false')
    if r.get('ok') is False and not r.get('reason'): errors.append('failed receipt needs reason')
    route=r.get('route')
    if route is not None:
        if not isinstance(route, dict):
            errors.append('route must be object when present')
        elif route.get('kind') not in ROUTE_KINDS:
            errors.append('route.kind must be known route kind')
    proof=r.get('proof')
    if not isinstance(proof, dict): errors.append('proof must be object')
    else:
        if r.get('stage') == 'woke' and not (proof.get('wakeLog') or proof.get('wakeJobId')):
            errors.append('woke receipt requires wakeLog or wakeJobId')
        if r.get('stage') == 'stored' and not (proof.get('inboxPath') or proof.get('objectId') or proof.get('deadDropId')):
            errors.append('stored receipt requires storage proof')
    return errors

def _check_iso8601(v):
    if not isinstance(v, str): return False
    import re
    return bool(re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', v))

def validate_agent_identity(a):
    errors=[]
    required=['cnsVersion','agentId','owner','name','description','harnessType','host','registeredAt','expiresAt']
    for k in required:
        if k not in a: errors.append(f'missing {k}')
    if a.get('cnsVersion') != '1.0-draft': errors.append('bad cnsVersion')
    if not is_agent_uri(a.get('agentId')): errors.append('agentId must be agent://')
    owner=a.get('owner','')
    if not (isinstance(owner,str) and owner.startswith('human://') and len(owner)>len('human://')): errors.append('owner must be human://')
    if a.get('harnessType') not in HARNESS_TYPES: errors.append('bad harnessType')
    if 'trustClass' in a and a['trustClass'] not in TRUST_CLASSES: errors.append('bad trustClass')
    if a.get('harnessType') == 'hermes' and not a.get('hermesProfile'): errors.append('hermes harnessType requires hermesProfile')
    reg=a.get('registeredAt',''); exp=a.get('expiresAt','')
    if not _check_iso8601(reg): errors.append('registeredAt must be ISO-8601')
    if not _check_iso8601(exp): errors.append('expiresAt must be ISO-8601')
    if _check_iso8601(reg) and _check_iso8601(exp) and exp <= reg: errors.append('expiresAt must be after registeredAt')
    for bad_key in SECRET_FIELD_NAMES:
        if bad_key in a: errors.append(f'secret field "{bad_key}" must not appear in identity doc')
    name=a.get('name',''); agent_id=a.get('agentId','')
    if isinstance(name,str) and isinstance(agent_id,str) and name and agent_id.startswith('agent://'):
        id_name = agent_id[len('agent://'):].split('.')[0]
        if name != id_name: errors.append('name must match name component of agentId')
    return errors

def validate_route_record(r):
    errors=[]
    required=['routeRecordVersion','routeId','agentId','kind','status','priority','createdAt','expiresAt']
    for k in required:
        if k not in r: errors.append(f'missing {k}')
    if r.get('routeRecordVersion') != '1.0-draft': errors.append('bad routeRecordVersion')
    if not is_agent_uri(r.get('agentId')): errors.append('agentId must be agent://')
    if r.get('kind') not in ROUTE_KINDS: errors.append('bad kind')
    if r.get('status') not in ROUTE_STATUSES: errors.append('bad status')
    pri=r.get('priority')
    if not isinstance(pri,int) or pri <= 0: errors.append('priority must be positive integer')
    created=r.get('createdAt',''); expires=r.get('expiresAt','')
    if not _check_iso8601(created): errors.append('createdAt must be ISO-8601')
    if not _check_iso8601(expires): errors.append('expiresAt must be ISO-8601')
    if _check_iso8601(created) and _check_iso8601(expires) and expires <= created: errors.append('expiresAt must be after createdAt')
    store_only_kinds = {'filedrop','store-only','lakebed-dead-drop'}
    proof_kind=r.get('proofKind','')
    if r.get('kind') in store_only_kinds and proof_kind in ('wake-output',):
        errors.append('store-only route kinds cannot claim wake-output proof')
    return errors

def validate_capability_grant(g):
    errors=[]
    required=['grantVersion','grantId','subject','target','capabilities','createdAt','expiresAt']
    for k in required:
        if k not in g: errors.append(f'missing {k}')
    if g.get('grantVersion') != '1.0-draft': errors.append('bad grantVersion')
    if not is_agent_uri(g.get('subject')): errors.append('subject must be agent://')
    if not is_agent_uri(g.get('target')): errors.append('target must be agent://')
    caps=g.get('capabilities')
    if not isinstance(caps, list) or len(caps) == 0: errors.append('capabilities must be non-empty array')
    else:
        for c in caps:
            if c not in CAPS: errors.append(f'unknown capability: {c}')
        if ('tools' in caps or 'admin' in caps):
            approved_by=g.get('ownerApprovedBy','')
            if not (isinstance(approved_by,str) and approved_by.startswith('human://') and len(approved_by)>len('human://')):
                errors.append('tools/admin capabilities require ownerApprovedBy human://')
    created=g.get('createdAt',''); expires=g.get('expiresAt','')
    if not _check_iso8601(created): errors.append('createdAt must be ISO-8601')
    if not _check_iso8601(expires): errors.append('expiresAt must be ISO-8601')
    if _check_iso8601(created) and _check_iso8601(expires) and expires <= created: errors.append('expiresAt must be after createdAt')
    for bad_key in SECRET_FIELD_NAMES:
        if bad_key in g: errors.append(f'secret field "{bad_key}" must not appear in grant')
    return errors

def validate_heartbeat(h):
    errors=[]
    required=['heartbeatVersion','agentId','routeId','proofKind','proofAt','ttlSeconds']
    for k in required:
        if k not in h: errors.append(f'missing {k}')
    if h.get('heartbeatVersion') != '1.0-draft': errors.append('bad heartbeatVersion')
    if not is_agent_uri(h.get('agentId')): errors.append('agentId must be agent://')
    if not isinstance(h.get('routeId'), str) or not h.get('routeId'):
        errors.append('routeId must be non-empty string')
    if h.get('proofKind') not in HEARTBEAT_PROOF_KINDS: errors.append('bad proofKind')
    if not _check_iso8601(h.get('proofAt','')): errors.append('proofAt must be ISO-8601')
    if not isinstance(h.get('ttlSeconds'), int) or h.get('ttlSeconds', 0) < 60:
        errors.append('ttlSeconds must be integer >= 60')
    for bad_key in SECRET_FIELD_NAMES:
        if bad_key in h: errors.append(f'secret field "{bad_key}" must not appear in heartbeat')
    return errors

def main():
    checks = [
        ('valid-envelope.json', validate_envelope, True),
        ('invalid-envelope.json', validate_envelope, False),
        ('valid-receipt.json', validate_receipt, True),
        ('invalid-receipt.json', validate_receipt, False),
        ('valid-agent-identity.json', validate_agent_identity, True),
        ('invalid-agent-identity.json', validate_agent_identity, False),
        ('valid-route-record.json', validate_route_record, True),
        ('invalid-route-record.json', validate_route_record, False),
        ('valid-capability-grant.json', validate_capability_grant, True),
        ('invalid-capability-grant.json', validate_capability_grant, False),
        ('valid-heartbeat.json', validate_heartbeat, True),
        ('invalid-heartbeat.json', validate_heartbeat, False),
    ]
    ok=True
    for name, fn, should_pass in checks:
        errors=fn(load(name))
        passed=not errors
        print(f'{name}: {"PASS" if passed else "FAIL"}')
        if errors:
            for e in errors: print(f'  - {e}')
        if passed != should_pass:
            ok=False
            print(f'  EXPECTED {should_pass}, got {passed}')
    return 0 if ok else 1

if __name__ == '__main__':
    raise SystemExit(main())
