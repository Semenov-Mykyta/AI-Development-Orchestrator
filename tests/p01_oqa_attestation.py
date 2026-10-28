"""D5-only external deployment/observer attestation. No deployment or P01 implementation.

An independently provisioned OQ-09/A inspector signs *live* findings about the
actual signer deployment, ALL signing interfaces, and a read-only observation
channel. Collector output and ordinary runner HMAC are never an authority for
these claims. No inspector / no observer / missing receipt => NOT_CHECKED.
"""
from __future__ import annotations
import hashlib
import base64
import binascii
import json
import os
import secrets
import socket
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key


class OQAttestationError(AssertionError):
    """Evidence absent or untrusted: must be mapped to NOT_CHECKED by harness."""


def _deny(msg: str):
    raise OQAttestationError('NOT_CHECKED: ' + msg)


def _canon(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _protected(path: Path, kind: str):
    """Reject writable ancestors, symlinks and non-root-controlled trust files."""
    if not path.is_absolute() or path.is_symlink():
        _deny('unapproved external attestation path')
    try:
        for parent in (path.parent, *path.parent.parents):
            p = parent.lstat()
            if not stat.S_ISDIR(p.st_mode) or p.st_uid != 0 or p.st_mode & 0o022:
                _deny('external attestation directory not root controlled')
        s = path.lstat()
        ok = stat.S_ISREG(s.st_mode) if kind == 'file' else stat.S_ISSOCK(s.st_mode)
        if not ok or s.st_uid != 0 or s.st_mode & 0o022:
            _deny('external attestation service/key not root controlled')
    except OSError as exc:
        raise OQAttestationError('NOT_CHECKED: external attestation service missing') from exc


def _protected_observer_socket(path: Path, collector_gid: int):
    """Root-owned read-only RPC socket; group collector may connect, SUT may not.

    Socket connect permission alone does NOT make an RPC read-only: signed
    broker protocol and independent write-denial attestation are still required.
    """
    if not path.is_absolute() or path.is_symlink():
        _deny('observer socket path not pinned')
    try:
        for parent in (path.parent,*path.parent.parents):
            st=parent.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
                _deny('observer socket directory untrusted')
        st=path.lstat()
        if (not stat.S_ISSOCK(st.st_mode) or st.st_uid!=0 or st.st_gid!=collector_gid or
                st.st_mode & 0o007 or st.st_mode & 0o077 != 0o060):
            _deny('observer socket not root-controlled collector-group only')
    except OSError as exc:
        raise OQAttestationError('NOT_CHECKED: read-only observer socket absent') from exc


def _pinned_key(path: str, digest: str) -> Ed25519PublicKey:
    p = Path(path)
    _protected(p, 'file')
    try:
        buf = p.read_bytes()
        key = load_pem_public_key(buf)
    except (OSError, ValueError, TypeError) as exc:
        raise OQAttestationError('NOT_CHECKED: external inspector key unreadable') from exc
    if _sha(buf) != digest or not isinstance(key, Ed25519PublicKey):
        _deny('external inspector key fingerprint/type mismatch')
    return key


def validate_oqa_policy(policy: dict) -> bool:
    """Called after authenticating the *owner signature* on this whole policy."""
    need = ('oqa_attester_id','oqa_attester_public_key_path',
            'oqa_attester_public_key_sha256','oqa_attester_socket_path',
            'oqa_monitor_deployment_sha256','oqa_observer_deployment_sha256',
            'readonly_observer_id','readonly_observer_public_key_path',
            'readonly_observer_public_key_sha256','readonly_observer_socket_path',
            'readonly_observer_protocol','readonly_observer_sources',
            'oqa_kernel_audit_id','oqa_kernel_audit_public_key_path',
            'oqa_kernel_audit_public_key_sha256','oqa_kernel_audit_deployment_sha256')
    if not isinstance(policy, dict) or any(k not in policy for k in need):
        _deny('owner signed OQ-09/A deployment and observer contract missing')
    for name in ('oqa_attester_id','readonly_observer_id','oqa_kernel_audit_id'):
        if not isinstance(policy[name],str) or not policy[name]:
            _deny('missing owner-pinned independent service identity')
    for name in ('oqa_attester_public_key_path','oqa_attester_socket_path',
                 'readonly_observer_public_key_path','readonly_observer_socket_path',
                 'oqa_kernel_audit_public_key_path'):
        if not isinstance(policy[name],str) or not Path(policy[name]).is_absolute():
            _deny('unapproved external service path')
    for name in ('oqa_attester_public_key_sha256','oqa_monitor_deployment_sha256',
                 'oqa_observer_deployment_sha256','readonly_observer_public_key_sha256',
                 'oqa_kernel_audit_public_key_sha256','oqa_kernel_audit_deployment_sha256'):
        val=policy[name]
        if not isinstance(val,str) or len(val)!=64 or any(c not in '0123456789abcdef' for c in val):
            _deny('invalid signed deployment/public-key digest')
    if len({policy['oqa_attester_public_key_sha256'],
            policy['readonly_observer_public_key_sha256'],
            policy.get('kernel_monitor_public_key_sha256'),
            policy['oqa_kernel_audit_public_key_sha256']})!=4:
        _deny('independent monitor/observer/attester authorities must use different keys')
    if (policy['readonly_observer_protocol']!='aio.p01.readonly_snapshot.v1' or
            not isinstance(policy['readonly_observer_sources'],list) or
            not policy['readonly_observer_sources'] or
            not all(isinstance(v,str) and v for v in policy['readonly_observer_sources']) or
            len(policy['readonly_observer_sources'])!=len(set(policy['readonly_observer_sources'])) or
            'execve_trace' in policy['readonly_observer_sources']):
        _deny('approved read-only observation source plan invalid')
    return True


def _receive_attester(socket_path: Path, request: dict) -> dict:
    _protected(socket_path,'socket')
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(str(socket_path))
            sock.sendall(_canon(request)+b'\n')
            data=bytearray()
            while not data.endswith(b'\n'):
                part=sock.recv(4096)
                if not part or len(data)+len(part)>65536:
                    _deny('independent attestation response unavailable')
                data.extend(part)
        parsed=json.loads(data)
    except (OSError,ValueError,TypeError) as exc:
        raise OQAttestationError('NOT_CHECKED: independent OQ-09/A attester unavailable') from exc
    if not isinstance(parsed,dict):
        _deny('external attestation response invalid')
    return parsed


def _verify_raw_os_probe_artifact(obj: dict, digest: str, *, request: dict,
                                  deployment_sha: str, target: str,
                                  kind: str, expected_probes: tuple[tuple[str,str,str], ...],
                                  issued_monotonic_ns: int):
    """Verify actual signed primary probe BYTES, not a 64-character claim.

    The trusted attester embeds the exact syscall witness bytes in its detached
    Ed25519-signed receipt. An external OQ-09/A audit must independently check
    their OS origin; signature+hash alone does not prove the syscalls ran.
    """
    if not isinstance(obj,dict) or set(obj)!= {'os_probe_bytes_b64'}:
        _deny('primary OS probe artifact missing')
    if (not isinstance(digest,str) or len(digest)!=64 or
            any(ch not in '0123456789abcdef' for ch in digest)):
        _deny('primary OS probe digest not hexadecimal SHA-256')
    try:
        data=base64.b64decode(obj['os_probe_bytes_b64'],validate=True)
        if len(data)>32768 or _sha(data)!=digest:
            _deny('primary OS probe bytes mismatch signed digest')
        decoded=json.loads(data)
    except (ValueError,TypeError,KeyError,UnicodeDecodeError,binascii.Error) as exc:
        raise OQAttestationError('NOT_CHECKED: primary OS probe witness malformed') from exc
    if not isinstance(decoded,dict) or data!=_canon(decoded):
        _deny('primary OS probe witness not canonical bytes')
    required=('nonce','run_id','git_sha','command_digest','policy_sha256',
              'attester_id','boot_id','collector_uid','collector_gid','sut_uid','sut_gid')
    if (decoded.get('schema')!='aio.p01.oqa.os_probe.v1' or
            any(decoded.get(k)!=request.get(k) for k in required) or
            decoded.get('deployment_sha256')!=deployment_sha or
            decoded.get('target')!=target or decoded.get('kind')!=kind or
            decoded.get('provenance')!='attester_os_syscalls' or
            decoded.get('probe_origin')!='independent_attester' or
            not isinstance(decoded.get('namespace_id'),str) or
            not decoded['namespace_id'] or
            not isinstance(decoded.get('mac_profile'),str) or
            not decoded['mac_profile']):
        _deny('primary OS probe witness origin/deployment mismatch')
    attempts=decoded.get('syscall_attempts')
    if not isinstance(attempts,list) or len(attempts)!=len(expected_probes):
        _deny('incomplete primary OS syscall witness')
    expected={(role,operation,errno) for role,operation,errno in expected_probes}
    actual=set()
    for attempt in attempts:
        if not isinstance(attempt,dict) or set(attempt)!= {
                'role','uid','gid','operation','errno','target','timestamp_monotonic_ns',
                'namespace_id','mac_profile'}:
            _deny('missing primary OS syscall identity/provenance')
        role,op,errno=attempt['role'],attempt['operation'],attempt['errno']
        if role not in ('collector','sut'):
            _deny('unknown OS probe actor')
        uid=request['collector_uid'] if role=='collector' else request['sut_uid']
        gid=request['collector_gid'] if role=='collector' else request['sut_gid']
        if (type(attempt['uid']) is not int or attempt['uid']!=uid or
                type(attempt['gid']) is not int or attempt['gid']!=gid or
                attempt['target']!=target or
                attempt['namespace_id']!=decoded['namespace_id'] or
                attempt['mac_profile']!=decoded['mac_profile'] or
                type(attempt['timestamp_monotonic_ns']) is not int or
                not request['challenge_start_ns']<=attempt['timestamp_monotonic_ns']<=issued_monotonic_ns):
            _deny('primary OS probe actor, target, namespace or time unproven')
        triple=(role,op,errno)
        if triple in actual or triple not in expected:
            _deny('unexpected/repeated OS syscall or errno')
        actual.add(triple)
    if actual!=expected:
        _deny('missing primary OS negative or positive syscall')
    if kind=='readonly_observer':
        state=decoded.get('write_denial_state')
        if not isinstance(state,dict) or set(state)!={'target_path','before_b64','after_b64'}:
            _deny('observer write-denial primary bytes absent')
        target_path=state['target_path']
        if not isinstance(target_path,str) or not target_path.startswith('/synthetic/') or '..' in Path(target_path).parts:
            _deny('observer write probe outside test namespace')
        try:
            before=base64.b64decode(state['before_b64'],validate=True)
            after=base64.b64decode(state['after_b64'],validate=True)
        except (TypeError,ValueError,binascii.Error) as exc:
            raise OQAttestationError('NOT_CHECKED: noncanonical observer before/after bytes') from exc
        if not before or len(before)>4096 or not after or len(after)>4096 or before!=after:
            _deny('observer write-denial primary bytes changed or excessive')
        return {'before_sha256':_sha(before),'after_sha256':_sha(after)}
    return decoded


def verify_oqa_receipt(response: dict, policy: dict, request: dict, *,
                       attester_key: Ed25519PublicKey,
                       kernel_audit_key: Ed25519PublicKey | None = None) -> bool:
    """External attester must have inspected actual signer + read-only deployment.

    The attester must NOT be the collector, SUT, monitor or observer. Its owner-
    provisioned key is independently pinned. Fields below represent independently
    observed OS/MAC/namespace/access-policy results, not collector flags.
    """
    try:
        receipt=response['receipt']
        signature=bytes.fromhex(response['signature'])
        attester_key.verify(signature,_canon(receipt))
    except Exception as exc:
        raise OQAttestationError('NOT_CHECKED: independent deployment attestation signature invalid') from exc
    if not isinstance(receipt,dict): _deny('bad signed OQ receipt')
    for k in ('nonce','run_id','git_sha','command_digest','policy_sha256',
              'attester_id','monitor_id','monitor_public_key_sha256',
              'collector_uid','collector_gid','sut_uid','sut_gid','required_sources','boot_id',
              'oqa_kernel_audit_id'):
        if receipt.get(k)!=request.get(k):
            _deny('OQ attestation is not bound to this run, policy or boot')
    if receipt.get('schema')!='aio.p01.oqa.deployment.attested.v1':
        _deny('incorrect external deployment attestation schema')
    if (type(receipt.get('issued_monotonic_ns')) is not int or
            not request['challenge_start_ns']<=receipt['issued_monotonic_ns']<=time.monotonic_ns()):
        _deny('OQ deployment receipt stale or not freshly issued')
    signer=receipt.get('signer_deployment')
    observer=receipt.get('readonly_observer_deployment')
    if not isinstance(signer,dict) or not isinstance(observer,dict):
        _deny('actual signer/observer deployment measurement absent')
    if (signer.get('deployment_sha256')!=policy['oqa_monitor_deployment_sha256'] or
            signer.get('monitor_public_key_sha256')!=policy['kernel_monitor_public_key_sha256'] or
            signer.get('monitor_id')!=policy['kernel_monitor_id'] or
            not isinstance(signer.get('signer_key_id'),str) or not signer['signer_key_id'] or
            signer.get('actual_key_storage_measured') is not True or
            signer.get('namespace_and_mac_policy_measured') is not True or
            signer.get('all_signing_interfaces_enumerated') is not True or
            signer.get('unaudited_signing_brokers')!=0 or
            signer.get('fabricated_event_signing_rejected') is not True):
        _deny('actual monitor signer deployment or signing API not attested')
    interfaces=signer.get('signing_interfaces')
    if not isinstance(interfaces,list) or not interfaces:
        _deny('monitor signing interfaces not independently enumerated')
    if len({i.get('target') for i in interfaces if isinstance(i,dict)})!=len(interfaces):
        _deny('duplicate signing endpoint masks untested interface')
    for iface in interfaces:
        if (not isinstance(iface,dict) or not isinstance(iface.get('target'),str) or
                not iface['target'] or iface.get('collector_access_errno') not in ('EACCES','EPERM') or
                iface.get('sut_access_errno') not in ('EACCES','EPERM') or
                iface.get('signer_key_id')!=signer['signer_key_id']):
            _deny('unproven alternative signing interface or unsafe broker')
        _verify_raw_os_probe_artifact(iface.get('os_probe_artifact'),
                                     iface.get('os_probe_evidence_sha256'),
                                     request=request,
                                     deployment_sha=signer['deployment_sha256'],
                                     target=iface['target'],kind='monitor_signing_interface',
                                     expected_probes=(
                                         ('collector','signing_request',iface['collector_access_errno']),
                                         ('sut','signing_request',iface['sut_access_errno'])),
                                     issued_monotonic_ns=receipt['issued_monotonic_ns'])
    if (observer.get('deployment_sha256')!=policy['oqa_observer_deployment_sha256'] or
            observer.get('observer_id')!=policy['readonly_observer_id'] or
            observer.get('observer_public_key_sha256')!=policy['readonly_observer_public_key_sha256'] or
            observer.get('observer_socket_path')!=policy['readonly_observer_socket_path'] or
            observer.get('protocol')!='aio.p01.readonly_snapshot.v1' or
            observer.get('independently_measured_sources')!=request['required_sources'] or
            observer.get('snapshot_source')!='trusted_os_broker' or
            observer.get('sut_can_supply_measurements') is not False or
            observer.get('root_fallback') is not False or
            observer.get('collector_read_probe')!='ALLOW' or
            observer.get('collector_write_probe') not in ('EACCES','EPERM') or
            observer.get('sut_write_probe') not in ('EACCES','EPERM') or
            observer.get('write_probe_bytes_before_sha256')!=observer.get('write_probe_bytes_after_sha256') or
            not isinstance(observer.get('write_probe_bytes_before_sha256'),str) or
            len(observer['write_probe_bytes_before_sha256'])!=64 or
            observer.get('snapshot_scope_readonly_attested') is not True or
            not isinstance(observer.get('os_probe_evidence_sha256'),str)):
        _deny('positive read-only observer access/denial not independently proven')
    state_digests=_verify_raw_os_probe_artifact(observer.get('os_probe_artifact'),
                                 observer['os_probe_evidence_sha256'],
                                 request=request,
                                 deployment_sha=observer['deployment_sha256'],
                                 target=observer['observer_socket_path'],
                                 kind='readonly_observer',expected_probes=(
                                     ('collector','rpc_read','ALLOW'),
                                     ('collector','rpc_write',observer['collector_write_probe']),
                                     ('sut','rpc_write',observer['sut_write_probe'])),
                                     issued_monotonic_ns=receipt['issued_monotonic_ns'])
    if (observer['write_probe_bytes_before_sha256']!=state_digests['before_sha256'] or
            observer['write_probe_bytes_after_sha256']!=state_digests['after_sha256']):
        _deny('observer read-only evidence not tied to primary write-denial bytes')
    for field in ('write_probe_bytes_before_sha256','write_probe_bytes_after_sha256'):
        digest=observer[field]
        if len(digest)!=64 or any(x not in '0123456789abcdef' for x in digest):
            _deny('observer write-denial file digest invalid')
    # Attester signature alone cannot claim independent kernel syscall provenance.
    # An owner-pinned, separately keyed kernel audit sensor must countersign
    # the EXACT raw probe digest set. An unprovisioned sensor => NOT_CHECKED.
    audit=response.get('kernel_audit')
    if not isinstance(audit,dict) or kernel_audit_key is None:
        _deny('independent kernel audit witness missing')
    signed=audit.get('receipt')
    if not isinstance(signed,dict):
        _deny('kernel audit witness bytes missing')
    try:
        kernel_audit_key.verify(bytes.fromhex(audit['signature']),_canon(signed))
    except Exception as exc:
        raise OQAttestationError('NOT_CHECKED: independent kernel audit signature invalid') from exc
    digest_set=sorted([i['os_probe_evidence_sha256'] for i in interfaces]+[
                      observer['os_probe_evidence_sha256']])
    # Two independent signed sources must contain the same concrete OS events.
    # A naked attester claim about all signing APIs is not sufficient.
    primaries=[('monitor_signing_interface',i['target'],i['os_probe_artifact']) for i in interfaces]
    primaries.append(('readonly_observer',observer['observer_socket_path'],observer['os_probe_artifact']))
    expected_events=[]
    for kind,target,artifact in primaries:
        try:
            original=json.loads(base64.b64decode(artifact['os_probe_bytes_b64'],validate=True))
        except (TypeError,ValueError,KeyError,binascii.Error) as exc:
            raise OQAttestationError('NOT_CHECKED: no primary events for sensor correlation') from exc
        for event in original['syscall_attempts']:
            expected_events.append({'kind':kind,'target':target,'role':event['role'],
               'uid':event['uid'],'gid':event['gid'],'operation':event['operation'],
               'errno':event['errno'],'timestamp_monotonic_ns':event['timestamp_monotonic_ns'],
               'namespace_id':event['namespace_id'],'mac_profile':event['mac_profile']})
    recorded=signed.get('kernel_syscall_events')
    endpoints=signed.get('discovered_signing_endpoints')
    if (not isinstance(recorded,list) or not recorded or
            not isinstance(endpoints,list) or len(endpoints)!=len(set(endpoints)) or
            sorted(endpoints)!=sorted(i['target'] for i in interfaces) or
            sorted(_canon(x) for x in recorded)!=sorted(_canon(x) for x in expected_events)):
        _deny('independent kernel events or signing interface inventory mismatch')
    expected_source=('linux_audit_netlink_v1', 'kernel_syscall_events')
    if (signed.get('schema')!='aio.p01.oqa.kernel_audit.v1' or
            signed.get('audit_id')!=policy['oqa_kernel_audit_id'] or
            signed.get('deployment_sha256')!=policy['oqa_kernel_audit_deployment_sha256'] or
            any(signed.get(f)!=request.get(f) for f in (
                'nonce','run_id','git_sha','command_digest','policy_sha256','boot_id')) or
            signed.get('event_digest_set_sha256')!=_sha(_canon(digest_set)) or
            signed.get('source')!=expected_source[0] or
            signed.get('origin')!=expected_source[1] or
            signed.get('event_loss_count')!=0 or
            signed.get('all_signing_endpoints_observed') is not True or
            signed.get('independent_of_attester_collector_sut') is not True or
            type(signed.get('capture_started_ns')) is not int or
            type(signed.get('capture_stopped_ns')) is not int or
            not request['challenge_start_ns']<=signed['capture_started_ns']<=
                signed['capture_stopped_ns']<=receipt['issued_monotonic_ns']):
        _deny('independent kernel audit does not cover real primary OS probe set')
    return True


def require_live_oqa_attestation(policy: dict, *, run_id: str, git_sha: str,
                                  command_digest: str, required_sources: list[str]) -> dict:
    """Live nonce-bound attester challenge; no pre-existing/static JSON passes.

    Only owner-signed addresses are trusted; no inspector or observer deployed
    in D5. This function is a mandatory runtime gate at OQ-09/A.
    """
    validate_oqa_policy(policy)
    if not run_id or not isinstance(git_sha,str) or len(git_sha)!=40 or not command_digest:
        _deny('invalid runner-issued execution challenge')
    sources=sorted(set(required_sources)-{'execve_trace'})
    if not set(sources)<=set(policy['readonly_observer_sources']):
        _deny('read-only observer cannot cover requested independent sources')
    attester=_pinned_key(policy['oqa_attester_public_key_path'],
                         policy['oqa_attester_public_key_sha256'])
    observer=_pinned_key(policy['readonly_observer_public_key_path'],
                         policy['readonly_observer_public_key_sha256'])
    audit_key=_pinned_key(policy['oqa_kernel_audit_public_key_path'],
                          policy['oqa_kernel_audit_public_key_sha256'])
    _protected_observer_socket(Path(policy['readonly_observer_socket_path']),policy['collector_gid'])
    try:
        boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    except OSError as exc:
        raise OQAttestationError('NOT_CHECKED: kernel boot identity unavailable') from exc
    request={'schema':'aio.p01.oqa.deployment.challenge.v1',
             'nonce':secrets.token_hex(32), 'run_id':run_id,'git_sha':git_sha,
             'command_digest':command_digest, 'policy_sha256':_sha(_canon(policy)),
             'attester_id':policy['oqa_attester_id'],'monitor_id':policy['kernel_monitor_id'],
             'monitor_public_key_sha256':policy['kernel_monitor_public_key_sha256'],
             'sut_uid':policy['sut_uid'],'sut_gid':policy['sut_gid'],
             'collector_uid':policy['collector_uid'],'collector_gid':policy['collector_gid'],
             'required_sources':sources,'boot_id':boot,
             'oqa_kernel_audit_id':policy['oqa_kernel_audit_id'],
             'challenge_start_ns':time.monotonic_ns()}
    response=_receive_attester(Path(policy['oqa_attester_socket_path']),request)
    verify_oqa_receipt(response,policy,request,attester_key=attester,
                       kernel_audit_key=audit_key)
    return {'attested_receipt':response['receipt'],'attester_key':attester,
            'observer_key':observer,'observer_id':policy['readonly_observer_id']}


def verify_readonly_observer_measurements(evidence: dict, *, observer_key: Ed25519PublicKey,
                                           observer_id: str, run_id: str, git_sha: str,
                                           command_digest: str):
    """Every non-monitor capture must carry a separate signed observer snapshot.

    Collector HMAC alone cannot make observations authentic. Observer receipts
    bind original measurements to the exact run/source/digest and read-only
    independently provisioned broker. No receipt -> NOT_CHECKED.
    """
    if not evidence or observer_key is None or not observer_id:
        _deny('approved read-only observation authority missing')
    for source, proof in evidence.items():
        if source=='execve_trace':
            continue  # separate Ed25519 kernel monitor receipts are mandatory
        captured=getattr(proof,'captures',None)
        if not isinstance(captured,dict):
            _deny('observer source measurement missing')
        signed=captured.get('readonly_observer_receipt')
        if not isinstance(signed,dict):
            _deny('independent read-only snapshot signature missing')
        receipt=signed.get('receipt')
        if not isinstance(receipt,dict):
            _deny('observer snapshot receipt absent')
        measurement={k:v for k,v in captured.items() if k!='readonly_observer_receipt'}
        if (receipt.get('schema')!='aio.p01.observer.snapshot.v1' or
                receipt.get('observer_id')!=observer_id or
                receipt.get('source')!=source or receipt.get('run_id')!=run_id or
                receipt.get('git_sha')!=git_sha or
                receipt.get('command_digest')!=command_digest or
                receipt.get('measurement_sha256')!=_sha(_canon(measurement)) or
                receipt.get('readonly') is not True or
                receipt.get('origin')!='trusted_os_broker'):
            _deny('read-only broker snapshot mismatch or SUT controlled')
        try:
            observer_key.verify(bytes.fromhex(signed['signature']),_canon(receipt))
        except Exception as exc:
            raise OQAttestationError('NOT_CHECKED: independent observer snapshot signature invalid') from exc
    return True
