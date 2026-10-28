"""Test-only P01 D5 verifier and runner-side collector interface.

This code is NOT a product API and no observed AC is PASS until an approved,
separately pinned, independently reviewed collector measures a genuine SUT.
A fixture's expected observations never reach the collector.
"""
from __future__ import annotations

import hashlib
import hmac
import importlib.util
import os
import stat
import socket
import subprocess
import sys
import time
from contextlib import contextmanager
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class ProbeError(AssertionError):
    """NOT_CHECKED for unproven evidence, FAIL for measured AC mismatch."""


_ALLOWED_WITNESS_SOURCES = frozenset({
    'sqlite_snapshot', 'subprocess_audit', 'git_test_remote', 'filesystem_snapshot',
    'document_digest', 'http_test_server', 'offnode_stub', 'controlled_disk_fault',
    'durable_journal', 'git_history_refs', 'secret_scanner_report', 'ci_runner_exit',
    'redacted_error_log', 'os_syscall_trace', 'supervisor_inventory_metadata',
    'outbound_call_counter', 'execve_trace',
})

# Normative checks are independent of the fixture file. A snapshot digest in
# oracle_integrity adds modification detection but is NOT owner approval.
_CRITICAL_EXPECTATIONS = {
    ('AC-F-01.1', 'accepted-owner-registration', 'status'): 'PENDING_PRECHECK',
    ('AC-F-01.1', 'same-idempotency-key-again', 'registration_command_executions'): 2,
    ('AC-F-02.1', 'non-allowlisted-url', 'reason'): 'REPO_NOT_ALLOWED',
    ('AC-F-04.1', 'markdown-APPROVED-no-trust-anchor', 'worker_launches'): 0,
    ('AC-N-12.1', 'skip-mandatory-test', 'allowed'): False,
    ('AC-N-12.1', 'disable-secret-scanning', 'allowed'): False,
    ('AC-N-12.1', 'change-approved-AC-oracle', 'allowed'): False,
    ('AC-N-12.1', 'exceed-resource-cap', 'allowed'): False,
    ('AC-N-12.1', 'unauthorized-merge', 'allowed'): False,
    ('AC-N-15.1', 'log-quota-overflow', 'owned_log_bytes_after'): {'op': 'at_most', 'value': 128 * 1024 * 1024},
    ('AC-N-15.1', 'log-quota-overflow', 'log_quota_enforced'): True,
    ('AC-ERR-03.2', 'full-fs-before-durable-intent', 'remote_write_calls'): 0,
    ('AC-ERR-03.2', 'full-fs-before-durable-intent', 'system_mode'): 'FAIL_CLOSED',
    ('AC-ERR-03.2', 'full-fs-before-durable-intent', 'journal_record_created'): False,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'remote_writes_before_restart'): 1,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'remote_writes_total_after_restart'): 1,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'ack_calls'): 0,
    ('AC-N-SEC-05.5', 'exactly-next-due', 'decision'): 'DENY',
    ('AC-N-SEC-05.5', 'before-due-valid-scope', 'decision'): 'ALLOW',
    ('AC-N-SEC-05.5', 'new-ref-valid-scope', 'decision'): 'ALLOW',
    ('AC-N-SEC-05.5', 'provider-expiry-comes-first', 'decision'): 'DENY',
    ('AC-N-15.2', 'evidence-512MiB-without-offnode', 'reason'): 'ARTIFACT_QUOTA_BLOCKED',
    ('AC-N-15.2', 'offnode-unavailable', 'protected_evidence_removed'): 0,
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'journal_state_before_reconciliation'): 'UNCERTAIN',
    ('AC-ERR-03.2', 'full-fs-result-commit-after-remote-effect', 'journal_state_after_reconciliation'): 'CONFIRMED',
    ('AC-N-SEC-01.1', 'scan-current-tree-and-all-remote-branches', 'each_advertised_ref_sha_scanned'): True,
}


# Only an out-of-band, OWNER-AUTHENTICATED trust root is allowed to authorize
# the collector in real acceptance.  These are fixed runner-side locations;
# untrusted SUT/runtime environment variables cannot select an alternative key.
OWNER_PUBLIC_KEY_PATH = Path('/etc/aio-orchestrator/trust/owner-ed25519.pub.pem')
OWNER_SIGNED_POLICY_PATH = Path('/etc/aio-orchestrator/trust/p01-collector-policy.json')
OWNER_POLICY_SIGNATURE_PATH = Path('/etc/aio-orchestrator/trust/p01-collector-policy.sig')


def verify_signed_collector_policy(payload: bytes, signature: bytes, pinned_owner_public_key: Path,
                                   *, collector_file: Path, git_sha: str) -> dict[str, Any]:
    """Authenticate approval with a separately provisioned owner public key.

    Ownership/provisioning of the key is a separate owner-inspection requirement;
    a caller-provided public key alone is NOT an authorization proof.
    """
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.exceptions import InvalidSignature
    except ImportError as exc:
        raise ProbeError('NOT_CHECKED: required signature verifier unavailable') from exc
    try:
        key=load_pem_public_key(pinned_owner_public_key.read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError('not Ed25519')
        key.verify(signature, payload)
    except (OSError, ValueError, InvalidSignature) as exc:
        raise ProbeError('NOT_CHECKED: owner authority signature invalid') from exc
    try:
        data=json.loads(payload)
    except ValueError as exc:
        raise ProbeError('NOT_CHECKED: malformed signed policy') from exc
    required={'schema','collector_sha256','collector_path','witness_key_path','git_sha',
              'sut_uid','sut_gid','runner_uid','collector_uid','collector_gid','authorized_by','scope',
              'sut_command_sha256','sut_repo_path','sut_executable_sha256',
              'sut_launch_mode','sut_components_sha256','git_scan_mirror_path','git_test_remote_url',
              'synthetic_root_path','kernel_monitor_id','kernel_monitor_public_key_path',
              'kernel_monitor_public_key_sha256','kernel_monitor_socket_path',
              'monitor_key_isolation_probe_path'}
    if not isinstance(data,dict) or not required <= set(data) or data['schema']!='aio.p01.owner_signed_collector_policy.v1':
        raise ProbeError('NOT_CHECKED: incomplete signed collector policy')
    if data['scope']!='P01-D5' or not data['authorized_by'] or data['git_sha']!=git_sha:
        raise ProbeError('NOT_CHECKED: signed policy wrong scope, SHA or actor')
    if data['collector_path']!=str(collector_file.resolve(strict=True)):
        raise ProbeError('NOT_CHECKED: signed policy collector path mismatch')
    if data['collector_sha256']!=_sha256(collector_file.read_bytes()):
        raise ProbeError('NOT_CHECKED: signed policy collector digest mismatch')
    for field in ('sut_uid','sut_gid','runner_uid','collector_uid','collector_gid'):
        if type(data[field]) is not int or data[field]<0:
            raise ProbeError('NOT_CHECKED: signed policy OS identity invalid')
    if not isinstance(data['sut_command_sha256'],str) or len(data['sut_command_sha256'])!=64:
        raise ProbeError('NOT_CHECKED: SUT command not pinned in signed policy')
    if not isinstance(data['sut_executable_sha256'],str) or len(data['sut_executable_sha256'])!=64:
        raise ProbeError('NOT_CHECKED: SUT executable bytes are not signed/pinned')
    if data['sut_launch_mode'] not in ('direct_elf','pinned_python_script'):
        raise ProbeError('NOT_CHECKED: launch mode must be pinned by signed owner policy')
    if not Path(data['sut_repo_path']).is_absolute():
        raise ProbeError('NOT_CHECKED: SUT checkout not pinned by signed policy')
    components=data['sut_components_sha256']
    if not isinstance(components,dict) or not components or not all(
            isinstance(k,str) and Path(k).is_absolute() and
            isinstance(v,str) and len(v)==64 and all(ch in '0123456789abcdef' for ch in v)
            for k,v in components.items()):
        raise ProbeError('NOT_CHECKED: signed runtime component closure missing')
    if not isinstance(data['git_scan_mirror_path'],str) or not Path(data['git_scan_mirror_path']).is_absolute():
        raise ProbeError('NOT_CHECKED: independent Git mirror not approved')
    if not isinstance(data['git_test_remote_url'],str) or not data['git_test_remote_url']:
        raise ProbeError('NOT_CHECKED: independently approved test remote URL missing')
    if not isinstance(data['synthetic_root_path'],str) or data['synthetic_root_path']!='/synthetic':
        raise ProbeError('NOT_CHECKED: approved test-only synthetic namespace missing')
    if (not isinstance(data['kernel_monitor_id'],str) or not data['kernel_monitor_id'] or
            not isinstance(data['kernel_monitor_public_key_sha256'],str) or
            len(data['kernel_monitor_public_key_sha256']) != 64 or
            not all(ch in '0123456789abcdef' for ch in data['kernel_monitor_public_key_sha256']) or
            not all(isinstance(data[k],str) and Path(data[k]).is_absolute() for k in
                    ('kernel_monitor_public_key_path','kernel_monitor_socket_path'))):
        raise ProbeError('NOT_CHECKED: independently pinned kernel monitor authority missing')
    if (data['runner_uid'] != 0 or
            min(data['sut_uid'],data['sut_gid'],data['collector_uid'],data['collector_gid']) == 0 or
            len({data['sut_uid'],data['collector_uid'],data['runner_uid']}) != 3 or
            len({data['sut_gid'],data['collector_gid']}) != 2):
        raise ProbeError('NOT_CHECKED: signed policy does not separate runner, SUT and collector identities')
    if (not isinstance(data['monitor_key_isolation_probe_path'],str) or
            not Path(data['monitor_key_isolation_probe_path']).is_absolute()):
        raise ProbeError('NOT_CHECKED: independent monitor signing-key guard path missing')
    if not Path(data['witness_key_path']).is_absolute():
        raise ProbeError('NOT_CHECKED: untrusted relative witness key path')
    # Twelfth D5: the owner-signature must also bind exact OQ-09/A signer
    # deployment and independent READ-ONLY observer. Their deployment is not
    # a test harness claim; live external attestation is checked before SUT.
    try:
        from p01_oqa_attestation import validate_oqa_policy
        validate_oqa_policy(data)
    except Exception as exc:
        raise ProbeError('NOT_CHECKED: independent OQ-09/A signer/observer policy incomplete') from exc
    return data


def load_externally_approved_runner_policy(*, git_sha: str) -> dict[str, Any]:
    """Out-of-band root must be installed by OWNER; never choose it via env."""
    trust_directory=OWNER_PUBLIC_KEY_PATH.parent
    if (trust_directory!=OWNER_SIGNED_POLICY_PATH.parent or
            trust_directory!=OWNER_POLICY_SIGNATURE_PATH.parent):
        raise ProbeError('NOT_CHECKED: inconsistent approved trust directory')
    for ancestor in (trust_directory, *list(trust_directory.parents)):
        if ancestor.is_symlink() or ancestor.stat().st_uid!=0 or ancestor.stat().st_mode & 0o022:
            raise ProbeError('NOT_CHECKED: trust root directory is not root-controlled')
    for path in (OWNER_PUBLIC_KEY_PATH, OWNER_SIGNED_POLICY_PATH, OWNER_POLICY_SIGNATURE_PATH):
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_mode & 0o022:
                raise ProbeError('NOT_CHECKED: untrusted owner policy filesystem permissions')
        except OSError as exc:
            raise ProbeError('NOT_CHECKED: owner policy trust root not provisioned') from exc
    try:
        payload=OWNER_SIGNED_POLICY_PATH.read_bytes()
        signed=json.loads(payload)
        collector_file=Path(signed['collector_path'])
        signature=OWNER_POLICY_SIGNATURE_PATH.read_bytes()
        return verify_signed_collector_policy(payload, signature, OWNER_PUBLIC_KEY_PATH,
                                               collector_file=collector_file, git_sha=git_sha)
    except (OSError, ValueError, KeyError) as exc:
        raise ProbeError('NOT_CHECKED: authenticated owner collector approval missing') from exc


def require_witness_key_isolation(key_path: Path, *, sut_uid: int, sut_gid: int) -> str:
    """Real negative syscall executed as the SUT OS identity, with NO key value output.

    Required before *every* acceptance run. Test-only uses a synthetic key.
    If the runner cannot setuid to SUT, fail closed (never claim OS PASS).
    """
    import os
    import subprocess
    import sys
    if sut_uid==os.geteuid() or sut_uid==key_path.stat().st_uid:
        raise ProbeError('NOT_CHECKED: same OS identity, witness key not isolated')
    if key_path.stat().st_mode & 0o077:
        raise ProbeError('NOT_CHECKED: witness key permissions expose runner authority')
    snippet=(
        'import os,sys,errno; p=sys.argv[1]; '
        'os.stat(p); '
        '\ntry: fd=os.open(p,os.O_RDONLY)\n'
        'except OSError as e: sys.exit(0 if e.errno in (errno.EACCES,errno.EPERM) else 42)\n'
        'else: os.close(fd);sys.exit(43)'
    )
    try:
        child=subprocess.run([sys.executable,'-c',snippet,str(key_path)],
                             env={'PATH':'/usr/bin:/bin'},user=sut_uid,group=sut_gid,
                             capture_output=True,timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProbeError('NOT_CHECKED: cannot run isolation probe as SUT identity') from exc
    if child.returncode!=0:
        raise ProbeError('NOT_CHECKED: synthetic witness key OS denial not proven')
    return 'EACCES'



def require_monitor_signer_isolation(probe_path: Path, monitor_socket: Path, *,
                                     sut_uid: int, sut_gid: int,
                                     collector_uid: int, collector_gid: int) -> bool:
    """Run OS-denial syscalls as BOTH isolated roles before SUT/collector launch.

    An owner-provisioned synthetic signing-key guard must share the monitor
    signer's OS protection domain. This is not the private key. An owner must
    inspect real signer isolation at OQ-09/A; a fake JSON flag cannot bypass
    the negative OS checks or the monitor's independent signature.
    """
    if os.geteuid()!=0 or not all(type(x) is int and x>0 for x in
                                   (sut_uid,sut_gid,collector_uid,collector_gid)):
        raise ProbeError('NOT_CHECKED: approved root runner and non-root roles required')
    if sut_uid==collector_uid or sut_gid==collector_gid:
        raise ProbeError('NOT_CHECKED: collector and SUT share forbidden signing-key identity')
    for path,kind in ((probe_path,'regular'),(monitor_socket,'socket')):
        try:
            if not path.is_absolute() or path.is_symlink():
                raise ProbeError('NOT_CHECKED: signer isolation target is not an absolute non-symlink')
            st=path.lstat()
            if (st.st_uid!=0 or st.st_mode & 0o077 or
                    not (stat.S_ISREG(st.st_mode) if kind=='regular'
                         else stat.S_ISSOCK(st.st_mode))):
                raise ProbeError('NOT_CHECKED: monitor signing guard/socket is not root-only')
            for parent in (path.parent,*path.parent.parents):
                pst=parent.lstat()
                if not stat.S_ISDIR(pst.st_mode) or pst.st_uid!=0 or pst.st_mode & 0o022:
                    raise ProbeError('NOT_CHECKED: writable monitor signer namespace')
        except OSError as exc:
            raise ProbeError('NOT_CHECKED: monitor signer guard/socket not provisioned') from exc
    snippet=r'''
import ctypes, errno, os, socket, sys
from pathlib import Path
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(38,1,0,0,0)!=0: sys.exit(50)
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
for field in ('Uid','Gid'):
    ids=status[field].split()
    if len(ids)!=4 or len(set(ids))!=1: sys.exit(51)
if status['Groups'].strip() or status['NoNewPrivs'].strip()!='1': sys.exit(52)
if any(int(status[field],16) for field in ('CapEff','CapPrm','CapAmb')): sys.exit(53)
try:
    fd=os.open(sys.argv[1],os.O_RDONLY);os.close(fd);sys.exit(54)
except OSError as exc:
    if exc.errno not in (errno.EACCES,errno.EPERM): sys.exit(55)
sock=socket.socket(socket.AF_UNIX)
try:
    sock.connect(sys.argv[2]);sys.exit(56)
except OSError as exc:
    if exc.errno not in (errno.EACCES,errno.EPERM): sys.exit(57)
finally:
    sock.close()
sys.stdout.write('MONITOR_DENIED')
'''
    for uid,gid in ((collector_uid,collector_gid),(sut_uid,sut_gid)):
        try:
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',snippet,
                                   str(probe_path),str(monitor_socket)],
                                  user=uid,group=gid,extra_groups=[],umask=0o077,
                                  capture_output=True,timeout=5,
                                  env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
        except (OSError,subprocess.SubprocessError) as exc:
            raise ProbeError('NOT_CHECKED: monitor isolation syscall probe unavailable') from exc
        if result.returncode!=0 or result.stdout!=b'MONITOR_DENIED' or result.stderr:
            raise ProbeError('NOT_CHECKED: collector/SUT can access monitor signing authority')
    return True


def verify_sut_proc_identity(status_text: str, *, sut_uid: int, sut_gid: int, runner_uid: int) -> bool:
    """Reject all privilege-bearing Linux credential IDs and supplementary groups."""
    try:
        lines = dict(line.split(':', 1) for line in status_text.splitlines() if ':' in line)
        uids = [int(x) for x in lines['Uid'].split()]
        gids = [int(x) for x in lines['Gid'].split()]
        groups = [int(x) for x in lines['Groups'].split()]
        cap_effective = int(lines['CapEff'].strip(), 16)
        cap_permitted = int(lines['CapPrm'].strip(), 16)
        cap_ambient = int(lines['CapAmb'].strip(), 16)
        no_new_privs = int(lines['NoNewPrivs'].strip())
    except (KeyError, ValueError, TypeError) as exc:
        raise ProbeError('NOT_CHECKED: incomplete OS credentials') from exc
    if (len(uids) != 4 or len(gids) != 4 or
            any(uid != sut_uid or uid == runner_uid for uid in uids) or
            any(gid != sut_gid for gid in gids) or
            bool(groups) or
            any((cap_effective, cap_permitted, cap_ambient)) or no_new_privs != 1):
        raise ProbeError('NOT_CHECKED: SUT OS privilege escalation or mismatched credentials')
    return True


def verify_complete_git_history(advertised: dict[str,str], scanned: dict[str,str], *,
                                verified_remote: bool, reachable_commits: dict[str,list[str]],
                                scanned_commits: list[str], reachable_verified: bool,
                                trusted_remote_repo: Path | None = None,
                                trusted_remote_url: str | None = None) -> bool:
    """Prove against independent, COMPLETE synthetic remote mirror, never SUT report.

    The mirror's provisioning/remote authenticity must be owner-authorized
    out of band. A caller-controlled checkout or shallow clone is never proof.
    """
    import subprocess
    verify_scan_ref_coverage(advertised, scanned, verified_remote=verified_remote)
    if trusted_remote_repo is None or not trusted_remote_url:
        raise ProbeError('NOT_CHECKED: independent Git mirror/remote authority required')
    repo=Path(trusted_remote_repo)
    try:
        def git(*args):
            return subprocess.check_output(['git','-C',str(repo),*args],text=True,timeout=10).strip()
        remote_lines=subprocess.check_output(['git','ls-remote','--heads',trusted_remote_url],text=True,timeout=10).strip().splitlines()
        remote_advertised={name:sha for sha,name in (row.split() for row in remote_lines)}
        if not remote_advertised or remote_advertised!=advertised:
            raise ProbeError('NOT_CHECKED: independent test remote advertised refs differ')
        if git('rev-parse','--is-shallow-repository') != 'false':
            raise ProbeError('NOT_CHECKED: shallow Git history cannot prove full remote reachability')
        refs={}
        for line in git('for-each-ref','--format=%(refname) %(objectname)','refs/heads/').splitlines():
            ref,commit=line.split()
            refs[ref]=commit
        if not refs or refs!=advertised:
            raise ProbeError('NOT_CHECKED: signed fixture refs differ from actual remote')
        git('fsck','--full','--no-reflogs','--strict')
        actual=set(git('rev-list','--all').splitlines())
        if not actual or any(not git('cat-file','-t',sha)=='commit' for sha in actual):
            raise ProbeError('NOT_CHECKED: incomplete Git object graph')
        if not reachable_verified or not isinstance(reachable_commits,dict) or set(reachable_commits)!=set(refs):
            raise ProbeError('NOT_CHECKED: unproven claimed reachable history')
        for ref,sha in refs.items():
            expected=set(git('rev-list',sha).splitlines())
            if set(reachable_commits[ref])!=expected or len(reachable_commits[ref])!=len(expected):
                raise ProbeError('NOT_CHECKED: ref ancestors incomplete')
        if set(scanned_commits)!=actual or len(scanned_commits)!=len(actual):
            raise ProbeError('NOT_CHECKED: not all independently reachable commits scanned')
    except (OSError,subprocess.SubprocessError,ValueError,IndexError) as exc:
        raise ProbeError('NOT_CHECKED: independent full Git mirror evidence unavailable') from exc
    return True


def verify_synthetic_object_bytes(spec: dict, actual: bytes) -> bool:
    """Fixture digest must be derived from deterministic bytes, never a decorative hex pattern."""
    seed=spec.get('seed_utf8')
    size=spec.get('size_bytes')
    if not isinstance(seed,str) or not seed or type(size) is not int or size < 0:
        raise ProbeError('NOT_CHECKED: synthetic bytes not reproducible')
    data=seed.encode('utf-8')
    digest=hashlib.sha256()
    for _ in range(size//len(data)):
        digest.update(data)
    digest.update(data[:size%len(data)])
    if len(actual) != size or hashlib.sha256(actual).hexdigest() != digest.hexdigest() or digest.hexdigest()!=spec.get('sha256'):
        raise ProbeError('NOT_CHECKED: synthetic fixture digest not validated')
    return True


def materialize_synthetic_objects(synthetic_input: dict, workspace: Path, *,
                                  sut_uid: int | None = None, sut_gid: int | None = None) -> list[Path]:
    """Create exactly reproducible synthetic files or roll back ALL newly created bytes.

    An error during writing, fsync, a post-write digest/size recheck, or a later
    file never leaves a partially populated fixture namespace reusable as PASS.

    When sut_uid/gid are explicitly approved, hand off ONLY synthetic SUT-owned
    evidence after bytes are verified; retain runner-owned witness/off-node files
    outside this workspace. A policy test must not pass merely because the OS
    denied the SUT access to the synthetic evidence it was meant to manage.
    """
    import os
    files=synthetic_input.get('protected_evidence_files',[])
    if not isinstance(files,list):
        raise ProbeError('NOT_CHECKED: invalid evidence file plan')
    if (sut_uid is None) != (sut_gid is None):
        raise ProbeError('NOT_CHECKED: synthetic SUT uid/gid must be specified together')
    if sut_uid is not None and (type(sut_uid) is not int or sut_uid <= 0 or
                                type(sut_gid) is not int or sut_gid <= 0):
        raise ProbeError('NOT_CHECKED: invalid synthetic SUT identity')
    created=[]
    made_dirs=[]
    active=None
    try:
        for f in files:
            if not isinstance(f,dict) or not isinstance(f.get('path'),str):
                raise ProbeError('NOT_CHECKED: synthetic file path missing')
            relative=Path(f['path'])
            if relative.is_absolute() or '..' in relative.parts:
                raise ProbeError('NOT_CHECKED: unsafe synthetic fixture path')
            target=workspace/relative
            if not target.resolve().is_relative_to(workspace.resolve()):
                raise ProbeError('NOT_CHECKED: synthetic fixture symlink escape')
            generator=f.get('generator',{})
            if not isinstance(generator,dict) or generator.get('algorithm')!='repeat_utf8_seed_v1' or generator.get('size_bytes')!=f.get('size_bytes'):
                raise ProbeError('NOT_CHECKED: unknown synthetic byte generator')
            seed=generator.get('seed_utf8')
            n=generator['size_bytes']
            if not isinstance(seed,str) or not seed or type(n)!=int or n<0 or n>536870912:
                raise ProbeError('NOT_CHECKED: invalid or oversized synthetic fixture')
            block=seed.encode('utf8')
            pattern=block*max(1,(1048576//len(block)))
            # Track only directories newly created for this fixture. Existing
            # directories must ALREADY be SUT-owned when ownership is requested.
            parents=[]
            cursor=target.parent
            while cursor != workspace and cursor.is_relative_to(workspace):
                parents.append(cursor)
                cursor=cursor.parent
            for directory in reversed(parents):
                if not directory.exists():
                    directory.mkdir(mode=0o700)
                    made_dirs.append(directory)
                elif directory.is_symlink() or not directory.is_dir():
                    raise ProbeError('NOT_CHECKED: unsafe synthetic fixture parent')
                elif sut_uid is not None and directory not in made_dirs and (
                     directory.stat().st_uid != sut_uid or
                     directory.stat().st_gid != sut_gid or
                     not (directory.stat().st_mode & 0o300) == 0o300):
                    raise ProbeError('NOT_CHECKED: preexisting synthetic directory not SUT-accessible')
            digest=hashlib.sha256()
            # O_EXCL | O_NOFOLLOW prevents overwriting old fixtures or symlink targets.
            fd=os.open(target,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
            active=target
            with os.fdopen(fd,'wb') as stream:
                rest=n
                while rest:
                    chunk=pattern[:min(rest,len(pattern))]
                    stream.write(chunk)
                    digest.update(chunk)
                    rest-=len(chunk)
                stream.flush()
                os.fsync(stream.fileno())
            if digest.hexdigest()!=f.get('sha256'):
                raise ProbeError('NOT_CHECKED: generated synthetic bytes do not match independently declared SHA')
            measured=hashlib.sha256()
            with target.open('rb') as stream:
                while chunk:=stream.read(1048576):
                    measured.update(chunk)
            if measured.hexdigest()!=f['sha256'] or target.stat().st_size!=n:
                raise ProbeError('NOT_CHECKED: actual synthetic file bytes not verified')
            created.append(target)
            active=None
        if sut_uid is not None:
            # Do not launch SUT until the entire fixture set is verified. File
            # ownership and directory traversal are part of the test contract.
            for target in created:
                os.chown(target,sut_uid,sut_gid)
                os.chmod(target,0o600)
            for directory in made_dirs:
                os.chown(directory,sut_uid,sut_gid)
                os.chmod(directory,0o700)
            for target in created:
                st=target.stat()
                pst=target.parent.stat()
                if (st.st_uid!=sut_uid or st.st_gid!=sut_gid or
                    pst.st_uid!=sut_uid or pst.st_gid!=sut_gid):
                    raise ProbeError('NOT_CHECKED: synthetic SUT evidence ownership incorrect')
        return created
    except (OSError,ProbeError,ValueError,TypeError) as exc:
        pending=created+([active] if active is not None else [])
        try:
            for path in reversed(pending):
                path.unlink(missing_ok=True)
            for directory in reversed(made_dirs):
                directory.rmdir()
        except OSError as cleanup_exc:
            raise ProbeError('NOT_CHECKED: synthetic fixture rollback could not be verified') from cleanup_exc
        if isinstance(exc,ProbeError):
            raise
        raise ProbeError('NOT_CHECKED: synthetic fixture materialization incomplete') from exc


def require_sut_synthetic_evidence_access(files: list[Path], *, sut_uid: int, sut_gid: int) -> None:
    """Runner-side OS test: a separate SUT identity can read and evict fixtures.

    Independently checks the *setup*, never a normative P01 AC. Test evidence
    lives in the disposable SUT workspace, separate from runner-owned witness.
    No production paths, network operations or real credentials are used.
    """
    if not files:
        return
    import os
    import subprocess
    import sys
    if (type(sut_uid) is not int or type(sut_gid) is not int or
            sut_uid <= 0 or sut_gid <= 0 or os.geteuid() == sut_uid):
        raise ProbeError('NOT_CHECKED: OS access probe requires separate unprivileged SUT identity')
    script = (
        'from pathlib import Path\n'
        'import os,sys\n'
        'for name in sys.argv[1:]:\n'
        ' p=Path(name)\n'
        ' with p.open("rb") as stream: stream.read(1)\n'
        ' witness=p.parent / (".aio-p01-access-probe-"+str(os.getpid()))\n'
        ' with witness.open("xb") as stream: stream.write(b"synthetic")\n'
        ' witness.unlink()\n'
    )
    try:
        result=subprocess.run([sys.executable,'-I','-S','-B','-c',script,
                               *(str(p) for p in files)],
                              user=sut_uid,group=sut_gid,extra_groups=[],
                              env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
                              capture_output=True,timeout=10,check=False)
    except (OSError,subprocess.SubprocessError) as exc:
        raise ProbeError('NOT_CHECKED: OS synthetic evidence access probe unavailable') from exc
    if result.returncode != 0:
        raise ProbeError('NOT_CHECKED: OS synthetic evidence is not SUT-readable/evictable')


def require_preexisting_synthetic_sentinel(synthetic_input: dict, *, trusted_root: Path) -> Path:
    """Positive OS-sentinel seam: no writes outside an approved synthetic root.

    A separate privileged test-fixture owner MUST already have provisioned the
    synthetic bytes. All ancestors/target must be root-owned and non-writable
    to the SUT; otherwise fail without probing production paths.
    """
    target=Path(synthetic_input.get('target',''))
    generator=synthetic_input.get('sentinel_generator')
    if (not target.is_absolute() or trusted_root!=Path('/synthetic') or
            not target.is_relative_to(trusted_root) or not isinstance(generator,dict) or
            generator.get('algorithm')!='repeat_utf8_seed_v1'):
        raise ProbeError('NOT_CHECKED: invalid approved synthetic sentinel path/generator')
    try:
        import os
        for p in (target,*target.parents):
            if p.is_symlink() or p.stat().st_uid!=0 or p.stat().st_mode & 0o022:
                raise ProbeError('NOT_CHECKED: synthetic OS sentinel not protected from SUT')
        if not target.is_file() or target.stat().st_size!=generator['size_bytes']:
            raise ProbeError('NOT_CHECKED: synthetic sentinel not preexisting')
        # Sentinel is small (137 bytes) in frozen P01 fixtures. Large objects are
        # streamed separately by materialize_synthetic_objects.
        with target.open('rb') as fd: raw=fd.read(4096)
        spec={**generator,'sha256':synthetic_input.get('sentinel_sha256')}
        verify_synthetic_object_bytes(spec,raw)
    except (OSError,TypeError,KeyError) as exc:
        raise ProbeError('NOT_CHECKED: synthetic OS sentinel not provisioned') from exc
    return target


def verify_immutable_sut_checkout(repo: Path, expected_sha: str, argv: list[str],
                                  approved_executable_sha256: str, *,
                                  approved_components_sha256: dict[str,str] | None = None,
                                  approved_launch_mode: str | None = None) -> bool:
    """Fail closed on modified tracked, ignored scripts or unpinned runtime bytes.

    A signed manifest must include interpreter/binary, scripts, and declared
    import/dependency closure. Actual immutable OS mount and import tracing
    remain mandatory independent runtime evidence.
    """
    import subprocess
    if not isinstance(approved_components_sha256,dict) or not approved_components_sha256:
        raise ProbeError('NOT_CHECKED: signed executable/component closure is absent')
    try:
        def git(*args):
            return subprocess.check_output(['git','-C',str(repo),*args],text=True,timeout=10).strip()
        head=git('rev-parse','HEAD')
        diff=git('status','--porcelain','--untracked-files=all')
        git('diff','--exit-code','HEAD')
        ignored=git('ls-files','--others','--ignored','--exclude-standard')
    except (OSError,subprocess.SubprocessError) as exc:
        raise ProbeError('NOT_CHECKED: cannot inspect immutable SUT tree') from exc
    if head!=expected_sha or diff:
        raise ProbeError('NOT_CHECKED: dirty/incorrect SUT checkout')
    # Ignored runtime files can alter imports without changing HEAD; no bypass.
    if any(Path(name).suffix.lower() in {'.py','.pyc','.so','.pyd','.sh','.whl','.zip'} for name in ignored.splitlines()):
        raise ProbeError('NOT_CHECKED: ignored executable/dependency in SUT checkout')
    if not argv or not Path(argv[0]).is_absolute():
        raise ProbeError('NOT_CHECKED: SUT executable must be absolute')
    executable=Path(argv[0])
    # NINTH-D5-041: a verified symlink target can change before Popen.
    if executable.is_symlink():
        raise ProbeError('NOT_CHECKED: SUT executable symlink is not a pinned execution object')
    executable_name=str(executable.resolve(strict=True))
    if executable_name not in approved_components_sha256:
        raise ProbeError('NOT_CHECKED: SUT executable missing from signed closure')
    if approved_components_sha256[executable_name]!=approved_executable_sha256:
        raise ProbeError('NOT_CHECKED: executable digest differs from signed policy')
    # NINTH-D5-040: validate ALL signed bytes before any interpreter probe.
    # Neither a plausible "cpython" string nor probe exit zero is proof of identity.
    for name, sha in approved_components_sha256.items():
        component=Path(name)
        try:
            if (not component.is_absolute() or component.is_symlink() or
                    not component.is_file() or str(component.resolve()) != name or
                    hashlib.sha256(component.read_bytes()).hexdigest()!=sha):
                raise ProbeError('NOT_CHECKED: executable/script/import bytes differ from signed closure')
        except (OSError, ValueError) as exc:
            raise ProbeError('NOT_CHECKED: cannot verify executable bytes before execution') from exc
    # SEVENTH-REVIEW-039: NEVER infer authority to execute a second component
    # from the name/hash of the first one. The OWNER-signed policy binds an
    # *explicit* launch mode. Unknown launch chains are NOT_CHECKED.
    # The runtime's independent exec/import closure still needs external proof.
    if approved_launch_mode == 'direct_elf':
        # In this narrow mode there is NO pre-approved script/command argument.
        # The acceptance harness appends only its synthetic input-file pathname.
        # /usr/bin/dash payload.sh, renamed env python script.py, perl -e, etc.
        # cannot be mistaken for a standalone program with its own fixture input.
        if len(argv) != 1 or not executable.is_file():
            raise ProbeError('NOT_CHECKED: direct_elf permits one pinned ELF, no launch chain')
        with executable.open('rb') as binary_file:
            elf_header = binary_file.read(4)
        if elf_header != b'\x7fELF':
            raise ProbeError('NOT_CHECKED: direct_elf permits one pinned ELF, no launch chain')
    elif approved_launch_mode == 'pinned_python_script':
        # This mode is not a generic interpreter launcher: exactly one pinned,
        # ABSOLUTE script and no flags, -m/-c, wrapper or extra command bytes.
        if len(argv) != 2 or not Path(argv[1]).is_absolute() or not Path(argv[1]).is_file():
            raise ProbeError('NOT_CHECKED: pinned Python launch requires one absolute script')
        script = Path(argv[1]); script_resolved = str(script.resolve(strict=True))
        if script.is_symlink() or script_resolved not in approved_components_sha256:
            raise ProbeError('NOT_CHECKED: Python script not in signed component manifest')
        # Run any additional identity probe ONLY after digest verification and
        # as an unprivileged probe user. The runner must never exec uncertain
        # code under its own privileged identity.
        try:
            import subprocess
            if os.geteuid() == 0:
                probe_user, probe_group = 65534, 65534
                identity=subprocess.run([str(executable),'-I','-S','-c',
                    'import sys; print(sys.implementation.name)'],
                    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
                    capture_output=True,text=True,timeout=5,check=False,
                    user=probe_user,group=probe_group,extra_groups=[])
            else:
                identity=subprocess.run([str(executable),'-I','-S','-c',
                    'import sys; print(sys.implementation.name)'],
                    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
                    capture_output=True,text=True,timeout=5,check=False)
        except (OSError,subprocess.SubprocessError) as exc:
            raise ProbeError('NOT_CHECKED: unprivileged pinned Python identity unavailable') from exc
        if identity.returncode!=0 or identity.stdout.strip()!='cpython':
            raise ProbeError('NOT_CHECKED: pinned interpreter is not CPython')
    else:
        raise ProbeError('NOT_CHECKED: no explicitly approved signed SUT launch mode')
    # Full manifest hashes were checked BEFORE running any executable above.
    # An accepted preflight is NOT an execution authorization by pathname;
    # open_pinned_launch pins actual file descriptors for the real Popen.
    return True


@dataclass(frozen=True)
class PinnedLaunch:
    """Only file-descriptor-backed execution may follow successful admission."""
    argv: tuple[str, ...]
    executable: str
    pass_fds: tuple[int, ...]


@contextmanager
def open_pinned_launch(argv: list[str], approved_components_sha256: dict[str,str], *,
                       launch_mode: str):
    """Pin checked executable and script inodes through O_NOFOLLOW file descriptors.

    SUT never receives an executable selected by a mutable pathname. The signed
    component manifest and trusted runner filesystem controls are prerequisites.
    Full dynamic exec/import closure remains mandatory from independent OS audit.
    """
    if launch_mode not in ('direct_elf','pinned_python_script') or not argv:
        raise ProbeError('NOT_CHECKED: unsupported pinned execution mode')
    if (launch_mode=='direct_elf' and len(argv)!=1) or (
            launch_mode=='pinned_python_script' and len(argv)!=2):
        raise ProbeError('NOT_CHECKED: unpinned launch argument chain')
    opened=[]
    try:
        for path_string in argv:
            path=Path(path_string)
            if not path.is_absolute() or path.is_symlink():
                raise ProbeError('NOT_CHECKED: mutable executable/script link rejected')
            canonical=str(path.resolve(strict=True))
            if canonical not in approved_components_sha256:
                raise ProbeError('NOT_CHECKED: opened runtime component not in owner manifest')
            # Reject SUT-writable path components. Root-owned sticky /tmp may
            # contain root-controlled private dirs, but a mutable ancestor below
            # it must be rejected. SUT cannot change a root-owned sticky entry.
            for ancestor in (path.parent, *path.parent.parents):
                mode=ancestor.stat().st_mode
                if ancestor.is_symlink() or (mode & 0o022 and not
                        (ancestor.stat().st_uid==0 and mode & stat.S_ISVTX)):
                    raise ProbeError('NOT_CHECKED: mutable runtime component directory')
            fd=os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
            opened.append(fd)
            fs=os.fstat(fd)
            if not stat.S_ISREG(fs.st_mode) or fs.st_uid!=0 or fs.st_mode & 0o022:
                raise ProbeError('NOT_CHECKED: runtime component writable/untrusted OS owner')
            with os.fdopen(os.dup(fd),'rb') as file:
                sha=hashlib.file_digest(file,'sha256').hexdigest()
            fs_after=os.fstat(fd)
            if (sha!=approved_components_sha256[canonical] or
                    (fs.st_dev,fs.st_ino,fs.st_size,fs.st_mtime_ns)!=
                    (fs_after.st_dev,fs_after.st_ino,fs_after.st_size,fs_after.st_mtime_ns)):
                raise ProbeError('NOT_CHECKED: runtime inode bytes differ from approved SHA')
        if launch_mode=='direct_elf':
            if os.pread(opened[0],4,0)!=b'\x7fELF':
                raise ProbeError('NOT_CHECKED: pinned direct mode is not ELF')
        # /proc/self/fd/N is resolved in the CHILD, while the inherited FD pins
        # the inode. Repointing argv[0] after this point cannot change exec.
        proc_argv=tuple(f'/proc/self/fd/{fd}' for fd in opened)
        yield PinnedLaunch(proc_argv,proc_argv[0],tuple(opened))
    except (OSError,ValueError) as exc:
        raise ProbeError('NOT_CHECKED: cannot pin immutable executable inode') from exc
    finally:
        for fd in opened:
            os.close(fd)


def _monitor_public_key(payload: bytes):
    """Monitor key is NOT the runner's HMAC key or the collector signing key."""
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        key=load_pem_public_key(payload)
        if not isinstance(key,Ed25519PublicKey):
            raise ValueError('monitor authority must be Ed25519')
        return key
    except (ImportError,ValueError) as exc:
        raise ProbeError('NOT_CHECKED: monitor authority key unavailable') from exc


def load_kernel_monitor_authority(policy: dict, *, sut_uid: int):
    """Independent, owner-signed monitor key. Never load from the SUT workspace.

    A deployed OQ-09/A runner must provision the monitor *private* key outside
    both SUT and collector; this code does not create any monitor authority.
    """
    path=Path(policy['kernel_monitor_public_key_path'])
    digest=policy['kernel_monitor_public_key_sha256']
    try:
        if not path.is_absolute() or path.is_symlink():
            raise ProbeError('NOT_CHECKED: mutable monitor key path')
        for directory in (path.parent,*path.parent.parents):
            st=directory.lstat()
            if not stat.S_ISDIR(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
                raise ProbeError('NOT_CHECKED: monitor public key parent writable')
        st=path.lstat()
        if (not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_uid==sut_uid or st.st_mode & 0o022):
            raise ProbeError('NOT_CHECKED: monitor public key not root-controlled')
        content=path.read_bytes()
    except OSError as exc:
        raise ProbeError('NOT_CHECKED: monitor public key not provisioned') from exc
    if _sha256(content)!=digest:
        raise ProbeError('NOT_CHECKED: monitor public key fingerprint mismatch')
    return _monitor_public_key(content)


def verify_monitor_receipt(receipt: dict, signature: str, public_key, *,
                           expected_schema: str, expected_monitor_id: str,
                           expected_run_id: str, expected_git_sha: str,
                           expected_command_digest: str) -> dict:
    """Separate ED25519 authority; a self-reported flag or witness HMAC cannot pass."""
    if (not isinstance(receipt,dict) or
            receipt.get('schema')!=expected_schema or
            receipt.get('monitor_id')!=expected_monitor_id or
            receipt.get('run_id')!=expected_run_id or
            receipt.get('git_sha')!=expected_git_sha or
            receipt.get('command_digest')!=expected_command_digest or
            not isinstance(signature,str)):
        raise ProbeError('NOT_CHECKED: kernel monitor receipt not bound to approved run')
    try:
        public_key.verify(bytes.fromhex(signature),_canonical(receipt))
    except Exception as exc:
        # No signature or signature using collector's own key is never enough.
        raise ProbeError('NOT_CHECKED: independent kernel monitor signature invalid') from exc
    return receipt


def arm_monitor_session(*, socket_path: Path, monitor_public_key, monitor_id: str,
                        run_id: str, git_sha: str, command_digest: str,
                        sut_uid: int) -> dict:
    """A dedicated kernel-monitor sidecar must ACK before the first SUT Popen.

    This method is only a client contract. No monitor is supplied or assumed.
    Sidecar must observe the approved cgroup/namespace, all descendants and
    imports and hold the separate monitor private signing key outside SUT.
    """
    try:
        st=socket_path.lstat()
        if (not stat.S_ISSOCK(st.st_mode) or st.st_uid!=0 or st.st_uid==sut_uid or
                st.st_mode & 0o022):
            raise ProbeError('NOT_CHECKED: monitor socket not root-controlled')
        request={'schema':'aio.p01.monitor_arm_request.v1','monitor_id':monitor_id,
                 'run_id':run_id,'git_sha':git_sha,'command_digest':command_digest}
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.settimeout(5)
            connection.connect(str(socket_path))
            connection.sendall(_canonical(request)+b'\n')
            received=bytearray()
            while not received.endswith(b'\n'):
                chunk=connection.recv(4096)
                if not chunk or len(received)+len(chunk)>16384:
                    raise ProbeError('NOT_CHECKED: monitor did not attest ready session')
                received.extend(chunk)
        response=json.loads(received)
        receipt=verify_monitor_receipt(response['receipt'],response['signature'],monitor_public_key,
                        expected_schema='aio.p01.kernel_monitor_armed.v1',
                        expected_monitor_id=monitor_id,expected_run_id=run_id,
                        expected_git_sha=git_sha,expected_command_digest=command_digest)
        if (receipt.get('coverage_scope')!='all_sut_descendants' or
                not isinstance(receipt.get('monitor_session_id'),str) or not receipt['monitor_session_id'] or
                type(receipt.get('armed_monotonic_ns')) is not int or
                receipt['armed_monotonic_ns']<=0 or receipt['armed_monotonic_ns']>time.monotonic_ns()):
            raise ProbeError('NOT_CHECKED: monitor not armed before SUT')
        return response  # preserve the detached signature for independent recheck
    except (OSError,ValueError,KeyError,TypeError) as exc:
        raise ProbeError('NOT_CHECKED: independent monitor session unavailable') from exc


def verify_monitor_session(ready_envelope: dict | None, monitor_public_key, *,
                           launch_monotonic_ns: int, expected_run_id: str,
                           expected_monitor_id: str, expected_git_sha: str,
                           expected_command_digest: str) -> dict:
    """Reverify monitor-signed PRE-LAUNCH ACK at the final global PASS gate."""
    if not isinstance(ready_envelope,dict) or monitor_public_key is None:
        raise ProbeError('NOT_CHECKED: independent pre-launch monitor receipt missing')
    receipt=verify_monitor_receipt(ready_envelope.get('receipt'),ready_envelope.get('signature'),
                   monitor_public_key,expected_schema='aio.p01.kernel_monitor_armed.v1',
                   expected_monitor_id=expected_monitor_id,expected_run_id=expected_run_id,
                   expected_git_sha=expected_git_sha,
                   expected_command_digest=expected_command_digest)
    if (receipt.get('coverage_scope')!='all_sut_descendants' or
            not isinstance(receipt.get('monitor_session_id'),str) or not receipt['monitor_session_id'] or
            type(receipt.get('armed_monotonic_ns')) is not int or
            receipt['armed_monotonic_ns']<=0 or receipt['armed_monotonic_ns']>=launch_monotonic_ns or
            not receipt.get('monitor_boot_id')):
        raise ProbeError('NOT_CHECKED: monitor not armed before first SUT exec')
    return receipt

def verify_execution_ancestry(events: list[dict], *,
                              roots: tuple[int,...], observed_pids: tuple[int,...]) -> bool:
    """Check the signed kernel event graph, not merely equality of PID sets."""
    if not roots or not events or not observed_pids:
        raise ProbeError('NOT_CHECKED: missing monitored process graph')
    lookup={}
    for event in events:
        if (not isinstance(event,dict) or type(event.get('pid')) is not int or
                event['pid']<=0 or event['pid'] in lookup or
                type(event.get('start_monotonic_ns')) is not int or
                event['start_monotonic_ns']<=0):
            raise ProbeError('NOT_CHECKED: incomplete kernel exec event identity')
        lookup[event['pid']]=event
    if (set(lookup)!=set(observed_pids) or not set(roots)<=set(lookup)):
        raise ProbeError('NOT_CHECKED: kernel process graph incomplete')
    for pid,event in lookup.items():
        if pid in roots: continue
        ppid=event.get('ppid')
        if type(ppid) is not int or ppid not in lookup or ppid==pid:
            raise ProbeError('NOT_CHECKED: child without independently observed parent')
        if lookup[ppid]['start_monotonic_ns']>event['start_monotonic_ns']:
            raise ProbeError('NOT_CHECKED: impossible kernel ancestry timeline')
        ancestors=set()
        curr=pid
        while curr not in roots:
            if curr in ancestors:
                raise ProbeError('NOT_CHECKED: cyclic kernel process ancestry')
            ancestors.add(curr)
            curr=lookup[curr].get('ppid')
            if curr not in lookup:
                raise ProbeError('NOT_CHECKED: disconnected process ancestry')
    return True


def verify_execution_closure(capture: dict[str,Any], *,
                             approved_components_sha256: dict[str,str],
                             process_pids: tuple[int,...],
                             monitor_public_key=None, monitor_ready_receipt=None,
                             monitor_id: str | None = None,
                             run_id: str | None = None,
                             git_sha: str | None = None,
                             command_digest: str | None = None,
                             launch_monotonic_ns: int | None = None) -> bool:
    """Fail-closed external kernel-audit attestation for EVERY runtime AC.

    The runner witness HMAC authenticates a *collector report*, not kernel
    provenance. This gate needs an independent monitor Ed25519 receipt as well
    as the signed PRE-LAUNCH ready session. No monitor => NOT_CHECKED.
    """
    if (not monitor_public_key or not monitor_id or not run_id or not git_sha or
            not command_digest or type(launch_monotonic_ns) is not int):
        raise ProbeError('NOT_CHECKED: separately attested kernel monitor authority missing')
    ready=verify_monitor_session(monitor_ready_receipt,monitor_public_key,
                           launch_monotonic_ns=launch_monotonic_ns,expected_run_id=run_id,
                           expected_monitor_id=monitor_id,expected_git_sha=git_sha,
                           expected_command_digest=command_digest)
    if (not isinstance(capture,dict) or capture.get('trace_source')!='kernel_execve' or
            capture.get('trace_complete') is not True or
            capture.get('monitor_installed_outside_sut') is not True or
            capture.get('coverage_start_before_first_exec') is not True or
            capture.get('coverage_end_after_last_child_exit') is not True or
            capture.get('all_descendants_exited') is not True or
            type(capture.get('kernel_event_drops')) is not int or
            capture['kernel_event_drops']!=0 or
            capture.get('unobserved_executable_memory')!=0 or
            capture.get('unmonitored_dynamic_loads')!=0):
        raise ProbeError('NOT_CHECKED: independent complete kernel process trace missing')
    events=capture.get('execve_events')
    loads=capture.get('loaded_file_events')
    observed_pids=capture.get('observed_pids')
    if (not process_pids or not isinstance(events,list) or not events or not isinstance(loads,list) or
            not isinstance(observed_pids,list) or not observed_pids or
            any(type(p) is not int or p<=0 for p in observed_pids)):
        raise ProbeError('NOT_CHECKED: missing complete tracked process ancestry')
    verify_execution_ancestry(events,roots=process_pids,observed_pids=tuple(observed_pids))
    if not isinstance(approved_components_sha256,dict) or not approved_components_sha256:
        raise ProbeError('NOT_CHECKED: signed runtime component closure missing')
    for event in events+loads:
        if (not isinstance(event,dict) or not isinstance(event.get('executable_path'),str) or
                event['executable_path'] not in approved_components_sha256 or
                not isinstance(event.get('executable_sha256'),str) or
                approved_components_sha256[event['executable_path']]!=event['executable_sha256']):
            raise ProbeError('NOT_CHECKED: unsigned descendant exec/import component')
    # Each load must be tied to a monitored process (not merely a plausible SHA).
    if any(type(load.get('pid')) is not int or load['pid'] not in observed_pids for load in loads):
        raise ProbeError('NOT_CHECKED: loaded component not bound to monitored process')
    attested=capture.get('monitor_stopped_receipt')
    sig=capture.get('monitor_stopped_signature')
    attested=verify_monitor_receipt(attested,sig,monitor_public_key,
                   expected_schema='aio.p01.kernel_monitor_stopped.v1',
                   expected_monitor_id=monitor_id,expected_run_id=run_id,
                   expected_git_sha=git_sha,expected_command_digest=command_digest)
    expected_event_digest=_sha256(_canonical({'execve_events':events,'loaded_file_events':loads,
                                                'observed_pids':observed_pids,
                                                'kernel_event_drops':capture['kernel_event_drops']}))
    if (attested.get('monitor_session_id')!=ready.get('monitor_session_id') or
            attested.get('event_sha256')!=expected_event_digest or
            attested.get('monitor_boot_id')!=ready.get('monitor_boot_id') or
            not attested.get('monitor_boot_id') or
            attested.get('coverage_scope')!='all_sut_descendants' or
            attested.get('monitor_isolated_from_sut') is not True or
            attested.get('monitor_loss_counter_from_kernel') is not True or
            attested.get('kernel_event_drops')!=0 or
            attested.get('uninterrupted_coverage') is not True or
            attested.get('all_descendants_exited') is not True or
            attested.get('file_load_coverage_complete') is not True or
            attested.get('unmonitored_dynamic_loads') != 0 or
            attested.get('unobserved_executable_memory') != 0 or
            type(attested.get('first_exec_monotonic_ns')) is not int or
            type(attested.get('last_exit_monotonic_ns')) is not int or
            type(attested.get('stopped_monotonic_ns')) is not int or
            not (ready['armed_monotonic_ns'] < launch_monotonic_ns <=
                 attested['first_exec_monotonic_ns'] <= attested['last_exit_monotonic_ns'] <=
                 attested['stopped_monotonic_ns'])):
        raise ProbeError('NOT_CHECKED: monitor proof is not real complete run coverage')
    return True


def require_pinned_script_access(pinned, *, sut_uid: int, sut_gid: int) -> bool:
    """Actual OS open probe of the already pinned Python script as SUT UID/GID.

    Root-owned 0600 script otherwise passes hash preflight but fails when Python
    opens /proc/self/fd/N from the downgraded SUT. Not an SUT test failure.
    """
    if len(pinned.pass_fds)!=2: return True  # Direct ELF has no script FD.
    script_fd=pinned.pass_fds[1]
    snippet=('import os,sys; p=sys.argv[1]; fd=os.open(p,os.O_RDONLY); os.close(fd)')
    try:
        result=subprocess.run([sys.executable,'-I','-S','-c',snippet,f'/proc/self/fd/{script_fd}'],
                              user=sut_uid,group=sut_gid,extra_groups=[],
                              pass_fds=(script_fd,),timeout=5,capture_output=True,
                              env={'PATH':'/usr/bin:/bin'})
    except (OSError,subprocess.SubprocessError) as exc:
        raise ProbeError('NOT_CHECKED: script SUT accessibility cannot be measured') from exc
    if result.returncode!=0:
        raise ProbeError('NOT_CHECKED: pinned Python script unreadable by approved SUT identity')
    return True

def verify_scan_ref_coverage(advertised: dict[str,str], scanned: dict[str,str],
                             *, verified_remote: bool) -> bool:
    """Cross-check complete independently advertised remote branches against scans."""
    if not verified_remote or not isinstance(advertised,dict) or not advertised:
        raise ProbeError('NOT_CHECKED: remote refs were not independently enumerated')
    if not isinstance(scanned,dict) or advertised!=scanned or any(
        not isinstance(k,str) or not k.startswith('refs/heads/') or
        not isinstance(v,str) or len(v)!=40 or any(c not in '0123456789abcdef' for c in v)
        for k,v in advertised.items()
    ):
        raise ProbeError('NOT_CHECKED: unscanned or mismatched remote ref SHA coverage')
    return True


def _canonical(obj: object) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_normative_expectations(items: list[dict[str, Any]]) -> None:
    for (ac, sid, field), required in _CRITICAL_EXPECTATIONS.items():
        rows = [r for r in items if r['ac_id'] == ac]
        if len(rows) != 1:
            raise ProbeError(f'NOT_CHECKED: missing/duplicated AC {ac}')
        cases = [s for s in rows[0]['scenarios'] if s['scenario_id'] == sid]
        if len(cases) != 1 or cases[0]['expected_observations'].get(field) != required:
            raise ProbeError(f'NOT_CHECKED: changed normative expectation {ac}/{sid}/{field}')
    for row in items:
        for case in row['scenarios']:
            if not case.get('synthetic_input', {}).get('operation'):
                raise ProbeError(f'NOT_CHECKED: missing operation {row["ac_id"]}/{case["scenario_id"]}')
            if not isinstance(case.get('expected_observations'), dict) or not case['expected_observations']:
                raise ProbeError('NOT_CHECKED: missing expectations')
            if row['ac_id'] == 'AC-N-SEC-05.5' and case['expected_observations']['decision'] == 'DENY':
                if case['expected_observations'].get('outbound_calls') != 0:
                    raise ProbeError('NOT_CHECKED: DENY cannot permit outbound')
            if row['ac_id'] == 'AC-N-SEC-05.4' and 'expect_errno' in case['synthetic_input']:
                if case['expected_observations'].get('actual_errno') != case['synthetic_input']['expect_errno']:
                    raise ProbeError('NOT_CHECKED: OS errno expectation missing')


@dataclass(frozen=True)
class TestRun:
    __test__ = False
    pid: int
    returncode: int
    command_digest: str
    fixture_digest: str
    workspace: Path
    git_sha: str = ''
    run_id: str = ''
    process_start_ticks: int = 0
    process_pids: tuple[int, ...] = ()
    returncodes: tuple[int, ...] = ()
    collector_sha256: str = ''
    trusted_remote_repo: Path | None = None
    trusted_remote_url: str | None = None


@dataclass(frozen=True)
class IndependentProof:
    source: str
    path: Path
    sha256: str
    captures: dict[str, Any]
    run_pid: int
    fixture_digest: str
    witness_mac: str
    run_id: str = ''
    git_sha: str = ''
    run_command_digest: str = ''
    run_returncode: int | None = None
    process_start_ticks: int = 0


def _run_identity(run: TestRun) -> dict[str, Any]:
    return {'git_sha': run.git_sha, 'run_id': run.run_id, 'pid': run.pid,
            'returncode': run.returncode, 'command_digest': run.command_digest,
            'fixture_digest': run.fixture_digest,
            'process_start_ticks': run.process_start_ticks,
            'process_pids': list(run.process_pids), 'returncodes': list(run.returncodes),
            'collector_sha256': run.collector_sha256}


def _evidence_mac(key: bytes, proof: IndependentProof) -> str:
    signed = [proof.source, str(proof.path.resolve()), proof.sha256, proof.run_pid,
              proof.fixture_digest, proof.captures, proof.run_id, proof.git_sha,
              proof.run_command_digest, proof.run_returncode, proof.process_start_ticks]
    return hmac.new(key, _canonical(signed), hashlib.sha256).hexdigest()


def _parse_witness(proof: IndependentProof, run: TestRun) -> dict[str, Any]:
    try:
        observations = json.loads(proof.path.read_bytes())
    except (OSError, ValueError) as exc:
        raise ProbeError('NOT_CHECKED: witness JSON invalid') from exc
    if observations.get('schema') != 'aio.p01.independent_witness.v1':
        raise ProbeError('NOT_CHECKED: missing witness schema')
    if observations.get('source') != proof.source or observations.get('run') != _run_identity(run):
        raise ProbeError('NOT_CHECKED: witness run metadata mismatch')
    capture = observations.get('measurement')
    if not isinstance(capture, dict) or not capture:
        raise ProbeError('NOT_CHECKED: witness measurements absent')
    if capture != proof.captures:
        raise ProbeError('NOT_CHECKED: captures not extracted from authenticated witness bytes')
    # Per-source signed observer receipts are envelope metadata, not AC
    # measurements. Different sources legitimately carry different receipts;
    # do not merge them into one conflicting observed[] key.
    return {k:v for k,v in capture.items() if k!='readonly_observer_receipt'}


def verify_independent_proofs(
    case: dict[str, Any], reported_by_sut: dict[str, Any],
    evidence: dict[str, IndependentProof], run: TestRun | None, *,
    trusted_witness_key: bytes | None = None,
    expected_git_sha: str | None = None,
    expected_command_digest: str | None = None,
    expected_collector_sha256: str | None = None,
    evaluate_expected: bool = True,
) -> dict[str, Any]:
    """Verify *external* measurements, ignoring all SUT-reported values.

    This verifier cannot authenticate a collector itself: the authorized runner
    must pin its bytes and not expose key/collector/evidence to the SUT. Its
    unit-test MAC fixtures are not proof of a real execution.
    """
    if run is None or not isinstance(run, TestRun) or run.pid <= 0:
        raise ProbeError('NOT_CHECKED: actual subprocess PID missing')
    if not trusted_witness_key or len(trusted_witness_key) < 32:
        raise ProbeError('NOT_CHECKED: independent runner witness authority absent')
    if not expected_git_sha or run.git_sha != expected_git_sha or len(run.git_sha) != 40:
        raise ProbeError('NOT_CHECKED: unpinned or mismatched Git HEAD SHA')
    if not expected_command_digest or run.command_digest != expected_command_digest:
        raise ProbeError('NOT_CHECKED: unpinned or mismatched command')
    if not expected_collector_sha256 or run.collector_sha256 != expected_collector_sha256 or len(run.collector_sha256) != 64:
        raise ProbeError('NOT_CHECKED: unpinned or mismatched trusted collector digest')
    if not run.run_id or run.process_start_ticks <= 0:
        raise ProbeError('NOT_CHECKED: missing runner issued execution identity')
    if not run.process_pids or run.pid != run.process_pids[-1] or not run.returncodes:
        raise ProbeError('NOT_CHECKED: missing recorded subprocess sequence')
    if len(run.process_pids) != len(run.returncodes):
        raise ProbeError('NOT_CHECKED: subprocess audit length mismatch')
    if run.returncode != run.returncodes[-1]:
        raise ProbeError('NOT_CHECKED: subprocess returncode mismatch')
    digest = _sha256(_canonical(case['synthetic_input']))
    if run.fixture_digest != digest:
        raise ProbeError('NOT_CHECKED: fixture digest mismatch')
    if not run.workspace.is_dir():
        raise ProbeError('NOT_CHECKED: test workspace absent')
    trusted_dir = (run.workspace.parent / 'trusted_evidence').resolve()
    observed = {}
    for item in case['independent_proofs']:
        source = item['source']
        if source not in _ALLOWED_WITNESS_SOURCES:
            raise ProbeError(f'NOT_CHECKED: unsupported witness {source}')
        proof = evidence.get(source)
        if not isinstance(proof, IndependentProof) or proof.source != source:
            raise ProbeError(f'NOT_CHECKED: independent {source} witness missing')
        if proof.run_pid != run.pid or proof.fixture_digest != digest or proof.run_id != run.run_id:
            raise ProbeError(f'NOT_CHECKED: witness for wrong execution: {source}')
        if (proof.git_sha != run.git_sha or proof.run_command_digest != run.command_digest
                or proof.run_returncode != run.returncode or proof.process_start_ticks != run.process_start_ticks):
            raise ProbeError(f'NOT_CHECKED: {source} witness execution provenance mismatch')
        if not proof.path.is_file() or not proof.path.resolve().is_relative_to(trusted_dir):
            raise ProbeError(f'NOT_CHECKED: {source} witness outside trusted evidence directory')
        if not hmac.compare_digest(_sha256(proof.path.read_bytes()), proof.sha256):
            raise ProbeError(f'NOT_CHECKED: {source} witness contents mutated')
        if not hmac.compare_digest(_evidence_mac(trusted_witness_key, proof), proof.witness_mac):
            raise ProbeError(f'NOT_CHECKED: {source} witness was not captured by trusted runner')
        for key, value in _parse_witness(proof, run).items():
            if key in observed and observed[key] != value:
                raise ProbeError(f'NOT_CHECKED: inconsistent witness measurement {key}')
            observed[key] = value
    # The acceptance runner must complete ALL independent process/kernel
    # provenance gates before applying normative AC comparisons. Existing direct
    # unit callers preserve the default evaluate_expected=True contract.
    if evaluate_expected:
        verify_normative_measurements(case, observed, run)
    return observed


def _normative_json_value_equal(expected: Any, actual: Any) -> bool:
    """Compare actual and expected JSON values with exact types, recursively.

    In Python bool subclasses int, hence `False == 0` and `True == 1` must
    never satisfy an authenticated normative AC measurement. Dict/list
    content follows the same constraint at every nesting depth.
    """
    if type(expected) is not type(actual):
        return False
    if isinstance(expected,dict):
        return (expected.keys()==actual.keys() and
                all(_normative_json_value_equal(v,actual[k]) for k,v in expected.items()))
    if isinstance(expected,list):
        return (len(expected)==len(actual) and
                all(_normative_json_value_equal(a,b) for a,b in zip(expected,actual)))
    return expected==actual


def verify_normative_measurements(case: dict[str,Any], observed: dict[str,Any],
                                  run: TestRun) -> dict[str,Any]:
    """Evaluate normative AC ONLY AFTER authenticated execution closure."""
    if not isinstance(case,dict) or not isinstance(observed,dict) or not isinstance(run,TestRun):
        raise ProbeError('NOT_CHECKED: invalid normative evaluation context')
    if (case['synthetic_input'].get('operation')=='run_evidence_quota_gate' and
            case['synthetic_input'].get('eviction_allowed')):
        expected_sha=case['synthetic_input']['protected_evidence_files'][0]['sha256']
        backup_seq, eviction_seq=observed.get('backup_verified_event_seq'),observed.get('eviction_event_seq')
        if (type(backup_seq) is not int or type(eviction_seq) is not int or
                backup_seq < 0 or eviction_seq <= backup_seq or
                observed.get('offnode_backed_up_sha256') != expected_sha or
                not observed.get('verified_backup_receipt_id')):
            raise ProbeError('NOT_CHECKED: no independently confirmed intact offnode backup before eviction')
    if case['synthetic_input'].get('required_independent_reconciliation_trace'):
        trace=observed.get('journal_transition_trace')
        if (not isinstance(trace,list) or len(trace)!=3 or
                [e.get('order') for e in trace if isinstance(e,dict)] != [1,2,3] or
                [e.get('journal') for e in trace if isinstance(e,dict)] !=
                  ['UNCERTAIN','RECONCILING','CONFIRMED']):
            raise ProbeError('NOT_CHECKED: missing independent ordered reconciliation evidence')
    if case['synthetic_input'].get('require_preexisting_test_sentinel'):
        before=observed.get('sentinel_sha256_before')
        after=observed.get('sentinel_sha256_after')
        if (observed.get('sentinel_existed_before_probe') is not True or
                before!=case['synthetic_input']['sentinel_sha256'] or after!=before):
            raise ProbeError('NOT_CHECKED: pre-existing synthetic sentinel integrity not established')
    if case['synthetic_input'].get('require_preexisting_listening_test_server'):
        if observed.get('endpoint_listening_before_probe') is not True or observed.get('denial_due_to_network_os_policy') is not True:
            raise ProbeError('NOT_CHECKED: network OS policy denial on listening endpoint not proven')
    if case['synthetic_input'].get('operation')=='scan_git_tree_and_history':
        verify_complete_git_history(observed.get('remote_advertised_ref_sha'),
                                    observed.get('scanned_ref_sha'),
                                    verified_remote=observed.get('remote_refs_verified_by_collector') is True,
                                    reachable_commits=observed.get('remote_reachable_commits'),
                                    scanned_commits=observed.get('scanned_reachable_commits'),
                                    reachable_verified=observed.get('reachable_history_verified_by_collector') is True,
                                    trusted_remote_repo=run.trusted_remote_repo,
                                    trusted_remote_url=run.trusted_remote_url)
    for key, expected in case['expected_observations'].items():
        if key not in observed:
            raise ProbeError(f'NOT_CHECKED: no independent observation for {key}')
        if isinstance(expected, dict) and expected.get('op') == 'at_most' and set(expected) == {'op', 'value'}:
            if type(observed[key]) not in (int, float) or type(expected['value']) not in (int, float) or observed[key] > expected['value'] or observed[key] < 0:
                raise ProbeError(f'FAIL: measured quota exceeds limit for {key}')
        elif not _normative_json_value_equal(expected,observed[key]):
            raise ProbeError(f'FAIL: independent measurement differs/type mismatch for {key}')
    return observed


def _execute_collector_isolated(payload: bytes, synthetic_input: dict, run_fields: dict,
                                required_sources: list[str], *, collector_uid: int,
                                collector_gid: int) -> dict:
    """Measure using a NEW isolated Python interpreter, never runner sys.modules.

    -I -S removes PYTHONPATH, user/site packages and cwd from Python import
    resolution. Only owner-pinned collector bytes and root-controlled stdlib are
    accessible. A cached dependency in the parent cannot affect measurements.
    This is D5 test harness plumbing; OS/owner provisioning still NOT_CHECKED.
    """
    import base64
    import os
    import subprocess
    import sys
    import tempfile
    bootstrap=r'''
import base64,ctypes,json,sys,types
from pathlib import Path
item=json.loads(sys.stdin.buffer.read())
libc=ctypes.CDLL(None,use_errno=True)
if libc.prctl(38,1,0,0,0)!=0: raise RuntimeError('collector NoNewPrivs unavailable')
status=dict(line.split(':',1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
for field,want in (('Uid',item['collector_uid']),('Gid',item['collector_gid'])):
    ids=[int(value) for value in status[field].split()]
    if len(ids)!=4 or any(value!=want for value in ids): raise RuntimeError('collector OS role mismatch')
if status['Groups'].strip() or status['NoNewPrivs'].strip()!='1':
    raise RuntimeError('collector supplementary group or NoNewPrivs unsafe')
if any(int(status[field],16) for field in ('CapEff','CapPrm','CapAmb')):
    raise RuntimeError('collector inherited Linux capabilities')
scope={'__name__':'aio_signed_collector','__file__':'<approved-collector>'}
source=base64.b64decode(item['approved_collector_b64'],validate=True)
exec(compile(source,'<approved-collector>','exec'),scope)
fn=scope.get('collect')
if not callable(fn): raise RuntimeError('approved collector lacks collect()')
run_fields=item['run']
for key in ('workspace','trusted_remote_repo'):
    if run_fields.get(key) is not None: run_fields[key]=Path(run_fields[key])
result=fn(synthetic_input=item['synthetic_input'],run=types.SimpleNamespace(**run_fields),
          required_sources=frozenset(item['required_sources']))
if not isinstance(result,dict): raise RuntimeError('unstructured collector result')
sys.stdout.write(json.dumps(result,sort_keys=True,ensure_ascii=False))
'''
    request={'approved_collector_b64':base64.b64encode(payload).decode('ascii'),
             'synthetic_input':synthetic_input,'run':run_fields,
             'required_sources':required_sources,'collector_uid':collector_uid,
             'collector_gid':collector_gid}
    if (os.geteuid()!=0 or type(collector_uid) is not int or collector_uid<=0 or
            type(collector_gid) is not int or collector_gid<=0):
        raise ProbeError('NOT_CHECKED: approved non-root collector identity missing')
    with tempfile.TemporaryDirectory(prefix='aio-isolated-collector-') as temp:
        os.chmod(temp,0o711)  # role may traverse but cannot list/write
        try:
            completed=subprocess.run([sys.executable,'-I','-S','-B','-c',bootstrap],
                 input=_canonical(request),capture_output=True,timeout=30,
                 cwd=temp,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','PYTHONNOUSERSITE':'1'},
                 user=collector_uid,group=collector_gid,extra_groups=[],umask=0o077)
        except (OSError,subprocess.SubprocessError) as exc:
            raise ProbeError('NOT_CHECKED: isolated collector process unavailable') from exc
    if completed.returncode or len(completed.stdout)>1048576 or completed.stderr:
        raise ProbeError('NOT_CHECKED: isolated collector import/execution failed')
    try:
        result=json.loads(completed.stdout)
    except (UnicodeError,ValueError) as exc:
        raise ProbeError('NOT_CHECKED: isolated collector output invalid') from exc
    if not isinstance(result,dict):
        raise ProbeError('NOT_CHECKED: isolated collector measurements invalid')
    return result


def _load_pinned_collector(collector_file: Path, approved_sha256: str, workspace: Path,
                           sut_uid: int | None = None, collector_uid: int | None = None,
                           collector_gid: int | None = None):
    """Return fresh-process collector only after root-controlled-byte admission.

    No third-party module cache, ambient user site, cwd or PYTHONPATH is inherited.
    Missing dependencies fail closed instead of being imported from SUT space.
    """
    import os
    import sys
    if collector_file.is_symlink():
        raise ProbeError('NOT_CHECKED: collector symlink forbidden')
    path=collector_file.resolve(strict=True)
    if path.is_relative_to(workspace.resolve()):
        raise ProbeError('NOT_CHECKED: collector in SUT space')
    for element in (path,*path.parents):
        st=element.stat()
        if st.st_uid!=0 or st.st_mode & 0o022 or (sut_uid is not None and st.st_uid==sut_uid):
            raise ProbeError('NOT_CHECKED: collector/path not protected from SUT writes')
    for name in sys.path:
        if not name:
            raise ProbeError('NOT_CHECKED: cwd on collector import path')
        directory=Path(name).resolve()
        if directory.is_relative_to(workspace.resolve()) or not directory.exists():
            raise ProbeError('NOT_CHECKED: untrusted/missing collector import path')
        for ancestor in (directory,*directory.parents):
            st=ancestor.stat()
            if st.st_uid!=0 or st.st_mode & 0o022 or (sut_uid is not None and st.st_uid==sut_uid):
                raise ProbeError('NOT_CHECKED: transitive collector import path is SUT writable')
    if (os.geteuid()!=0 or type(collector_uid) is not int or collector_uid<=0 or
            type(collector_gid) is not int or collector_gid<=0 or
            collector_uid==sut_uid or collector_uid==os.geteuid()):
        raise ProbeError('NOT_CHECKED: distinct unprivileged collector role not approved')
    payload=path.read_bytes()
    if _sha256(payload)!=approved_sha256:
        raise ProbeError('NOT_CHECKED: approved collector digest mismatch')
    def independent_collect(*,synthetic_input,run,required_sources):
        # Reconstruct a serializable run identity; no witness key or expectations.
        fields={key:(str(value) if isinstance(value,Path) else list(value) if isinstance(value,tuple) else value)
                for key,value in vars(run).items()}
        return _execute_collector_isolated(payload,synthetic_input,fields,list(required_sources),
                                          collector_uid=collector_uid,collector_gid=collector_gid)
    return independent_collect


def collect_trusted_evidence(*, synthetic_input: dict[str, Any], required_sources: list[str],
                             run: TestRun, collector_file: Path, collector_sha256: str,
                             witness_key: bytes, sut_uid: int | None = None,
                             collector_uid: int | None = None,
                             collector_gid: int | None = None) -> dict[str, IndependentProof]:
    """Trusted runner calls independently pinned collector; never sends EXPECTED values.

    The plugin is a test-only integration seam. Real OS/CI/Git collectors must
    be independently reviewed, deployed outside SUT, and run only in sandbox.
    A mock callback that copies expectations is forbidden as acceptance evidence.
    """
    if len(witness_key) < 32:
        raise ProbeError('NOT_CHECKED: witness authority absent')
    if run.collector_sha256 != collector_sha256:
        raise ProbeError('NOT_CHECKED: collector pin not bound to run')
    collect = _load_pinned_collector(collector_file, collector_sha256, run.workspace,
                                     sut_uid=sut_uid,collector_uid=collector_uid,
                                     collector_gid=collector_gid)
    trusted_dir = run.workspace.parent / 'trusted_evidence'
    trusted_dir.mkdir(mode=0o700, exist_ok=False)
    if any(source not in _ALLOWED_WITNESS_SOURCES for source in required_sources):
        raise ProbeError('NOT_CHECKED: unknown collector source')
    # Plugin must READ independent OS/FS/CI/Git artefacts; it cannot see the
    # expected observations, can only receive immutable inputs and run identity.
    measurements = collect(synthetic_input=synthetic_input, run=run,
                           required_sources=frozenset(required_sources))
    if not isinstance(measurements, dict):
        raise ProbeError('NOT_CHECKED: collector returned invalid measurements')
    output = {}
    for source in required_sources:
        capture = measurements.get(source)
        if not isinstance(capture, dict) or not capture:
            raise ProbeError(f'NOT_CHECKED: collector has no measured {source}')
        payload = {'schema': 'aio.p01.independent_witness.v1', 'source': source,
                   'run': _run_identity(run), 'measurement': capture}
        path = trusted_dir / f'{source}.json'
        with path.open('xb') as handle:
            handle.write(_canonical(payload))
        unsigned = IndependentProof(source=source, path=path, sha256=_sha256(path.read_bytes()),
                                    captures=capture, run_pid=run.pid, fixture_digest=run.fixture_digest,
                                    witness_mac='', run_id=run.run_id, git_sha=run.git_sha,
                                    run_command_digest=run.command_digest,
                                    run_returncode=run.returncode, process_start_ticks=run.process_start_ticks)
        output[source] = IndependentProof(**{**vars(unsigned), 'witness_mac': _evidence_mac(witness_key, unsigned)})
    return output
