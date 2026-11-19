#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Confined GitHub transport for a manual personal build; never echo remote data.

The CI secret is consumed here, removed from the environment before spawning Git,
and held only in memory. Git receives an immutable anonymous config via /proc,
not a token in its argv, environment, checkout config, or build inputs. Build code
runs in a later credential-free step. This is a trusted hosted-runner boundary,
not protection against GitHub/repository administrators or malicious build code.
"""
import argparse
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import signal
import ssl
import stat
import subprocess
import sys
import urllib.parse
import uuid

API = 'api.github.com'
UPLOAD = 'uploads.github.com'
SHA40 = re.compile(r'[0-9a-f]{40}')
REPOSITORY = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*')
MAX_JSON = 4 * 1024 * 1024
MAX_ASSET = 1900 * 1024 * 1024


class Rejected(Exception):
    pass


def need(value, reason):
    if not value:
        raise Rejected(reason)


def sha256(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def directory(path):
    p = Path(path)
    need(p.is_absolute() and '..' not in p.parts and p.resolve(strict=True) == p
         and p.is_dir() and not p.is_symlink(), 'directory-invalid')
    return p


def write_json(path, data):
    # Serialize before creating anything; publish the final marker atomically and
    # without replacement. A failed write must not look like a completed build.
    directory(path.parent)
    need(not os.path.lexists(path), 'json-output-already-exists')
    payload = (json.dumps(data, indent=2, sort_keys=True) + '\n').encode('utf-8')
    temporary = path.parent / ('.' + path.name + '.' + uuid.uuid4().hex + '.tmp')
    try:
        with temporary.open('xb') as stream:
            temporary.chmod(0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path, follow_symlinks=False)
    finally:
        if os.path.lexists(temporary):
            # Only remove this newly-created, canonical temporary file, never a
            # caller-selected path or an existing final output.
            need(temporary.resolve(strict=True) == temporary and temporary.is_file(), 'temporary-path-invalid')
            temporary.unlink()


def git_env():
    # No Actions credentials, config overlays, askpass, trace, replace objects,
    # preload, Python startup, or caller-supplied Git configuration are inherited.
    result = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR', 'LANG')
              if key in os.environ}
    result.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM='/dev/null',
                  GIT_CONFIG_GLOBAL='/dev/null', GIT_TERMINAL_PROMPT='0',
                  GIT_ASKPASS='/bin/false', GIT_NO_REPLACE_OBJECTS='1',
                  GIT_OPTIONAL_LOCKS='0', LC_ALL='C')
    return result


def run_git(args, cwd, config=None):
    command = ['git', '--no-optional-locks', '--no-replace-objects',
               '-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null',
               '-c', 'protocol.file.allow=never', '-c', 'http.followRedirects=false',
               '-c', 'http.sslVerify=true', '-c', 'fetch.recurseSubmodules=false',
               '-c', 'submodule.recurse=false']
    if config is not None:
        command += ['-c', 'include.path=' + config]
    command += args
    env = git_env()
    # Do not let curl discover a runner/host .netrc outside this new checkout.
    env['HOME'] = str(Path(cwd) / '.git')
    process = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        stdout, _ = process.communicate(timeout=240)
        need(process.returncode == 0, 'git-operation-failed-output-withheld')
        return stdout
    except BaseException:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.stdout.close()
                process.stderr.close()
        raise


def auth_config(repository, token):
    # A pathname to the *parent* FD works for Git's remote child too; no secret FD
    # needs to survive Git's exec. The parent closes it before source checkout.
    fd = os.memfd_create('personal-auth', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        encoded = base64.b64encode(('x-access-token:' + token).encode('ascii')).decode('ascii')
        data = ('[http "https://github.com/' + repository + '.git"]\n'
                '\textraHeader = AUTHORIZATION: basic ' + encoded + '\n').encode('ascii')
        need(os.write(fd, data) == len(data), 'auth-config-write')
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_SEAL | fcntl.F_SEAL_WRITE |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK)
        return fd, '/proc/' + str(os.getpid()) + '/fd/' + str(fd)
    except BaseException:
        os.close(fd)
        raise


def owner_classic_opt_in(repository, repository_id):
    # Explicit owner exception, not a reduction of the PAT's actual permissions.
    # Other repositories, actors, events and refs retain the fine-grained default.
    context = {
        'PERSONAL_PRIVATE_ALLOW_CLASSIC': 'true',
        'GITHUB_REPOSITORY': 'barton0426/immortalwrt_nss_ci',
        'GITHUB_REPOSITORY_ID': '979201312',
        'GITHUB_REPOSITORY_OWNER': 'barton0426',
        'GITHUB_ACTOR': 'barton0426',
        'GITHUB_TRIGGERING_ACTOR': 'barton0426',
        'GITHUB_EVENT_NAME': 'workflow_dispatch',
        'GITHUB_REF': 'refs/heads/main',
    }
    return (repository == 'barton0426/sing-box-private' and repository_id == 1457920845
            and all(os.environ.get(key) == value for key, value in context.items()))


class GitHub:
    def __init__(self, repository, repository_id, token):
        need(REPOSITORY.fullmatch(repository) and not repository.endswith('.git'), 'repository-invalid')
        need(type(repository_id) is int and repository_id > 0, 'repository-id-invalid')
        fine_grained = isinstance(token, str) and re.fullmatch(r'github_pat_[A-Za-z0-9_]{30,}', token)
        classic = isinstance(token, str) and re.fullmatch(r'ghp_[A-Za-z0-9]{30,}', token)
        need(fine_grained or (classic and owner_classic_opt_in(repository, repository_id)),
             'dedicated-fine-grained-token-required')
        self.repository, self.repository_id, self.token = repository, repository_id, token
        self.prefix = '/repos/' + repository

    def request(self, method, path, data=None, host=API, length=None):
        need(host in (API, UPLOAD) and (path == self.prefix or path.startswith(self.prefix + '/')) and
             not any(c in path for c in '\r\n#'), 'request-target-invalid')
        if length is None and data is not None:
            data = json.dumps(data, separators=(',', ':')).encode('utf-8')
        headers = {'Accept': 'application/vnd.github+json', 'User-Agent': 'personal-build',
                   'X-GitHub-Api-Version': '2022-11-28', 'Authorization': 'Bearer ' + self.token}
        if data is not None:
            headers['Content-Type'] = 'application/json' if length is None else 'application/octet-stream'
            headers['Content-Length'] = str(len(data) if length is None else length)
        connection = http.client.HTTPSConnection(host, timeout=120, context=ssl.create_default_context())
        try:
            connection.request(method, path, body=data, headers=headers)
            response = connection.getresponse()
            raw = response.read(MAX_JSON + 1)
            need(response.status in (200, 201) and len(raw) <= MAX_JSON,
                 'github-request-failed-output-withheld')
            value = json.loads(raw)
            need(isinstance(value, dict), 'github-response-invalid-output-withheld')
            return value
        finally:
            connection.close()

    def private_guard(self):
        value = self.request('GET', self.prefix)
        need(type(value.get('id')) is int and value.get('id') == self.repository_id and
             isinstance(value.get('full_name'), str) and value['full_name'].lower() ==
             self.repository.lower() and value.get('private') is True and
             value.get('fork') is False and value.get('default_branch') == 'main',
             'private-repository-guard-failed')
        return value

    def commit(self, revision):
        need(SHA40.fullmatch(revision), 'commit-full40-required')
        value = self.request('GET', self.prefix + '/git/commits/' + revision)
        need(isinstance(value.get('tree'), dict), 'commit-tree-invalid')
        tree = value['tree'].get('sha')
        need(value.get('sha') == revision and isinstance(tree, str) and SHA40.fullmatch(tree),
             'commit-tree-invalid')
        return tree

    def main(self):
        value = self.request('GET', self.prefix + '/git/ref/heads/main')
        need(isinstance(value.get('object'), dict), 'main-reference-invalid')
        result = value['object']
        need(result.get('type') == 'commit' and isinstance(result.get('sha'), str) and
             SHA40.fullmatch(result['sha']), 'main-reference-invalid')
        return result['sha']


def fetch(args, github):
    state = directory(args.state)
    need(SHA40.fullmatch(args.commit), 'commit-full40-required')
    github.private_guard()
    need(github.main() == args.commit, 'private-main-changed-review-new-pin')
    tree = github.commit(args.commit)
    source = state / 'source'
    need(not os.path.lexists(source), 'source-output-already-exists')
    source.mkdir(mode=0o700)
    run_git(['init', '--quiet'], source)
    url = 'https://github.com/' + github.repository + '.git'
    run_git(['remote', 'add', 'origin', url], source)
    fd, config = auth_config(github.repository, github.token)
    try:
        run_git(['fetch', '--quiet', '--no-tags', '--depth=1', 'origin', args.commit], source, config)
    finally:
        os.close(fd)
    # No private source code or hooks have run while an authentication FD existed.
    run_git(['checkout', '--quiet', '--detach', args.commit], source)
    actual_tree = run_git(['rev-parse', 'HEAD^{tree}'], source).decode('ascii').strip()
    need(actual_tree == tree and run_git(['status', '--porcelain', '--untracked-files=all'], source) == b'',
         'checked-out-tree-invalid')
    # Reject persisted HTTP credentials even if a future Git version changes its
    # handling of inherited configuration. Inspect the local config only.
    local = run_git(['config', '--local', '--list'], source)
    need(b'extraheader' not in local.lower() and b'credential' not in local.lower() and
         github.token.encode('ascii') not in local, 'checkout-credential-persisted')
    github.private_guard()
    need(github.main() == args.commit, 'private-main-changed-during-fetch')
    write_json(state / 'FETCH.json', {'schema_version': 1, 'paired_commit': args.commit,
                                     'paired_tree': tree, 'repository_id': github.repository_id,
                                     'credential_persisted': False})


def regular_asset(state, name, asset_directory='publish'):
    need(asset_directory in ('publish', 'diagnostics'), 'asset-directory-invalid')
    need(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,180}', name),
         'asset-name-invalid')
    path = state / asset_directory / name
    st = path.lstat()
    need(path.resolve(strict=True) == path and stat.S_ISREG(st.st_mode) and st.st_nlink == 1
         and 0 < st.st_size <= MAX_ASSET, 'asset-file-invalid')
    return path


def publish(args, github):
    state = directory(args.state)
    # A missing final build inventory is a STOP. Never salvage a partial tree by
    # uploading arbitrary runner files, logs, caches, or error messages publicly.
    inventory_path = state / 'PUBLISH.json'
    need(inventory_path.resolve(strict=True) == inventory_path and
         inventory_path.is_file() and inventory_path.stat().st_size <= MAX_JSON,
         'complete-publish-inventory-required')
    inventory = json.loads(inventory_path.read_text(encoding='utf-8'))
    need(isinstance(inventory, dict), 'publish-inventory-invalid')
    need(inventory.get('schema_version') == 1 and inventory.get('complete') is True,
         'complete-publish-inventory-required')
    commit = inventory.get('paired_commit')
    need(isinstance(commit, str) and SHA40.fullmatch(commit), 'publish-commit-invalid')
    fetched_path = state / 'FETCH.json'
    fetched_stat = fetched_path.lstat()
    need(fetched_path.resolve(strict=True) == fetched_path and stat.S_ISREG(fetched_stat.st_mode) and
         fetched_stat.st_nlink == 1 and 0 < fetched_stat.st_size <= MAX_JSON, 'verified-fetch-receipt-required')
    fetched = json.loads(fetched_path.read_text(encoding='utf-8'))
    need(isinstance(fetched, dict) and fetched.get('schema_version') == 1 and
         fetched.get('repository_id') == github.repository_id and fetched.get('credential_persisted') is False and
         fetched.get('paired_commit') == commit and fetched.get('paired_tree') == inventory.get('paired_tree'),
         'publish-fetch-source-binding')
    need(re.fullmatch(r'personal-[a-z0-9_-]+-[0-9]+-[0-9]+', args.tag), 'release-tag-invalid')
    files = inventory.get('files_sha256')
    need(isinstance(files, dict) and 3 <= len(files) <= 16, 'publish-inventory-invalid')
    asset_directory = inventory.get('asset_directory')
    firmware_complete = inventory.get('firmware_complete')
    need((asset_directory == 'publish' and firmware_complete is True) or
         (asset_directory == 'diagnostics' and firmware_complete is False), 'publish-kind-invalid')
    paths = {}
    for name, expected in files.items():
        path = regular_asset(state, name, asset_directory)
        need(isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected) and
             sha256(path) == expected, 'publish-asset-hash')
        paths[name] = path
    github.private_guard()
    need(github.commit(commit) == inventory.get('paired_tree'), 'publish-source-binding')
    release = github.request('POST', github.prefix + '/releases', {
        'tag_name': args.tag, 'target_commitish': commit,
        'name': 'Personal firmware' if firmware_complete else 'Personal build diagnostics - NO FIRMWARE',
        'body': ('Manual personal build. CLI/source/licenses/config and private build logs included. '
                 'Not device runtime acceptance. No automatic installation.' if firmware_complete else
                 'The build STOPPED. Private diagnostic files only; there is NO complete firmware in this release. '
                 'No partial binary is offered for installation.'),
        'draft': True, 'prerelease': True, 'generate_release_notes': False})
    release_id = release.get('id')
    need(type(release_id) is int and release_id > 0 and release.get('draft') is True,
         'draft-release-invalid')
    # Deliberately no automatic deletion or retry: a failure leaves a PRIVATE draft
    # that the owner may inspect, and never opens a public fallback download path.
    write_json(state / 'PRIVATE-DRAFT.json', {'release_id': release_id, 'tag': args.tag})
    for name, path in sorted(paths.items()):
        github.private_guard()
        need(sha256(path) == files[name], 'publish-asset-changed')
        with path.open('rb') as stream:
            uploaded = github.request('POST', github.prefix + '/releases/' + str(release_id) +
                                      '/assets?name=' + urllib.parse.quote(name, safe=''),
                                      data=stream, host=UPLOAD, length=path.stat().st_size)
        need(uploaded.get('name') == name and uploaded.get('state') == 'uploaded' and
             uploaded.get('size') == path.stat().st_size and
             uploaded.get('digest') == 'sha256:' + files[name], 'uploaded-asset-invalid')
    github.private_guard()
    finished = github.request('PATCH', github.prefix + '/releases/' + str(release_id), {'draft': False})
    need(finished.get('id') == release_id and finished.get('draft') is False, 'release-finalization-invalid')
    github.private_guard()
    write_json(state / 'PUBLISHED.json', {'schema_version': 1, 'private_verified': True,
                                        'release_id': release_id, 'tag': args.tag,
                                        'firmware_complete': firmware_complete,
                                        'files_sha256': files})


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('fetch', 'publish'))
    parser.add_argument('--state', required=True)
    parser.add_argument('--commit', default='')
    parser.add_argument('--tag', default='')
    args = parser.parse_args()
    token = os.environ.pop('PERSONAL_PRIVATE_TOKEN', '')
    try:
        github = GitHub(os.environ.get('PERSONAL_PRIVATE_REPOSITORY', ''),
                        int(os.environ.get('PERSONAL_PRIVATE_REPOSITORY_ID', '0')), token)
        if args.operation == 'fetch':
            fetch(args, github)
        else:
            publish(args, github)
        print('Private ' + args.operation + ' completed; no public artifacts or logs were uploaded.')
        return 0
    except (Rejected, OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.SubprocessError, http.client.HTTPException, RecursionError):
        print('Private operation stopped; remote output and credentials withheld.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
