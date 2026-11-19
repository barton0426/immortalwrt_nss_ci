#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline regression. No real credential loader, network, Go, SDK, or router."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BASE = '70dd5d61377f21ca0b25abfc354d913c5bd8931e'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


p = load('personal_private_test_module', HERE / 'personal-private.py')
b = load('personal_private_build_test_module', HERE / 'personal-private-build.py')
TOKEN = 'github_pat_' + 'Z' * 40  # synthetic only
CLASSIC = 'ghp_' + 'Z' * 40  # synthetic only; never a real credential loader
OWNER_CONTEXT = {
    'PERSONAL_PRIVATE_ALLOW_CLASSIC': 'true',
    'GITHUB_REPOSITORY': 'barton0426/immortalwrt_nss_ci',
    'GITHUB_REPOSITORY_ID': '979201312',
    'GITHUB_REPOSITORY_OWNER': 'barton0426',
    'GITHUB_ACTOR': 'barton0426',
    'GITHUB_TRIGGERING_ACTOR': 'barton0426',
    'GITHUB_EVENT_NAME': 'workflow_dispatch',
    'GITHUB_REF': 'refs/heads/main',
}
COMMIT = 'a' * 40
TREE = 'b' * 40


class TransportTests(unittest.TestCase):
    def github(self, metadata=None):
        gh = p.GitHub('tester/private', 1, TOKEN)
        metadata = metadata or {'id': 1, 'full_name': 'tester/private', 'private': True,
                                'fork': False, 'default_branch': 'main'}
        gh.request = lambda *a, **kw: metadata
        return gh

    def test_only_dedicated_fine_grained_token(self):
        for token in ('', 'ghp_' + 'Z' * 40, 'github_pat_bad\n', 'github_pat_short'):
            with self.subTest(token_kind=len(token)), self.assertRaises(p.Rejected):
                p.GitHub('tester/private', 1, token)

    def test_classic_owner_exception_accepts_only_explicit_context(self):
        with patch.dict(os.environ, OWNER_CONTEXT, clear=True):
            gh = p.GitHub('barton0426/sing-box-private', 1457920845, CLASSIC)
            self.assertEqual(gh.repository_id, 1457920845)
        with patch.dict(os.environ, {}, clear=True), self.assertRaises(p.Rejected):
            p.GitHub('barton0426/sing-box-private', 1457920845, CLASSIC)

    def test_classic_rejects_each_wrong_or_missing_context_before_network(self):
        for key in OWNER_CONTEXT:
            for missing in (True, False):
                context = dict(OWNER_CONTEXT)
                if missing:
                    del context[key]
                else:
                    context[key] = 'wrong'
                with self.subTest(key=key, missing=missing), patch.dict(os.environ, context, clear=True), \
                        patch.object(p.http.client, 'HTTPSConnection') as network, \
                        patch.object(p, 'run_git') as git, self.assertRaises(p.Rejected):
                    p.GitHub('barton0426/sing-box-private', 1457920845, CLASSIC)
                network.assert_not_called()
                git.assert_not_called()
        for value in ('TRUE', '1', 'yes', 'false', ''):
            with self.subTest(flag=value), patch.dict(os.environ, dict(OWNER_CONTEXT, PERSONAL_PRIVATE_ALLOW_CLASSIC=value), clear=True), self.assertRaises(p.Rejected):
                p.GitHub('barton0426/sing-box-private', 1457920845, CLASSIC)

    def test_classic_exception_binds_private_name_and_immutable_id(self):
        for name, identity in (('tester/private', 1457920845), ('barton0426/other', 1457920845),
                               ('barton0426/sing-box-private', 1), ('barton0426/sing-box-private', True)):
            with self.subTest(name=name, identity=identity), patch.dict(os.environ, OWNER_CONTEXT, clear=True), self.assertRaises(p.Rejected):
                p.GitHub(name, identity, CLASSIC)

    def test_malformed_classic_still_rejected_when_opted_in(self):
        for token in ('', 'ghp_short', CLASSIC + '\n', CLASSIC + '_', 'Bearer ' + CLASSIC):
            with self.subTest(length=len(token)), patch.dict(os.environ, OWNER_CONTEXT, clear=True), self.assertRaises(p.Rejected):
                p.GitHub('barton0426/sing-box-private', 1457920845, token)

    def test_fine_grained_default_unchanged_by_classic_flag(self):
        for flag in ('', 'true', 'false', 'wrong'):
            with patch.dict(os.environ, {'PERSONAL_PRIVATE_ALLOW_CLASSIC': flag}, clear=True):
                self.assertEqual(p.GitHub('tester/private', 1, TOKEN).repository_id, 1)

    def test_classic_token_and_opt_in_never_reach_git_environment(self):
        with patch.dict(os.environ, dict(OWNER_CONTEXT, PERSONAL_PRIVATE_TOKEN=CLASSIC), clear=True):
            env = p.git_env()
        self.assertNotIn(CLASSIC, env.values())
        self.assertNotIn('PERSONAL_PRIVATE_TOKEN', env)
        self.assertNotIn('PERSONAL_PRIVATE_ALLOW_CLASSIC', env)

    def test_repository_shape(self):
        for name in ('../private', 'https://github.com/tester/private', 'tester/private.git',
                     'tester/private\n', 'tester/private/other'):
            with self.subTest(name=name), self.assertRaises(p.Rejected):
                p.GitHub(name, 1, TOKEN)

    def test_private_guard_rejects_public_fork_wrong_id_and_branch(self):
        valid = {'id': 1, 'full_name': 'tester/private', 'private': True,
                 'fork': False, 'default_branch': 'main'}
        self.github(valid).private_guard()
        for key, value in [('id', 2), ('private', False), ('fork', True),
                           ('default_branch', 'other'), ('full_name', 'tester/other')]:
            invalid = dict(valid, **{key: value})
            with self.subTest(key=key), self.assertRaises(p.Rejected):
                self.github(invalid).private_guard()

    def test_git_environment_removes_all_token_and_trace_overlays(self):
        with patch.dict(os.environ, {'PERSONAL_PRIVATE_TOKEN': TOKEN, 'GITHUB_TOKEN': TOKEN,
                                     'GH_TOKEN': TOKEN, 'GIT_TRACE': '1', 'GIT_CURL_VERBOSE': '1',
                                     'GIT_CONFIG_COUNT': '1', 'LD_PRELOAD': 'invalid'}, clear=False):
            env = p.git_env()
        self.assertNotIn(TOKEN, env.values())
        for key in ('PERSONAL_PRIVATE_TOKEN', 'GITHUB_TOKEN', 'GH_TOKEN', 'GIT_TRACE',
                    'GIT_CURL_VERBOSE', 'GIT_CONFIG_COUNT', 'LD_PRELOAD'):
            self.assertNotIn(key, env)
        self.assertEqual(env['GIT_CONFIG_GLOBAL'], '/dev/null')

    def test_auth_config_is_anonymous_immutable_and_never_persisted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            p.run_git(['init', '--quiet'], root)
            fd, config = p.auth_config('tester/private', TOKEN)
            try:
                self.assertTrue(config.startswith('/proc/'))
                with self.assertRaises(OSError):
                    os.write(fd, b'overwrite')
                result = p.run_git(['config', '--get', 'http.https://github.com/tester/private.git.extraheader'],
                                   root, config)
                self.assertTrue(result.startswith(b'AUTHORIZATION: basic '))
                self.assertNotIn(TOKEN.encode(), p.run_git(['config', '--local', '--list'], root))
                self.assertNotIn(b'extraheader', p.run_git(['config', '--local', '--list'], root).lower())
            finally:
                os.close(fd)
            self.assertFalse(Path(config).exists())
            self.assertNotIn(TOKEN, str(list(root.rglob('*'))))

    def test_request_never_follows_redirect_or_echoes_body(self):
        class Response:
            status = 302
            def read(self, limit):
                return (TOKEN + ' private source').encode()
        class Connection:
            def __init__(self, *a, **kw):
                pass
            def request(self, *a, **kw):
                pass
            def getresponse(self):
                return Response()
            def close(self):
                pass
        gh = p.GitHub('tester/private', 1, TOKEN)
        with patch.object(p.http.client, 'HTTPSConnection', Connection):
            with self.assertRaises(p.Rejected) as caught:
                gh.request('GET', gh.prefix)
        self.assertNotIn(TOKEN, str(caught.exception))
        self.assertNotIn('private source', str(caught.exception))

    def test_request_rejects_cross_host_and_cross_repository_before_connect(self):
        gh = p.GitHub('tester/private', 1, TOKEN)
        with patch.object(p.http.client, 'HTTPSConnection') as connection:
            for path, host in [('/repos/other/private/releases', p.API),
                               (gh.prefix, 'evil.example'), (gh.prefix + '/x\n', p.API)]:
                with self.subTest(host=host), self.assertRaises(p.Rejected):
                    gh.request('GET', path, host=host)
            connection.assert_not_called()

    def test_publish_private_draft_hashes_and_guard_each_upload(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve()
            (state / 'publish').mkdir(mode=0o700)
            files = {}
            for name in ('firmware.tar.gz', 'source.tar.gz', 'receipt.json'):
                path = state / 'publish' / name
                path.write_bytes(('synthetic ' + name).encode())
                files[name] = p.sha256(path)
            p.write_json(state / 'PUBLISH.json', {'schema_version': 1, 'complete': True,
                                                'firmware_complete': True, 'asset_directory': 'publish',
                                                'paired_commit': COMMIT, 'paired_tree': TREE,
                                                'files_sha256': files})
            p.write_json(state / 'FETCH.json', {'schema_version': 1, 'repository_id': 1,
                                              'credential_persisted': False,
                                              'paired_commit': COMMIT, 'paired_tree': TREE})
            gh = p.GitHub('tester/private', 1, TOKEN)
            calls = []
            def request(method, path, data=None, host=p.API, length=None):
                calls.append((method, path, host))
                if path == gh.prefix:
                    return {'id': 1, 'full_name': 'tester/private', 'private': True,
                            'fork': False, 'default_branch': 'main'}
                if '/git/commits/' in path:
                    return {'sha': COMMIT, 'tree': {'sha': TREE}}
                if host == p.UPLOAD:
                    name = path.split('name=', 1)[1]
                    value = data.read()
                    self.assertEqual(len(value), length)
                    return {'name': name, 'state': 'uploaded', 'size': length,
                            'digest': 'sha256:' + hashlib.sha256(value).hexdigest()}
                if method == 'POST':
                    self.assertTrue(data['draft'])
                    self.assertEqual(data['target_commitish'], COMMIT)
                    return {'id': 5, 'draft': True}
                self.assertEqual(method, 'PATCH')
                self.assertFalse(data['draft'])
                return {'id': 5, 'draft': False}
            gh.request = request
            p.publish(argparse.Namespace(state=str(state), tag='personal-x86-64-123-1'), gh)
            self.assertTrue((state / 'PUBLISHED.json').is_file())
            self.assertEqual(sum(host == p.UPLOAD for _, _, host in calls), 3)
            for index, (_, _, host) in enumerate(calls):
                if host == p.UPLOAD:
                    self.assertEqual(calls[index - 1][:2], ('GET', gh.prefix))

    def test_publish_rejects_public_destination_without_any_write(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve()
            (state / 'publish').mkdir()
            files = {}
            for name in ('a.txt', 'b.txt', 'c.txt'):
                path = state / 'publish' / name
                path.write_bytes(b'synthetic')
                files[name] = p.sha256(path)
            p.write_json(state / 'PUBLISH.json', {'schema_version': 1, 'complete': True,
                                                'firmware_complete': True, 'asset_directory': 'publish',
                                                'paired_commit': COMMIT, 'paired_tree': TREE,
                                                'files_sha256': files})
            p.write_json(state / 'FETCH.json', {'schema_version': 1, 'repository_id': 1,
                                              'credential_persisted': False,
                                              'paired_commit': COMMIT, 'paired_tree': TREE})
            gh = p.GitHub('tester/private', 1, TOKEN)
            calls = []
            def request(method, path, *a, **kw):
                calls.append(method)
                return {'id': 1, 'full_name': 'tester/private', 'private': False,
                        'fork': False, 'default_branch': 'main'}
            gh.request = request
            with self.assertRaises(p.Rejected):
                p.publish(argparse.Namespace(state=str(state), tag='personal-x86-64-123-1'), gh)
            self.assertEqual(calls, ['GET'])
            self.assertFalse((state / 'PRIVATE-DRAFT.json').exists())

    def test_fetch_rejects_mixed_case_synthetic_token_in_noncredential_key(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve()
            gh = p.GitHub('tester/private', 1, TOKEN)
            gh.private_guard = lambda: None
            gh.main = lambda: COMMIT
            gh.commit = lambda sha: TREE
            def git(args, cwd, config=None):
                if args[0] == 'rev-parse':
                    return (TREE + '\n').encode()
                if args[:3] == ['config', '--local', '--list']:
                    return b'nonsecret.label=' + TOKEN.encode() + b'\n'
                return b''
            with patch.object(p, 'run_git', side_effect=git):
                with self.assertRaises(p.Rejected) as caught:
                    p.fetch(argparse.Namespace(state=str(state), commit=COMMIT), gh)
            self.assertEqual(str(caught.exception), 'checkout-credential-persisted')
            self.assertFalse((state / 'FETCH.json').exists())

    def test_diagnostics_can_only_publish_privately_and_never_claim_firmware(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve()
            p.write_json(state / 'FETCH.json', {'schema_version': 1, 'repository_id': 1,
                                              'credential_persisted': False,
                                              'paired_commit': COMMIT, 'paired_tree': TREE})
            b.diagnostic_products(state, 'x86-64')
            gh = p.GitHub('tester/private', 1, TOKEN)
            writes = []
            def request(method, path, data=None, host=p.API, length=None):
                if path == gh.prefix:
                    return {'id': 1, 'full_name': 'tester/private', 'private': True,
                            'fork': False, 'default_branch': 'main'}
                if '/git/commits/' in path:
                    return {'sha': COMMIT, 'tree': {'sha': TREE}}
                writes.append((method, host))
                if host == p.UPLOAD:
                    value = data.read()
                    return {'name': path.split('name=', 1)[1], 'state': 'uploaded', 'size': len(value),
                            'digest': 'sha256:' + hashlib.sha256(value).hexdigest()}
                if method == 'POST':
                    self.assertIn('NO FIRMWARE', data['name'])
                    return {'id': 6, 'draft': True}
                return {'id': 6, 'draft': False}
            gh.request = request
            p.publish(argparse.Namespace(state=str(state), tag='personal-x86-64-456-1'), gh)
            self.assertFalse(json.loads((state / 'PUBLISHED.json').read_text())['firmware_complete'])
            self.assertTrue(all(host in (p.API, p.UPLOAD) for _, host in writes))
            self.assertEqual(sum(host == p.UPLOAD for _, host in writes), 3)

    def test_asset_symlink_hardlink_traversal_and_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve()
            (state / 'publish').mkdir()
            outside = state / 'outside'
            outside.write_bytes(b'synthetic')
            (state / 'publish/link.txt').symlink_to(outside)
            os.link(outside, state / 'publish/hard.txt')
            for name in ('link.txt', 'hard.txt', '../outside', 'bad\n.txt'):
                with self.subTest(name=name), self.assertRaises(p.Rejected):
                    p.regular_asset(state, name)


class BuildTests(unittest.TestCase):
    def test_target_selection_is_single_and_preserves_non_target_settings(self):
        content = '\n'.join(['CONFIG_TARGET_ALL_PROFILES=y',
            'CONFIG_TARGET_qualcommax=y', 'CONFIG_TARGET_qualcommax_ipq60xx=y',
            'CONFIG_TARGET_DEVICE_qualcommax_ipq60xx_DEVICE_qihoo_360v6=y',
            'CONFIG_TARGET_DEVICE_qualcommax_ipq807x_DEVICE_redmi_ax6=y',
            'CONFIG_TARGET_KERNEL_PARTSIZE=128', 'CONFIG_TARGET_ROOTFS_PARTSIZE=4096',
            'CONFIG_PACKAGE_luci-app-dockerman=y', 'CONFIG_PACKAGE_luci-theme-vantage=y'])
        for choice, (_, arch, target, subtarget, package_arch, device) in b.TARGETS.items():
            with self.subTest(choice=choice):
                result = b.select_target(content, choice)
                active = [x for x in result.splitlines() if x.endswith('=y') and '_DEVICE_' in x]
                self.assertEqual(active, ['CONFIG_TARGET_DEVICE_' + target + '_' + subtarget + '_DEVICE_' + device + '=y'])
                self.assertNotIn('CONFIG_TARGET_ALL_PROFILES=y', result)
                self.assertIn('CONFIG_TARGET_ROOTFS_PARTSIZE=4096', result)
                self.assertIn('CONFIG_PACKAGE_luci-app-dockerman=y', result)
                for package in ('box-private', 'sing-box', 'luci-app-homeproxy', 'luci-app-homeproxy-private'):
                    self.assertIn('CONFIG_PACKAGE_' + package + '=y', result)

    def test_build_environment_excludes_credentials_and_actions_cache_tokens(self):
        with patch.dict(os.environ, {'PERSONAL_PRIVATE_TOKEN': TOKEN, 'GITHUB_TOKEN': TOKEN,
            'GH_TOKEN': TOKEN, 'ACTIONS_RUNTIME_TOKEN': TOKEN, 'ACTIONS_CACHE_URL': 'secret-url',
            'BASH_ENV': 'startup', 'LD_PRELOAD': 'injected', 'GOFLAGS': '-mod=mod'}, clear=False):
            env = b.safe_environment(Path('/synthetic/state'), Path('/synthetic/checkout'), 'x86-64')
        self.assertNotIn(TOKEN, env.values())
        self.assertNotIn('secret-url', env.values())
        for key in ('PERSONAL_PRIVATE_TOKEN', 'ACTIONS_RUNTIME_TOKEN', 'ACTIONS_CACHE_URL', 'BASH_ENV', 'LD_PRELOAD'):
            self.assertNotIn(key, env)
        self.assertEqual(env['GOFLAGS'], '')
        self.assertEqual(env['GITHUB_TOKEN'], '')
        self.assertEqual(env['PRIVATE_PREBUILT_DIR'], '/synthetic/state/prepared')

    def test_precise_ui_and_core_apk_ipk_names_exclude_meta_package(self):
        for filename in ('luci-app-homeproxy-20261111-r1.apk',
                         'luci-app-homeproxy_20261111-1_all.ipk'):
            self.assertTrue(b.exact_package_filename('luci-app-homeproxy', filename))
        for filename in ('luci-app-homeproxy-private-1.15.0-r1.apk',
                         'luci-app-homeproxy-private_1.15.0-1_all.ipk',
                         'luci-app-homeproxy-old.apk', 'luci-app-homeproxy-20261111.apk.backup'):
            self.assertFalse(b.exact_package_filename('luci-app-homeproxy', filename))
        self.assertTrue(b.exact_package_filename('box-private', 'box-private-1.15.0_alpha.13-private.1-r1.apk'))
        self.assertTrue(b.exact_package_filename('box-private', 'box-private_1.15.0_alpha.13-private.1-1_x86_64.ipk'))

    def test_only_meta_and_core_cannot_create_complete_publish_inventory(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            state, root = base / 'state', base / 'firmware'
            state.mkdir(mode=0o700)
            root.mkdir(mode=0o700)
            build = b.Build(state, ROOT, root, 'x86-64')
            images = root / 'bin/targets/x86/64'
            packages = root / 'bin/packages/x86_64/personal_private'
            images.mkdir(parents=True)
            packages.mkdir(parents=True)
            (packages / 'box-private-1.15.0-r1.apk').write_bytes(b'synthetic')
            (packages / 'luci-app-homeproxy-private-1.15.0-r1.apk').write_bytes(b'synthetic')
            with self.assertRaises(b.transport.Rejected):
                build.products({'paired_commit': COMMIT, 'paired_tree': TREE}, 'c' * 40, {})
            self.assertFalse((state / 'PUBLISH.json').exists())

    def test_public_instruction_shadow_preserves_bytes_and_private_report_path(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            state, root = base / 'state', base / 'firmware'
            state.mkdir(mode=0o700)
            root.mkdir(mode=0o700)
            build = b.Build(state, ROOT, root, 'armsr-armv8')
            self.assertEqual(build.env['GITHUB_WORKSPACE'], str(state / 'workspace'))
            for name in ('Config', 'Scripts'):
                for path in (ROOT / name).rglob('*'):
                    if path.is_file():
                        copy = state / 'workspace' / name / path.relative_to(ROOT / name)
                        self.assertEqual(copy.read_bytes(), path.read_bytes())
            self.assertEqual(build.env['CARGO_HOME'], str(state / 'cargo'))
            self.assertTrue(Path(build.env['RUSTUP_HOME']).is_absolute())
            self.assertNotEqual(build.env['HOME'], os.environ['HOME'])

    def test_diagnostics_ignore_partial_firmware_and_hash_only_private_data(self):
        import tarfile
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve()
            (state / 'publish').mkdir()
            (state / 'publish/partial-firmware.img').write_bytes(b'NOT ready')
            (state / 'logs').mkdir()
            (state / 'logs/compiler.log').write_bytes(b'synthetic private diagnostic')
            p.write_json(state / 'FETCH.json', {'schema_version': 1, 'repository_id': 1,
                                              'credential_persisted': False,
                                              'paired_commit': COMMIT, 'paired_tree': TREE})
            b.diagnostic_products(state, 'armsr-armv8')
            marker = json.loads((state / 'PUBLISH.json').read_text())
            self.assertFalse(marker['firmware_complete'])
            self.assertEqual(marker['asset_directory'], 'diagnostics')
            self.assertEqual(len(marker['files_sha256']), 3)
            self.assertTrue((state / 'publish/partial-firmware.img').is_file())
            with tarfile.open(state / 'diagnostics/private-build-logs.tar.gz', 'r:gz') as archive:
                self.assertEqual(archive.getnames(), ['logs/compiler.log'])
            before = (state / 'PUBLISH.json').read_bytes()
            b.diagnostic_products(state, 'armsr-armv8')
            self.assertEqual(before, (state / 'PUBLISH.json').read_bytes())

    def test_diagnostics_without_verified_fetch_or_with_log_link_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve()
            with self.assertRaises((OSError, b.transport.Rejected)):
                b.diagnostic_products(state, 'x86-64')
            p.write_json(state / 'FETCH.json', {'schema_version': 1, 'repository_id': 1,
                                              'credential_persisted': False,
                                              'paired_commit': COMMIT, 'paired_tree': TREE})
            (state / 'logs').mkdir()
            (state / 'outside').write_bytes(b'not a controlled log')
            (state / 'logs/link').symlink_to(state / 'outside')
            with self.assertRaises(b.transport.Rejected):
                b.diagnostic_products(state, 'x86-64')
            self.assertFalse((state / 'PUBLISH.json').exists())

    def test_existing_incomplete_inventory_is_never_ready(self):
        for kind in ('truncated', 'directory', 'incomplete'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp:
                state = Path(temp).resolve()
                marker = state / 'PUBLISH.json'
                if kind == 'directory':
                    marker.mkdir()
                elif kind == 'truncated':
                    marker.write_text('{')
                else:
                    p.write_json(marker, {'schema_version': 1, 'complete': False})
                with self.assertRaises((ValueError, b.transport.Rejected)):
                    b.diagnostic_products(state, 'x86-64')
                self.assertFalse((state / 'diagnostics').exists())

    def test_json_marker_is_atomic_and_does_not_replace_existing_output(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp).resolve()
            marker = state / 'READY.json'
            with self.assertRaises(TypeError):
                p.write_json(marker, {'invalid': object()})
            self.assertFalse(marker.exists())
            p.write_json(marker, {'complete': True})
            self.assertEqual(marker.stat().st_nlink, 1)
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(state.iterdir()), [marker])
            with self.assertRaises(p.Rejected):
                p.write_json(marker, {'complete': False})
            self.assertTrue(json.loads(marker.read_text())['complete'])

    def test_caller_supplies_all_declared_required_inputs(self):
        import yaml
        core = yaml.safe_load((ROOT / '.github/workflows/WRT-CORE.yml').read_text())
        event = core.get('on', core.get(True))
        declared = event['workflow_call']['inputs']
        caller = yaml.safe_load((ROOT / '.github/workflows/PERSONAL-PRIVATE.yml').read_text())
        supplied = caller['jobs']['personal']['with']
        self.assertTrue(set(supplied).issubset(declared))
        self.assertTrue({name for name, value in declared.items() if value.get('required')}.issubset(supplied))

    def test_move_target_is_checked_before_shutil_move(self):
        # Source inspection is scoped to our new helper, not execution of any SDK.
        content = (HERE / 'personal-private-build.py').read_text(encoding='utf-8')
        self.assertLess(content.index('old.resolve(strict=True) == old'), content.index('shutil.move(str(old)'))
        self.assertIn("self.root / 'package/packages/luci-app-homeproxy'", content)
        self.assertNotIn('rm -rf', content)


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import yaml
        cls.yaml = yaml
        cls.current = yaml.safe_load((ROOT / '.github/workflows/WRT-CORE.yml').read_text())
        old = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'show', BASE + ':.github/workflows/WRT-CORE.yml'],
                             cwd=ROOT, capture_output=True, check=True)
        cls.old = yaml.safe_load(old.stdout)
        cls.caller = yaml.safe_load((ROOT / '.github/workflows/PERSONAL-PRIVATE.yml').read_text())

    def test_ordinary_core_is_exactly_preserved_except_default_false_gate(self):
        new = dict(self.current['jobs']['core'])
        self.assertEqual(new.pop('if'), '${{ !inputs.WRT_PERSONAL_PRIVATE }}')
        self.assertEqual(new, self.old['jobs']['core'])
        self.assertEqual(self.current['env'], self.old['env'])
        self.assertEqual(self.current['jobs']['cache-rollover'], self.old['jobs']['cache-rollover'])
        call = self.current.get('on', self.current.get(True))['workflow_call']
        self.assertIs(call['inputs']['WRT_PERSONAL_PRIVATE']['default'], False)

    def test_old_callers_are_byte_identical(self):
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            if path.name in ('WRT-CORE.yml', 'PERSONAL-PRIVATE.yml'):
                continue
            old = subprocess.run(['git', 'show', BASE + ':' + path.relative_to(ROOT).as_posix()],
                                 cwd=ROOT, capture_output=True, check=True)
            self.assertEqual(path.read_bytes(), old.stdout, path.name)

    def test_new_caller_has_no_automatic_event_or_public_docker(self):
        self.assertEqual(set(self.caller['on']), {'workflow_dispatch'})
        self.assertEqual(set(self.caller['jobs']), {'personal'})
        job = self.caller['jobs']['personal']
        self.assertTrue(job['with']['WRT_PERSONAL_PRIVATE'])
        self.assertEqual(job['secrets'], {'PERSONAL_PRIVATE_CONTENTS': '${{ secrets.PERSONAL_PRIVATE_CONTENTS }}'})
        for condition in (job['if'], self.current['jobs']['personal-private']['if']):
            for fragment in ("github.event_name == 'workflow_dispatch'", "github.actor == github.repository_owner",
                             "github.ref == 'refs/heads/main'", "github.repository == 'barton0426/immortalwrt_nss_ci'"):
                self.assertIn(fragment, condition)

    def test_private_secret_interface_is_optional_and_preflight_never_gets_token(self):
        call = self.current.get('on', self.current.get(True))['workflow_call']
        self.assertEqual(call['secrets'], {'PERSONAL_PRIVATE_CONTENTS': {'required': False}})
        job = self.current['jobs']['personal-private']
        self.assertEqual(job['env']['PERSONAL_PRIVATE_ALLOW_CLASSIC'], '${{ vars.PERSONAL_PRIVATE_ALLOW_CLASSIC }}')
        checks = [step for step in job['steps'] if 'PERSONAL_PRIVATE_SECRET_PRESENT' in step.get('env', {})]
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0]['env'], {'PERSONAL_PRIVATE_SECRET_PRESENT': "${{ secrets.PERSONAL_PRIVATE_CONTENTS != '' }}"})
        self.assertIn('exit 1', checks[0]['run'])
        self.assertNotIn('secrets.', checks[0]['run'])
        dependencies = next(step for step in job['steps'] if step['name'] == 'Prepare an isolated hosted build directory')
        self.assertLess(job['steps'].index(checks[0]), job['steps'].index(dependencies))

    def test_private_job_has_no_public_artifact_cache_or_release_action(self):
        job = self.current['jobs']['personal-private']
        self.assertEqual(job['environment'], 'personal-private')
        self.assertEqual(job['permissions'], {'contents': 'read'})
        self.assertEqual(job['env']['GITHUB_TOKEN'], '')
        self.assertEqual(job['env']['GH_TOKEN'], '')
        uses = [step['uses'] for step in job['steps'] if 'uses' in step]
        self.assertEqual(len(uses), 2)
        for action in uses:
            self.assertRegex(action, r'@(?:[0-9a-f]{40})$')
            self.assertNotIn('artifact', action)
            self.assertNotIn('cache', action)
            self.assertNotIn('release', action)
        self.assertFalse(job['steps'][0]['with']['persist-credentials'])
        self.assertFalse(job['steps'][1]['with']['cache'])
        secret_steps = [step for step in job['steps'] if 'PERSONAL_PRIVATE_TOKEN' in step.get('env', {})]
        self.assertEqual(len(secret_steps), 2)
        self.assertIn(' fetch ', secret_steps[0]['run'])
        self.assertIn(' publish ', secret_steps[1]['run'])
        for step in job['steps']:
            run = step.get('run', '')
            self.assertNotIn('set -x', run)
            self.assertNotIn('gh release', run)
            self.assertNotIn('collect-build-reports', run)
            self.assertNotIn('docker', run)


if __name__ == '__main__':
    unittest.main(verbosity=2)
