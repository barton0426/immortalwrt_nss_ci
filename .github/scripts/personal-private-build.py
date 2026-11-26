#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Use the ordinary Config/Scripts in a credential-free, uncached private job.

Nothing here is a deployment or a router runtime test. All child stdout/stderr,
including serial build failures, stays in 0600 files outside the public checkout.
Only a final, hash-bound inventory is eligible for the separate private publisher.
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('personal_transport', HERE / 'personal-private.py')
transport = importlib.util.module_from_spec(spec)
spec.loader.exec_module(transport)
need, directory, write_json, sha256 = transport.need, transport.directory, transport.write_json, transport.sha256
TARGETS = {
    'x86-64': ('X86', 'amd64', 'x86', '64', 'x86_64', 'generic'),
    'armsr-armv8': ('ARMSR', 'arm64', 'armsr', 'armv8', 'aarch64_generic', 'generic'),
    'ipq60xx-zn_m2': ('IPQ60XX-WIFI-YES', 'arm64', 'qualcommax', 'ipq60xx', 'aarch64_cortex-a53', 'zn_m2'),
    'ipq807x-redmi_ax6-stock': ('IPQ807X-WIFI-YES', 'arm64', 'qualcommax', 'ipq807x', 'aarch64_cortex-a53', 'redmi_ax6-stock'),
}
PUBLIC_SOURCE = 'https://github.com/VIKINGYFY/immortalwrt.git'
PAIRED_PACKAGES = ('sing-box', 'luci-app-homeproxy')
LEGACY_PACKAGES = ('box-private', 'luci-app-homeproxy-private', 'sing-box-tiny')
CORE_VERSION = '1.15.0-alpha.13-private.3'
CORE_APK_VERSION = '1.15.0_alpha13-r3'
CORE_IPK_VERSION = '1.15.0_alpha13-3'


def safe_environment(state, checkout, choice):
    config, arch, target, subtarget, package_arch, device = TARGETS[choice]
    # Deliberate allowlist: no Actions runtime/cache tokens, private PAT, Git auth,
    # trace/debug hooks, LD_PRELOAD, shell startup, proxies, or inherited GOFLAGS.
    env = {'PATH': os.environ['PATH'], 'HOME': str(state / 'home'),
           'TMPDIR': str(state / 'tmp'), 'USER': os.environ.get('USER', 'runner'),
           'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'GITHUB_WORKSPACE': str(state / 'workspace'),
           'CARGO_HOME': str(state / 'cargo'),
           'RUSTUP_HOME': os.environ.get('RUSTUP_HOME') or str(Path(os.environ['HOME']) / '.rustup'),
           'CCACHE_DIR': str(state / 'ccache'),
           'GITHUB_TOKEN': '', 'GH_TOKEN': '', 'GIT_CONFIG_NOSYSTEM': '1',
           'GIT_CONFIG_GLOBAL': '/dev/null', 'GIT_CONFIG_SYSTEM': '/dev/null',
           'GIT_TERMINAL_PROMPT': '0', 'GIT_ASKPASS': '/bin/false',
           'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_OPTIONAL_LOCKS': '0',
           'GOTOOLCHAIN': 'local', 'GOMAXPROCS': '2', 'GOWORK': 'off', 'GOENV': 'off',
           'GOFLAGS': '', 'CGO_ENABLED': '0', 'GOMODCACHE': str(state / 'gomod'),
           'GOCACHE': str(state / 'gocache'), 'GOPROXY': 'https://proxy.golang.org',
           'GOSUMDB': 'sum.golang.org', 'WRT_CONFIG': config, 'WRT_TARGET': target,
           'WRT_SUBTARGET': subtarget, 'WRT_THEME': 'vantage', 'WRT_NAME': 'OWRT',
           'WRT_SSID': 'OWRT', 'WRT_WORD': '12345678', 'WRT_IP': '192.168.10.1',
           'WRT_PW': '无', 'WRT_REPO': PUBLIC_SOURCE, 'WRT_BRANCH': 'owrt',
           'WRT_SOURCE': 'VIKINGYFY/immortalwrt', 'WRT_INFO': 'immortalwrt',
           'WRT_MARK': 'personal', 'WRT_PACKAGE': '', 'WRT_TEST': 'false',
           'WRT_WIFI': 'WIFI-YES' if target == 'qualcommax' else 'none',
           'WRT_DATE': datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).strftime('%Y%m%d-%H%M')}
    env['PRIVATE_PREBUILT_INPUT'] = str(state / 'cli-input')
    env['PRIVATE_PREBUILT_DIR'] = str(state / 'prepared')
    return env


def select_target(content, choice):
    config, arch, target, subtarget, package_arch, device = TARGETS[choice]
    # Do not inherit the public ZN M2/AX6 sibling selection or ALL_PROFILES.
    package_symbols = '|'.join(re.escape(name) for name in PAIRED_PACKAGES + LEGACY_PACKAGES)
    lines = [line for line in content.splitlines()
             if not re.match(r'^\s*#?\s*CONFIG_TARGET_(?:DEVICE_|ALL_PROFILES|MULTI_PROFILE|[a-z0-9]+(?:_|=))', line)
             and not re.match(r'^\s*#?\s*CONFIG_PACKAGE_(?:' + package_symbols + r')(?:=|\s+is not set\s*$)', line)]
    lines += ['CONFIG_TARGET_' + target + '=y', 'CONFIG_TARGET_' + target + '_' + subtarget + '=y',
              'CONFIG_TARGET_DEVICE_' + target + '_' + subtarget + '_DEVICE_' + device + '=y',
              '# CONFIG_TARGET_ALL_PROFILES is not set', 'CONFIG_TARGET_MULTI_PROFILE=y']
    lines += ['CONFIG_PACKAGE_' + name + '=y' for name in PAIRED_PACKAGES]
    return '\n'.join(lines) + '\n'


def exact_package_filename(name, filename):
    # APK: name-version.apk; IPK: name_version_arch.ipk. Versions in both
    # reviewed private recipes begin with a digit, so the empty '-private'
    # dependency package cannot masquerade as the actual HomeProxy UI.
    stem = re.escape(name)
    return bool(re.fullmatch(stem + r'-[0-9][A-Za-z0-9.+_~:-]*\.apk', filename) or
                re.fullmatch(stem + r'_[0-9][A-Za-z0-9.+_~:-]*_[A-Za-z0-9_]+\.ipk', filename))


def paired_product_inventory(images, packages, package_arch):
    """Check delivery identities against the producer's installed-package manifest."""
    entries = list(packages.iterdir())
    need(not any(exact_package_filename(name, path.name) for path in entries
                 for name in LEGACY_PACKAGES), 'legacy-paired-package-artifact')
    artifacts = {}
    for name in PAIRED_PACKAGES:
        matches = [path for path in entries if exact_package_filename(name, path.name)]
        need(len(matches) == 1, 'paired-package-artifacts-missing-or-duplicate')
        path = matches[0]
        need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode) and
             path.stat().st_nlink == 1 and 0 < path.stat().st_size <= transport.MAX_ASSET,
             'paired-package-artifact-invalid')
        if path.suffix == '.apk':
            version = path.name[len(name) + 1:-4]
        else:
            arch = 'all' if name == 'luci-app-homeproxy' and path.name.endswith('_all.ipk') else package_arch
            suffix = '_' + arch + '.ipk'
            need(path.name.endswith(suffix), 'paired-package-architecture-mismatch')
            version = path.name[len(name) + 1:-len(suffix)]
        if name == 'sing-box':
            need(version == (CORE_APK_VERSION if path.suffix == '.apk' else CORE_IPK_VERSION),
                 'paired-core-package-version-mismatch')
        artifacts[name] = {'filename': path.name, 'version': version, 'sha256': sha256(path)}
    manifests = list(images.glob('*.manifest'))
    need(manifests, 'firmware-package-manifest-missing')
    hashes = {}
    for path in manifests:
        need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode) and
             path.stat().st_nlink == 1 and path.stat().st_size <= 8 * 1024 * 1024,
             'firmware-package-manifest-invalid')
        installed = {}
        for line in path.read_text(encoding='utf-8').splitlines():
            if not line:
                continue
            match = re.fullmatch(r'([A-Za-z0-9+_.-]+) - ([A-Za-z0-9.+_~:-]+)', line)
            need(match is not None and match[1] not in installed, 'firmware-package-manifest-invalid')
            installed[match[1]] = match[2]
        need(not any(name in installed for name in LEGACY_PACKAGES), 'legacy-paired-package-installed')
        need(all(installed.get(name) == item['version'] for name, item in artifacts.items()),
             'firmware-paired-packages-mismatch')
        hashes[path.name] = sha256(path)
    return {'packages': artifacts, 'firmware_manifests_sha256': hashes}


def archive_tree(output, paths):
    need(not os.path.lexists(output), 'archive-output-already-exists')
    with tarfile.open(output, 'w:gz', format=tarfile.PAX_FORMAT) as archive:
        for prefix, root in paths:
            root = directory(root)
            for path in sorted(root.rglob('*')):
                need(not path.is_symlink(), 'artifact-link-invalid')
                if path.is_dir():
                    continue
                need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), 'artifact-file-invalid')
                archive.add(path, arcname=prefix + '/' + path.relative_to(root).as_posix(), recursive=False)
    output.chmod(0o600)
    need(0 < output.stat().st_size <= transport.MAX_ASSET, 'archive-size-invalid')


def diagnostic_products(state, choice):
    # Called without a token after a non-cancelled failure. Never reuse partial
    # firmware products or run checked-out source code to produce diagnostics.
    if os.path.lexists(state / 'PUBLISH.json'):
        marker = state / 'PUBLISH.json'
        need(marker.resolve(strict=True) == marker and stat.S_ISREG(marker.lstat().st_mode) and
             marker.stat().st_nlink == 1 and 0 < marker.stat().st_size <= transport.MAX_JSON,
             'complete-inventory-required')
        inventory = json.loads(marker.read_text(encoding='utf-8'))
        need(isinstance(inventory, dict) and inventory.get('schema_version') == 1 and
             inventory.get('complete') is True and
             ((inventory.get('asset_directory') == 'publish' and inventory.get('firmware_complete') is True) or
              (inventory.get('asset_directory') == 'diagnostics' and inventory.get('firmware_complete') is False)) and
             isinstance(inventory.get('files_sha256'), dict) and 3 <= len(inventory['files_sha256']) <= 16,
             'complete-inventory-required')
        for name, expected in inventory['files_sha256'].items():
            need(isinstance(expected, str) and re.fullmatch(r'[0-9a-f]{64}', expected) and
                 sha256(transport.regular_asset(state, name, inventory['asset_directory'])) == expected,
                 'complete-inventory-required')
        return
    fetch_path = state / 'FETCH.json'
    need(fetch_path.resolve(strict=True) == fetch_path and 0 < fetch_path.stat().st_size <= transport.MAX_JSON,
         'diagnostic-fetch-required')
    fetched = json.loads(fetch_path.read_text(encoding='utf-8'))
    need(isinstance(fetched, dict) and fetched.get('credential_persisted') is False and
         transport.SHA40.fullmatch(fetched.get('paired_commit', '')) and
         transport.SHA40.fullmatch(fetched.get('paired_tree', '')), 'diagnostic-source-binding')
    output = state / 'diagnostics'
    output.mkdir(mode=0o700)
    paths = [(name, state / path) for name, path in [('logs', 'logs'), ('reports', 'workspace/build-reports')]
             if os.path.lexists(state / path)]
    archive_tree(output / 'private-build-logs.tar.gz', paths)
    shutil.copyfile(fetch_path, output / 'FETCH-RECEIPT.json')
    write_json(output / 'BUILD-STOPPED.json', {'schema_version': 1, 'target_key': choice,
                                             'firmware_complete': False, 'diagnostics_only': True,
                                             'router_runtime_tested': False, 'partial_binaries_included': False})
    files = {path.name: sha256(path) for path in sorted(output.iterdir())}
    write_json(state / 'PUBLISH.json', {'schema_version': 1, 'complete': True,
                                      'firmware_complete': False, 'asset_directory': 'diagnostics',
                                      'paired_commit': fetched['paired_commit'], 'paired_tree': fetched['paired_tree'],
                                      'files_sha256': files})


class Build:
    def __init__(self, state, checkout, root, choice):
        self.state, self.checkout, self.root, self.choice = state, checkout, root, choice
        self.env = safe_environment(state, checkout, choice)
        self.sequence = 0
        for name in ('home', 'tmp', 'logs', 'workspace'):
            (state / name).mkdir(mode=0o700)
        # Ordinary scripts use GITHUB_WORKSPACE for Config/PRIVATE and reports.
        # A private shadow preserves their bytes without polluting the checked-out
        # public repository or a checkout action's post-job working directory.
        for name in ('Config', 'Scripts'):
            origin = directory(checkout / name)
            need(all(not path.is_symlink() for path in origin.rglob('*')), 'instruction-link-rejected')
            shutil.copytree(origin, state / 'workspace' / name)

    def run(self, label, args, cwd=None, allow_failure=False):
        need(re.fullmatch(r'[a-z0-9-]+', label), 'log-label-invalid')
        self.sequence += 1
        path = self.state / 'logs' / ('%02d-' % self.sequence + label + '.log')
        # Keep the log private from creation, independently of the caller's
        # umask. Only credential-free build children use OpenWrt's required 022;
        # the parent's 077 and the private directory boundaries are unchanged.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as log:
            process = subprocess.Popen(args, cwd=cwd or self.root, env=self.env,
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True, umask=0o022)
            try:
                result = process.wait(timeout=5 * 60 * 60)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
                raise
        path.chmod(0o600)
        need(result == 0 or allow_failure, 'build-command-failed-output-withheld')
        return result

    def script(self, label, relative):
        path = self.checkout / relative
        need(path.resolve(strict=True) == path and path.is_file(), 'public-script-invalid')
        self.run(label, ['bash', str(path)])

    def clone_firmware(self, revision):
        need(transport.SHA40.fullmatch(revision), 'firmware-full40-required')
        # The root is the exact, empty build directory created by this job.
        need(not any(self.root.iterdir()), 'buildroot-not-empty')
        self.run('firmware-init', ['git', '-c', 'core.hooksPath=/dev/null', 'init', '--quiet'])
        self.run('firmware-remote', ['git', 'remote', 'add', 'origin', PUBLIC_SOURCE])
        self.run('firmware-fetch', ['git', '-c', 'http.followRedirects=false', 'fetch', '--quiet',
                                   '--no-tags', '--depth=1', 'origin', revision])
        self.run('firmware-checkout', ['git', '-c', 'core.hooksPath=/dev/null', 'checkout', '--quiet', '--detach', revision])
        actual = transport.run_git(['rev-parse', 'HEAD'], self.root).decode('ascii').strip()
        need(actual == revision, 'firmware-pin-mismatch')

    def paired_feed(self):
        source, feed = self.state / 'source', self.state / 'feed'
        self.run('export-paired-feed', ['python3', '-I', '-B', str(source / '_downstream/openwrt/export-feed.py'), str(feed)])
        feed = directory(feed)
        original_manifest = (feed / 'FEED-MANIFEST.json').read_bytes()
        original = json.loads(original_manifest)
        need(type(original.get('schema_version')) is int and original['schema_version'] == 1 and
             original.get('complete') is True and original.get('contains_patched_homeproxy') is True and
             original.get('core_version') == CORE_VERSION and original.get('core_package') == 'sing-box' and
             original.get('core_command') == '/usr/bin/sing-box' and original.get('single_core') is True and
             isinstance(original.get('packages'), list) and
             all(isinstance(name, str) for name in original['packages']) and
             sorted(original['packages']) == sorted(PAIRED_PACKAGES), 'paired-feed-incomplete')
        need({path.name for path in feed.iterdir()} == set(PAIRED_PACKAGES) | {'FEED-MANIFEST.json'},
             'paired-feed-package-whitelist')
        inventory = {}
        for path in sorted(feed.rglob('*')):
            need(path.resolve(strict=True) == path and not path.is_symlink(), 'feed-file-invalid')
            if path.is_dir():
                continue
            need(stat.S_ISREG(path.lstat().st_mode) and path.stat().st_nlink == 1, 'feed-file-invalid')
            if path != feed / 'FEED-MANIFEST.json':
                inventory[path.relative_to(feed).as_posix()] = sha256(path)
        need(inventory == original.get('files_sha256') and 'sing-box/Makefile' in inventory and
             'luci-app-homeproxy/Makefile' in inventory, 'exported-feed-changed')
        # Preserve the paired manifest, then replace ONLY this runner's core recipe.
        # HomeProxy factory UCI/runtime files remain byte-identical to the paired source.
        write_json(feed / 'SOURCE-FEED-MANIFEST.json', original)
        (feed / 'sing-box/Makefile').write_bytes((HERE / 'prebuilt-box.Makefile').read_bytes())
        reader = feed / 'sing-box/private-prebuilt.py'
        need(not os.path.lexists(reader), 'unexpected-exported-prebuilt-reader')
        shutil.copyfile(HERE / 'private-prebuilt.py', reader)
        inventory = {path.relative_to(feed).as_posix(): sha256(path) for path in sorted(feed.rglob('*'))
                     if path.is_file() and path != feed / 'FEED-MANIFEST.json'}
        original.update(files_sha256=inventory, prebuilt_core_recipe=True,
                        source_export_sha256=hashlib.sha256(original_manifest).hexdigest())
        (feed / 'FEED-MANIFEST.json').write_text(json.dumps(original, sort_keys=True, indent=2) + '\n', encoding='utf-8')
        # Packages.sh installs both ordinary sources here. Validate ALL exact source,
        # backup and same-name alias paths before moving/removing the first one.
        moves = []
        for name, backup_name in (('sing-box', 'ordinary-sing-box-source'),
                                  ('luci-app-homeproxy', 'ordinary-homeproxy-source')):
            old = self.root / 'package/packages' / name
            backup = self.state / backup_name
            need(old.resolve(strict=True) == old and old.is_dir() and not old.is_symlink() and
                 backup.parent.resolve(strict=True) == self.state and not os.path.lexists(backup),
                 'ordinary-paired-source-location-invalid')
            moves.append((old, backup))
        alias_root = directory(self.root / 'package/feeds')
        aliases = []
        for name in PAIRED_PACKAGES:
            for alias in alias_root.glob('*/' + name):
                need(alias.parent.resolve(strict=True) == alias.parent and alias.is_symlink(),
                     'ordinary-paired-feed-alias-invalid')
                aliases.append(alias)
        feed_config = self.root / 'feeds.conf'
        need(not os.path.lexists(feed_config), 'unexpected-custom-feed-configuration')
        content = (self.root / 'feeds.conf.default').read_text(encoding='utf-8')
        need(not re.search(r'^src-\S+\s+personal_private\b', content, re.M), 'feed-name-collision')
        for old, backup in moves:
            shutil.move(str(old), str(backup))
        for alias in aliases:
            alias.unlink()  # Validated symlink itself only; never its target.
        feed_config.write_text(content + '\nsrc-link personal_private ' + str(feed) + '\n', encoding='utf-8')
        self.run('private-feed-update', ['./scripts/feeds', 'update', 'personal_private'])
        self.run('private-feed-install', ['./scripts/feeds', 'install', '-f', '-p', 'personal_private', *PAIRED_PACKAGES])
        for name in PAIRED_PACKAGES:
            alias = alias_root / 'personal_private' / name
            need(alias.parent.resolve(strict=True) == alias.parent and alias.is_symlink() and
                 alias.resolve(strict=True) == feed / name, 'paired-feed-link-mismatch')
            need(list(alias_root.glob('*/' + name)) == [alias], 'paired-feed-duplicate-alias')
        need(all(not os.path.lexists(old) for old, backup in moves), 'ordinary-paired-source-still-discoverable')

    def configuration_report(self, revision):
        # Preserve actual SDK inputs before the CLI, even when validation fails.
        # This imports reviewed public data-only code, never private source.
        spec = importlib.util.spec_from_file_location('personal_config_reader', HERE / 'private-prebuilt.py')
        reader = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = reader
        spec.loader.exec_module(reader)
        reader.directory(self.state / 'workspace')
        reports = self.state / 'workspace/build-reports'
        reports.mkdir(mode=0o700, exist_ok=True)
        reader.directory(reports)
        output = reports / 'configuration'
        output.mkdir(mode=0o700)
        reader.directory(output)
        _, arch, target, subtarget, package_arch, device = TARGETS[self.choice]
        base = 'target/linux/' + target
        sources = {
            'effective.config': ('.config', reader.MAX_CONFIG),
            'target-board.Makefile': (base + '/Makefile', reader.MAX_MK),
            'target-subtarget.mk': (base + '/' + subtarget + '/target.mk', reader.MAX_MK),
            'target-kconfig.in': ('tmp/.config-target.in', reader.MAX_KCONFIG),
            'package-kconfig.in': ('tmp/.config-package.in', 32 * 1024 * 1024),
        }
        data, inventory = {}, {}
        for name, (origin, limit) in sources.items():
            try:
                content = reader.read_regular(self.root, origin, limit)
            except reader.Rejected:
                raise transport.Rejected('configuration-snapshot-input-rejected') from None
            data[name] = content
            fd = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as stream:
                stream.write(content)
            inventory[name] = {'buildroot_path': origin, 'sha256': reader.digest(content), 'size': len(content)}
        config = data['effective.config'].decode('utf-8').split('\n')
        metadata = data['package-kconfig.in'].decode('utf-8')
        owners = {}
        for name in ('qt5base-gui', 'fwknopd', 'luci-app-fwknopd',
                     'squeezelite-custom', 'mihomo-alpha', 'mihomo-meta'):
            symbol = 'PACKAGE_' + name
            header = r'^[ \t]*(?:config|menuconfig)[ \t]+' + re.escape(symbol) + r'[ \t]*(?:#[^\n]*)?'
            declarations = re.findall(r'(?m)' + header + r'$', metadata)
            typed = re.findall(r'(?m)' + header + r'\n[ \t]*(?:bool|tristate)(?=[ \t\n]|$)', metadata)
            values = [line[len('CONFIG_' + symbol + '='):] for line in config
                      if line.startswith('CONFIG_' + symbol + '=')]
            values += ['n' for line in config if line == '# CONFIG_' + symbol + ' is not set']
            value = values[0] if len(values) == 1 and values[0] in ('y', 'm', 'n') else \
                'absent' if not values else 'invalid-or-duplicate'
            owners[name] = {'serialized_value': value, 'declaration_found': len(declarations) == len(typed) == 1,
                            'declaration_count': len(declarations), 'boolean_declaration_count': len(typed)}
        inactive = all(item['declaration_found'] and item['serialized_value'] in ('n', 'absent')
                       for item in owners.values())
        settings = {'config_sha256': reader.digest(data['effective.config']), 'goarch': arch,
                    'target': target, 'subtarget': subtarget, 'package_architecture': package_arch, 'device': device}
        report = {'schema_version': 1, 'stage': 'post-clean-defconfig-before-private-cli',
                  'firmware_commit': revision, 'target_key': self.choice, 'files': inventory,
                  'known_cycle_owner_packages': owners, 'known_cycle_owners_unselected': inactive,
                  'router_runtime_tested': False, 'firmware_complete': False}
        try:
            hashes = reader.check_target_files(self.root, settings)
            need(hashes == {item['buildroot_path']: item['sha256'] for name, item in inventory.items()
                            if name in ('target-board.Makefile', 'target-subtarget.mk', 'target-kconfig.in')},
                 'configuration-snapshot-changed')
            need(all('CONFIG_PACKAGE_' + name + '=y' in config for name in PAIRED_PACKAGES),
                 'paired-packages-not-selected')
            need(not any('CONFIG_PACKAGE_' + name + '=' + value in config
                         for name in LEGACY_PACKAGES for value in ('y', 'm')),
                 'legacy-paired-package-selected')
            report['target_config_preflight'] = 'passed'
        except (reader.Rejected, transport.Rejected) as error:
            report.update(target_config_preflight='rejected', reason=str(error))
            write_json(output / 'CONFIG-SNAPSHOT.json', report)
            raise transport.Rejected('effective-configuration-rejected') from None
        write_json(output / 'CONFIG-SNAPSHOT.json', report)
        need(inactive, 'known-kconfig-cycle-owner-requires-project-repair')

    def cli(self, fetched, revision):
        config, arch, target, subtarget, package_arch, device = TARGETS[self.choice]
        self.env['OUT_DIR'] = str(self.state / 'cli')
        self.run('private-cli-build', ['bash', str(self.state / 'source/_downstream/build-linux.sh'), arch],
                 cwd=self.state / 'source')
        out = directory(self.state / 'cli')
        source_path = out / 'SOURCE.json'
        source = json.loads(source_path.read_text(encoding='utf-8'))
        need(source.get('source_commit') == fetched['paired_commit'] and
             source.get('source_tree') == fetched['paired_tree'] and source.get('target_architecture') == arch,
             'fresh-cli-source-pin-mismatch')
        archives = list(out.glob('box-private-*-linux-' + arch + '-' + fetched['paired_commit'][:12] + '.tar.gz'))
        need(len(archives) == 1, 'one-cli-archive-required')
        archive = archives[0]
        binary = out / ('box-private-' + source['private_version'] + '-linux-' + arch)
        input_dir = self.state / 'cli-input'
        input_dir.mkdir(mode=0o700)
        shutil.copyfile(archive, input_dir / archive.name)
        settings = {'schema_version': 3, 'mode': 'firmware-prebuilt', 'firmware_commit': revision,
                    'cli_source_commit': source['source_commit'], 'cli_source_tree': source['source_tree'],
                    'paired_commit': fetched['paired_commit'], 'paired_tree': fetched['paired_tree'],
                    'config_sha256': sha256(self.root / '.config'), 'goarch': arch,
                    'package_architecture': package_arch, 'target': target, 'subtarget': subtarget,
                    'device': device, 'cli_archive': {'filename': archive.name, 'sha256': sha256(archive),
                                                   'binary_sha256': sha256(binary), 'source_sha256': sha256(source_path)}}
        write_json(input_dir / 'PREBUILT-INPUT.json', settings)
        reader = ['python3', '-I', '-B', str(HERE / 'private-prebuilt.py')]
        self.run('prebuilt-data-prepare', reader + ['prepare', '--buildroot', str(self.root),
                                                   '--input', str(input_dir), '--out', self.env['PRIVATE_PREBUILT_DIR']])
        self.run('prebuilt-data-recheck', reader + ['check-prepared', '--buildroot', str(self.root),
                                                   '--input', str(input_dir), '--prepared', self.env['PRIVATE_PREBUILT_DIR']])
        return source

    def archive(self, name, paths):
        archive_tree(self.state / 'publish' / name, paths)

    def products(self, fetched, revision, source):
        config, arch, target, subtarget, package_arch, device = TARGETS[self.choice]
        publish = self.state / 'publish'
        publish.mkdir(mode=0o700)
        images = directory(self.root / 'bin/targets' / target / subtarget)
        packages = directory(self.root / 'bin/packages' / package_arch / 'personal_private')
        paired_products = paired_product_inventory(images, packages, package_arch)
        self.archive('firmware-and-packages.tar.gz', [('firmware', images), ('packages', packages)])
        source_archive = source.get('source_archive', {})
        name = source_archive.get('filename', '')
        need(re.fullmatch(r'box-private-source-[0-9a-f]{40}-(amd64|arm64)\.tar\.gz', name), 'source-archive-name')
        corresponding = self.state / 'cli' / name
        need(corresponding.resolve(strict=True) == corresponding and stat.S_ISREG(corresponding.lstat().st_mode) and
             corresponding.stat().st_nlink == 1 and corresponding.stat().st_size <= transport.MAX_ASSET and
             sha256(corresponding) == source_archive.get('sha256'), 'corresponding-source-hash')
        # Keep CLI, exact corresponding source/dependency notices, and fresh paired
        # HomeProxy source privately. Historical aa1 files are never relabelled.
        for path in (self.state / 'cli').glob('*.tar.gz'):
            need(path.resolve(strict=True) == path and stat.S_ISREG(path.lstat().st_mode), 'cli-product-invalid')
            shutil.copyfile(path, publish / path.name)
        self.run('retain-paired-source', ['git', '-c', 'core.hooksPath=/dev/null', 'archive', '--format=tar.gz',
                                          '--output=' + str(publish / 'paired-source.tar.gz'), fetched['paired_commit']],
                 cwd=self.state / 'source')
        self.archive('paired-feed.tar.gz', [('personal_private', self.state / 'feed')])
        self.archive('private-build-logs.tar.gz', [('logs', self.state / 'logs'),
                                                  ('reports', self.state / 'workspace/build-reports')])
        # The small record binds config and inputs; it does not claim device testing.
        metadata = {'schema_version': 1, 'paired_commit': fetched['paired_commit'], 'paired_tree': fetched['paired_tree'],
                    'firmware_commit': revision, 'target': target, 'subtarget': subtarget, 'device': device,
                    'package_architecture': package_arch, 'goarch': arch, 'config_sha256': sha256(self.root / '.config'),
                    'prebuilt_input_sha256': sha256(self.state / 'cli-input/PREBUILT-INPUT.json'),
                    'prebuilt_manifest_sha256': sha256(self.state / 'prepared/PREBUILT-MANIFEST.json'),
                    'cli_runtime_evidence': json.loads((self.state / 'cli' / ('runtime-evidence-' + arch + '.json')).read_text()),
                    'router_runtime_tested': False, 'native_bypass_enabled_by_build': False,
                     'core_package': 'sing-box', 'core_command': '/usr/bin/sing-box',
                     'core_private_version': source['private_version'], 'paired_products': paired_products,
                     'homeproxy_backend_selection_required': False, 'homeproxy_factory_config_preserved': True,
                     'existing_upgrade_uci_preserved': True,
                    'shared_cache_used': False, 'public_artifact_upload': False}
        write_json(publish / 'BUILD-RECEIPT.json', metadata)
        shutil.copyfile(self.root / '.config', publish / 'effective.config')
        shutil.copyfile(self.state / 'cli-input/PREBUILT-INPUT.json', publish / 'PREBUILT-INPUT.json')
        if self.choice == 'x86-64':
            shutil.copyfile(self.state / 'X86-GPT.json', publish / 'X86-GPT.json')
        files = {path.name: sha256(path) for path in sorted(publish.iterdir())}
        write_json(self.state / 'PUBLISH.json', {'schema_version': 1, 'complete': True,
                                              'firmware_complete': True, 'asset_directory': 'publish',
                                              'paired_commit': fetched['paired_commit'], 'paired_tree': fetched['paired_tree'],
                                              'files_sha256': files})

    def build(self, revision):
        fetched = json.loads((self.state / 'FETCH.json').read_text(encoding='utf-8'))
        need(fetched.get('credential_persisted') is False and transport.SHA40.fullmatch(fetched.get('paired_commit', '')),
             'verified-source-fetch-required')
        self.clone_firmware(revision)
        if self.choice == 'x86-64':
            self.run('x86-gpt-prepare', ['python3', '-I', '-B', str(HERE / 'x86-gpt-image.py'),
                                         'prepare', str(self.root), str(self.state)])
        self.run('public-feed-update', ['./scripts/feeds', 'update', '-a'])
        self.run('public-feed-install', ['./scripts/feeds', 'install', '-a'])
        self.script('ordinary-packages', 'Scripts/Packages.sh')
        self.script('ordinary-handles', 'Scripts/Handles.sh')
        self.script('ordinary-i2c-tools', '.github/scripts/prepare-i2c-tools.sh')
        config = TARGETS[self.choice][0]
        content = (self.checkout / 'Config' / (config + '.txt')).read_text(encoding='utf-8')
        content += '\n' + (self.checkout / 'Config/GENERAL.txt').read_text(encoding='utf-8')
        (self.root / '.config').write_text(select_target(content, self.choice), encoding='utf-8')
        self.script('ordinary-settings', 'Scripts/Settings.sh')
        self.paired_feed()
        self.script('ordinary-build-host', '.github/scripts/prepare-build-host.sh')
        (self.root / '.config').write_text(select_target((self.root / '.config').read_text(encoding='utf-8'),
                                                       self.choice), encoding='utf-8')
        self.run('effective-defconfig', ['make', '-j2', 'defconfig'])
        self.run('initial-build-clean', ['make', '-j2', 'clean'])
        # Regenerate authoritative target Kconfig if clean removed tmp metadata.
        self.run('post-clean-defconfig', ['make', '-j2', 'defconfig'])
        self.configuration_report(revision)
        source = self.cli(fetched, revision)
        self.script('ordinary-rust', '.github/scripts/prepare-rust.sh')
        jobs = '-j' + str(max(1, os.cpu_count() or 1))
        if self.choice == 'x86-64':
            self.run('x86-gpt-recheck', ['python3', '-I', '-B', str(HERE / 'x86-gpt-image.py'),
                                         'recheck', str(self.root), str(self.state)])
        self.run('firmware-download', ['make', jobs, 'download'])
        if self.run('firmware-parallel', ['make', jobs], allow_failure=True) != 0:
            self.run('firmware-serial', ['make', '-j1', 'V=s'])
        self.run('final-prebuilt-recheck', ['python3', '-I', '-B', str(HERE / 'private-prebuilt.py'), 'check-prepared',
                                           '--buildroot', str(self.root), '--input', self.env['PRIVATE_PREBUILT_INPUT'],
                                           '--prepared', self.env['PRIVATE_PREBUILT_DIR']])
        if self.choice == 'x86-64':
            self.run('x86-gpt-verify', ['python3', '-I', '-B', str(HERE / 'x86-gpt-image.py'),
                                        'verify', str(self.root), str(self.state)])
        self.products(fetched, revision, source)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', required=True)
    parser.add_argument('--checkout', required=True)
    parser.add_argument('--buildroot', required=True)
    parser.add_argument('--target', required=True, choices=tuple(TARGETS))
    parser.add_argument('--firmware-commit', required=True)
    parser.add_argument('--diagnostics', action='store_true')
    args = parser.parse_args()
    try:
        need(not os.environ.get('PERSONAL_PRIVATE_TOKEN') and not os.environ.get('GITHUB_TOKEN') and
             not os.environ.get('GH_TOKEN'), 'credentials-must-not-enter-build-step')
        state, checkout, root = directory(args.state), directory(args.checkout), directory(args.buildroot)
        paths = (state, checkout, root)
        need(all(a != other and a not in other.parents and other not in a.parents
                 for index, a in enumerate(paths) for other in paths[index + 1:]), 'build-paths-overlap')
        if args.diagnostics:
            diagnostic_products(state, args.target)
        else:
            Build(state, checkout, root, args.target).build(args.firmware_commit)
        print('Personal output prepared. Products or diagnostics await PRIVATE publication only.')
        return 0
    except (transport.Rejected, OSError, ValueError, TypeError, KeyError, UnicodeError,
            subprocess.SubprocessError, tarfile.TarError, RecursionError):
        print('Personal build stopped. Build output is withheld; no public fallback is allowed.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
