"""Offline synthetic security regression tests; no SDK or real CLI execution.

Scratch is NEW private temp directories, deliberately retained on failure/success.
The reader's executable/network entry points are mocked to fail if ever called.
Real historical archives are exercised separately by the controlled caller, not
embedded in this public test file and never copied into the public checkout.
"""
import ast
import contextlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location('private_prebuilt', HERE / 'private-prebuilt.py')
pb = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pb
SPEC.loader.exec_module(pb)


def encoded(value):
    return (json.dumps(value, sort_keys=True) + '\n').encode()


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def build_text(arch, overrides=None):
    values = {'-buildmode': 'exe', '-compiler': 'gc', '-tags': pb.TAGS,
              '-trimpath': 'true', 'CGO_ENABLED': '0', 'GOARCH': arch,
              'GOOS': 'linux', 'GOAMD64' if arch == 'amd64' else 'GOARM64':
              'v1' if arch == 'amd64' else 'v8.0'}
    values.update(overrides or {})
    return ('path\t' + pb.MODULE + '/cmd/sing-box\nmod\t' + pb.MODULE + '\t(devel)\t\n' +
            ''.join('build\t' + key + '=' + value + '\n' for key, value in values.items()))


def elf(arch='amd64', overrides=None, extra_kind=None, go_version=None):
    """A data fixture, not an executable program; includes genuine-format Go info."""
    text = build_text(arch, overrides)
    version = (go_version or 'go' + pb.GO_VERSION).encode()
    module = pb.GO_MOD_START + text.encode() + pb.GO_MOD_END
    info = pb.GO_MAGIC + b'\x08\x02' + b'\0' * 16
    info += varint(len(version)) + version + varint(len(module)) + module
    info += b'\0' * (-len(info) % 16)
    base, offset = 0x400000, 4096
    names = b'\0.go.buildinfo\0.shstrtab\0'
    names_offset = offset + len(info)
    shoff = (names_offset + len(names) + 7) // 8 * 8
    kinds = (1, 1) + (() if extra_kind is None else (extra_kind,))
    length = shoff + 3 * 64
    ident = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    header = struct.pack('<16sHHIQQQIHHHHHH', ident, 2,
                         62 if arch == 'amd64' else 183, 1,
                         base + 512, 64, shoff, 0, 64, 56, len(kinds), 64, 3, 2)
    ph = struct.pack('<IIQQQQQQ', 1, 5, 0, base, base, offset, offset, 4096)
    ph += struct.pack('<IIQQQQQQ', 1, 6, offset, base + offset, base + offset,
                      len(info), len(info), 4096)
    if extra_kind is not None:
        ph += struct.pack('<IIQQQQQQ', extra_kind, 4, offset, base + offset,
                          base + offset, 0, 0, 1)
    data = bytearray(length)
    data[:64] = header
    data[64:64 + len(ph)] = ph
    data[offset:offset + len(info)] = info
    data[names_offset:names_offset + len(names)] = names
    sections = b'\0' * 64
    sections += struct.pack('<IIQQQQIIQQ', 1, 1, 3, base + offset, offset, len(info), 0, 0, 16, 0)
    sections += struct.pack('<IIQQQQIIQQ', 14, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
    data[shoff:] = sections
    artifact = ('box-private: ' + version.decode() + '\n' +
                ''.join('\t' + line + '\n' for line in text.splitlines())).encode()
    return bytes(data), artifact


def archive(entries, fmt=tarfile.USTAR_FORMAT, modes=None):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode='w', format=fmt) as stream:
        for name, data, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.mode = (modes or {}).get(name, 0o755 if name == 'box-private' else 0o644)
            if kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
                item.linkname = 'box-private'
            item.size = len(data) if kind in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
            stream.addfile(item, io.BytesIO(data) if item.size else None)
    return gzip.compress(result.getvalue(), mtime=0)


class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='private-prebuilt-test-')).absolute()
        self.root.chmod(0o700)
        self.buildroot = self.root / 'buildroot'
        self.inputs = self.root / 'input'
        self.buildroot.mkdir(mode=0o700)
        self.inputs.mkdir(mode=0o700)
        self.out = self.root / 'out'
        self.reset()

    def reset(self, key=None):
        key = key or next(iter(pb.TARGETS))
        arch, board, subtarget, package, device = key
        self.arch = arch
        cfgarch = pb.TARGETS[key]
        self.config = ('# Synthetic resolved configuration, NOT a firmware build\n' +
                       'CONFIG_HAVE_DOT_CONFIG=y\nCONFIG_ARCH_64BIT=y\nCONFIG_' + cfgarch + '=y\n' +
                       'CONFIG_ARCH="' + cfgarch + '"\nCONFIG_USE_MUSL=y\nCONFIG_LIBC="musl"\n' +
                       'CONFIG_TARGET_SUFFIX="musl"\n# CONFIG_BIG_ENDIAN is not set\n' +
                       'CONFIG_TARGET_ARCH_PACKAGES="' + package + '"\nCONFIG_TARGET_BOARD="' + board +
                       '"\nCONFIG_TARGET_SUBTARGET="' + subtarget + '"\nCONFIG_TARGET_' + board + '=y\n' +
                       'CONFIG_TARGET_' + board + '_' + subtarget + '=y\nCONFIG_TARGET_' + board + '_' +
                       subtarget + '_DEVICE_' + device + '=y\n').encode()
        (self.buildroot / '.config').write_bytes(self.config)
        generated = self.buildroot / 'tmp'
        generated.mkdir(mode=0o700, exist_ok=True)
        declaration = (board + '_' + subtarget + '_DEVICE_' + device)
        (generated / '.config-target.in').write_text(
            '# Synthetic generated target metadata, not real defconfig output\n' +
            'config TARGET_' + declaration + '\n\tbool "Synthetic device"\n' +
            '\tdepends on TARGET_' + board + '_' + subtarget + '\n\n' +
            'menu "Target Devices"\n\tdepends on TARGET_MULTI_PROFILE\n' +
            'menuconfig TARGET_DEVICE_' + declaration + '\n\tbool "Synthetic device"\n' +
            '\tdepends on TARGET_' + board + '_' + subtarget + '\nendmenu\n')
        directory = self.buildroot / 'target/linux' / board
        (directory / subtarget).mkdir(parents=True, exist_ok=True, mode=0o700)
        board_text = ('include $(TOPDIR)/rules.mk\nBOARD:=' + board + '\n')
        if board == 'x86':
            board_text += 'ARCH:=i386\nSUBTARGETS:=64 generic legacy geode\n'
            sub_text = 'ARCH:=x86_64\nBOARDNAME:=x86_64\n'
        elif board == 'armsr':
            sub_text = 'ARCH:=aarch64\nSUBTARGET:=armv8\n'
        else:
            board_text += 'ARCH:=aarch64\nCPU_TYPE:=cortex-a53\nSUBTARGETS:=ipq807x ipq60xx ipq50xx\n'
            sub_text = 'SUBTARGET:=' + subtarget + '\n'
        (directory / 'Makefile').write_text(board_text + 'include $(INCLUDE_DIR)/target.mk\n')
        (directory / subtarget / 'target.mk').write_text(sub_text)
        self.mk = directory / subtarget / 'target.mk'
        self.board_mk = directory / 'Makefile'
        self.license = b'Synthetic root license\n'
        self.modification = b'Synthetic modification notice\n'
        self.notice = b'Synthetic selected source notice\n'
        notices = [('LICENSE', self.license), ('MODIFICATION-NOTICE.md', self.modification),
                   ('src/copyright.go', self.notice)]
        self.modules = [{'id': 'synthetic-main', 'module': pb.MODULE, 'main': True,
                         'notices': {'LICENSE': pb.digest(self.license),
                                     'MODIFICATION-NOTICE.md': pb.digest(self.modification)},
                         'source_notice_files': {'src/copyright.go': pb.digest(self.notice)}}]
        self.blob_files = {'licenses/blobs/' + pb.digest(data) + '.txt': data for _, data in notices}
        self.licenses = {'schema_version': 1, 'modules': self.modules,
                         'supplemental_license_texts': {'GPL-3.0.txt': pb.digest(b'GPL'),
                                                       'MPL-2.0.txt': pb.digest(b'MPL')},
                         'notice_blobs': {pb.digest(data): {'archive_path': 'licenses/blobs/' + pb.digest(data) + '.txt',
                                                          'sources': []} for _, data in notices}}
        self.source = {'schema_version': 1, 'implementation': 'box-private',
                       'module_identity': pb.MODULE, 'go_version': pb.GO_VERSION,
                       'private_version': pb.VERSION, 'build_tags': pb.TAGS,
                       'cgo_enabled': False, 'source_commit': 'a' * 40,
                       'source_tree': 'b' * 40, 'target_architecture': arch,
                       'git_archive_sha256': 'c' * 64,
                       'source_archive': {'filename': 'box-private-source-' + 'a' * 40 + '-' + arch + '.tar.gz',
                                          'sha256': 'd' * 64},
                       'modules': self.modules}
        self.binary, self.build = elf(arch)
        self.runtime = {'schema_version': 1, 'source_commit': 'a' * 40,
                        'target_architecture': arch, 'private_features': None,
                        'runtime_validation': 'cross-built-not-run'}
        self.settings = {'schema_version': pb.SCHEMA, 'mode': 'firmware-prebuilt',
                         'firmware_commit': 'e' * 40, 'cli_source_commit': 'a' * 40,
                         'cli_source_tree': 'b' * 40, 'paired_commit': 'f' * 40,
                         'paired_tree': '0' * 40, 'config_sha256': pb.digest(self.config),
                         'goarch': arch, 'package_architecture': package,
                         'target': board, 'subtarget': subtarget, 'device': device,
                         'cli_archive': {'filename': 'cli.tar.gz', 'sha256': '',
                                         'binary_sha256': '', 'source_sha256': ''}}
        self.extra, self.omitted = [], set()
        self.repack()

    def repack(self, update_license=True):
        if update_license:
            self.source['licenses_manifest_sha256'] = pb.digest(encoded(self.licenses))
        files = {'box-private': self.binary, 'SOURCE.json': encoded(self.source),
                 'LICENSE': self.license, 'MODIFICATION-NOTICE.md': self.modification,
                 'licenses/LICENSES.json': encoded(self.licenses), 'licenses/GPL-3.0.txt': b'GPL',
                 'licenses/MPL-2.0.txt': b'MPL', **self.blob_files,
                 'licenses/unlisted-THIRD-PARTY-NOTICE': b'MUST ALSO RETAIN',
                 'build-info-' + self.arch + '.txt': self.build,
                 'runtime-evidence-' + self.arch + '.json': encoded(self.runtime)}
        self.base = [(name, data, tarfile.REGTYPE) for name, data in files.items() if name not in self.omitted]
        self.write_archive(archive(self.base + self.extra))
        self.settings['cli_archive']['binary_sha256'] = pb.digest(self.binary)
        self.settings['cli_archive']['source_sha256'] = pb.digest(encoded(self.source))
        self.save_settings()

    def save_settings(self):
        (self.inputs / pb.INPUT).write_bytes(encoded(self.settings))

    def write_archive(self, data):
        (self.inputs / 'cli.tar.gz').write_bytes(data)
        self.settings['cli_archive']['sha256'] = pb.digest(data)
        self.save_settings()

    def check(self):
        return pb.check(self.buildroot, self.inputs)

    def reject(self, reason=None):
        with self.assertRaises(pb.Rejected) as caught:
            self.check()
        if reason:
            self.assertEqual(str(caught.exception), reason)

    def config_change(self, before, after):
        self.config = self.config.replace(before.encode(), after.encode())
        (self.buildroot / '.config').write_bytes(self.config)
        self.settings['config_sha256'] = pb.digest(self.config)
        self.save_settings()

    def cli(self, args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            rc = pb.main(args)
        return rc, stdout.getvalue(), stderr.getvalue()

    def test_normal_check_is_read_only_and_commits_are_separate(self):
        before = {path.relative_to(self.root): path.read_bytes()
                  for path in self.root.rglob('*') if path.is_file()}
        bundle = self.check()
        self.assertNotEqual(bundle.settings['cli_source_commit'], bundle.settings['paired_commit'])
        after = {path.relative_to(self.root): path.read_bytes()
                 for path in self.root.rglob('*') if path.is_file()}
        self.assertEqual(before, after)
        self.assertFalse(self.out.exists())

    def test_all_four_audited_target_tuples_prepare_and_recheck(self):
        for index, key in enumerate(pb.TARGETS):
            with self.subTest(key=key):
                self.reset(key)
                out = self.root / ('prepared-' + str(index))
                pb.prepare(self.buildroot, self.inputs, out)
                bundle = pb.check_prepared(self.buildroot, self.inputs, out)
                self.assertEqual(target := pb.target_key(bundle.settings), key)
                self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
                self.assertEqual((out / 'box-private').read_bytes(), self.binary)
                self.assertEqual((out / 'licenses/unlisted-THIRD-PARTY-NOTICE').read_bytes(), b'MUST ALSO RETAIN')
                self.assertEqual(stat.S_IMODE((out / 'box-private').stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE((out / pb.MANIFEST).stat().st_mode), 0o600)
                manifest = json.loads((out / pb.MANIFEST).read_bytes())
                self.assertEqual(manifest, pb.manifest_for(bundle))
                self.assertFalse(manifest['corresponding_source_archive_verified'])
                self.assertFalse(manifest['runtime_execution_claimed'])
                self.assertEqual(set(manifest['target_files_sha256']),
                                 {'target/linux/' + target[1] + '/Makefile',
                                  'target/linux/' + target[1] + '/' + target[2] + '/target.mk',
                                  'tmp/.config-target.in'})

    def test_redmi_device_symbol_retains_raw_profile_id(self):
        self.reset(list(pb.TARGETS)[3])
        self.assertIn(b'_DEVICE_redmi_ax6-stock=y', self.config)
        self.check()
        self.config_change('_DEVICE_redmi_ax6-stock=y', '_DEVICE_redmi_ax6_stock=y')
        self.reject('config-target-or-abi')

    def test_multi_profile_means_one_device_and_actual_generated_selector(self):
        for key in pb.TARGETS:
            with self.subTest(key=key):
                self.reset(key)
                single = pb.device_symbol(self.settings, False)
                multi = pb.device_symbol(self.settings, True)
                self.config_change(single + '=y', 'CONFIG_TARGET_MULTI_PROFILE=y\n' + multi + '=y')
                self.check()
        self.config_change('# Synthetic', 'CONFIG_TARGET_DEVICE_qualcommax_ipq807x_DEVICE_other=y\n# Synthetic')
        self.reject('config-multiple-targets')

    def test_per_device_rootfs_policy_is_not_a_device_selector(self):
        for key in pb.TARGETS:
            for multi in (False, True):
                for value in ('y', 'n'):
                    with self.subTest(key=key, multi=multi, value=value):
                        self.reset(key)
                        if multi:
                            single = pb.device_symbol(self.settings, False)
                            selected = pb.device_symbol(self.settings, True)
                            self.config_change(single + '=y', '# ' + single + ' is not set\n' +
                                               'CONFIG_TARGET_MULTI_PROFILE=y\n' + selected + '=y')
                        self.config_change('# Synthetic', 'CONFIG_TARGET_PER_DEVICE_ROOTFS=' +
                                           value + '\n# Synthetic')
                        bundle = self.check()
                        self.assertEqual(bundle.settings['config_sha256'], pb.digest(self.config))
                        self.assertEqual(pb.check_config(self.config, self.settings),
                                         pb.device_symbol(self.settings, multi))

    def test_per_device_rootfs_policy_requires_an_exact_boolean(self):
        for multi in (False, True):
            for value in ('m', '', '"y"', '1', '0', '-1', '0Xf'):
                with self.subTest(multi=multi, value=value):
                    self.reset()
                    if multi:
                        self.config_change(pb.device_symbol(self.settings, False) + '=y',
                                           'CONFIG_TARGET_MULTI_PROFILE=y\n' +
                                           pb.device_symbol(self.settings, True) + '=y')
                    self.config_change('# Synthetic', 'CONFIG_TARGET_PER_DEVICE_ROOTFS=' +
                                       value + '\n# Synthetic')
                    self.reject('config-target-or-abi')

    def test_rootfs_policy_does_not_loosen_other_device_or_alias_selection(self):
        for key in pb.TARGETS:
            for multi in (False, True):
                for extra in (pb.device_symbol({'target': key[1], 'subtarget': key[2],
                                                'device': key[4]}, not multi) + '=y',
                              'CONFIG_TARGET_PER_DEVICE_ROOTFS_EXTRA=y',
                              'CONFIG_TARGET_PER_DEVICE_ROOTFS.other=y',
                              'CONFIG_TARGET_PER_DEVICE_ROOTFS/variant=m',
                              'CONFIG_TARGET_DEVICE_PER_DEVICE_ROOTFS=y',
                              'CONFIG_TARGET_DEVICE_x86_64_DEVICE_other=y',
                              'CONFIG_TARGET_DEVICE_armsr_armv8_DEVICE_other=m'):
                    with self.subTest(key=key, multi=multi, extra=extra):
                        self.reset(key)
                        if multi:
                            self.config_change(pb.device_symbol(self.settings, False) + '=y',
                                               'CONFIG_TARGET_MULTI_PROFILE=y\n' +
                                               pb.device_symbol(self.settings, True) + '=y')
                        self.config_change('# Synthetic', 'CONFIG_TARGET_PER_DEVICE_ROOTFS=y\n' +
                                           extra + '\n# Synthetic')
                        self.reject('config-multiple-targets')

    def test_rootfs_policy_keeps_config_hash_duplicate_and_abi_gates(self):
        for mutation in ('unbound-config', 'duplicate-policy', 'other-abi', 'other-board'):
            with self.subTest(mutation=mutation):
                self.reset()
                self.config_change(pb.device_symbol(self.settings, False) + '=y',
                                   'CONFIG_TARGET_MULTI_PROFILE=y\n' +
                                   pb.device_symbol(self.settings, True) + '=y')
                self.config_change('# Synthetic', 'CONFIG_TARGET_PER_DEVICE_ROOTFS=y\n# Synthetic')
                if mutation == 'unbound-config':
                    (self.buildroot / '.config').write_bytes(self.config + b'# changed raw config\n')
                    self.reject('config-hash')
                elif mutation == 'duplicate-policy':
                    self.config_change('# Synthetic', 'CONFIG_TARGET_PER_DEVICE_ROOTFS=n\n# Synthetic')
                    self.reject('config-duplicate')
                elif mutation == 'other-abi':
                    self.config_change('CONFIG_ARCH="x86_64"', 'CONFIG_ARCH="aarch64"')
                    self.reject('config-target-or-abi')
                else:
                    self.config_change('CONFIG_TARGET_BOARD="x86"', 'CONFIG_TARGET_BOARD="armsr"')
                    self.reject('config-target-or-abi')

    def test_generated_target_selector_is_required_and_hash_bound(self):
        generated = self.buildroot / 'tmp/.config-target.in'
        generated.write_text('config OTHER\n\tbool "Not selected"\n')
        self.reject('target-kconfig-device')
        self.reset()
        generated.write_text(generated.read_text().replace('depends on TARGET_x86_64', 'depends on TARGET_armsr_armv8'))
        self.reject('target-kconfig-device')
        self.reset()
        original = generated.read_text()
        for mutation in (original.replace('\tbool', '\ttristate'),
                         original.replace('config TARGET_x86_64_DEVICE_generic',
                                          'menuconfig TARGET_x86_64_DEVICE_generic'),
                         original + original):
            with self.subTest(mutation='generated-declaration'):
                generated.write_text(mutation)
                self.reject('target-kconfig-device')
        generated.write_text(original)
        pb.prepare(self.buildroot, self.inputs, self.out)
        generated.write_text(original + '\n# valid later target metadata mutation\n')
        with self.assertRaisesRegex(pb.Rejected, 'prepared-manifest-binding'):
            pb.check_prepared(self.buildroot, self.inputs, self.out)

    def test_implicit_archive_directories_also_count_toward_limit(self):
        data = archive([('licenses/a/b/c/data.txt', b'data', tarfile.REGTYPE)])
        with patch.object(pb, 'MAX_MEMBERS', 3):
            with self.assertRaisesRegex(pb.Rejected, 'tar-count-limit'):
                pb.tar_inventory(data)

    def test_allocated_nobits_is_memory_bounded_not_file_bounded(self):
        data = bytearray(self.binary)
        shoff = struct.unpack_from('<Q', data, 40)[0]
        filesz = struct.unpack_from('<Q', data, 152)[0]
        address = struct.unpack_from('<Q', data, 136)[0]
        struct.pack_into('<Q', data, 160, filesz + 256)
        struct.pack_into('<H', data, 60, 4)
        data.extend(struct.pack('<IIQQQQIIQQ', 0, 8, 3, address + filesz,
                                len(data) + 8192, 256, 0, 0, 8, 0))
        self.assertEqual(bytes(pb.elf_static(data, self.arch)),
                         bytes(pb.elf_static(self.binary, self.arch)))
        struct.pack_into('<Q', data, shoff + 3 * 64 + 16, 0)
        with self.assertRaisesRegex(pb.Rejected, 'elf-section-bounds'):
            pb.elf_static(data, self.arch)

    def test_missing_prepared_empty_directory_is_rejected_without_deleting(self):
        self.extra.append(('licenses/empty', b'', tarfile.DIRTYPE))
        self.repack()
        pb.prepare(self.buildroot, self.inputs, self.out)
        original = os.listdir
        with patch.object(os, 'listdir', side_effect=lambda fd: [leaf for leaf in original(fd) if leaf != 'empty']):
            with self.assertRaisesRegex(pb.Rejected, 'prepared-inventory'):
                pb.check_prepared(self.buildroot, self.inputs, self.out)
        self.assertTrue((self.out / 'licenses/empty').is_dir())

    def test_schema_field_and_commit_hash_formats(self):
        for key, bad in [('schema_version', True), ('schema_version', 2), ('mode', 'sdk-source'),
                         ('cli_source_commit', 'PRIVATE_SECRET'), ('paired_tree', 'F' * 40),
                         ('config_sha256', 'g' * 64)]:
            with self.subTest(key=key, bad=bad):
                old = self.settings[key]
                self.settings[key] = bad
                self.save_settings()
                self.reject()
                self.settings[key] = old
        self.settings['extra'] = 'PRIVATE_SECRET'
        self.save_settings()
        self.reject('input-schema')

    def test_missing_device_fixture_regression(self):
        del self.settings['device']
        self.save_settings()
        self.reject('input-schema')

    def test_bad_goarch_package_and_target_tuples(self):
        for key, value in [('goarch', '386'), ('package_architecture', 'aarch64_generic'),
                           ('subtarget', 'generic'), ('device', 'other'), ('target', 'unknown'),
                           ('target', ['PRIVATE_SECRET'])]:
            with self.subTest(key=key):
                old = self.settings[key]
                self.settings[key] = value
                self.save_settings()
                self.reject()
                self.settings[key] = old

    def test_archive_filename_and_hash_fields(self):
        for value in ['../cli.tar.gz', '/cli.tar.gz', 'a//cli.tar.gz', 'cli.zip',
                      'private secret.tar.gz', '-option.tar.gz', 'x\\y.tar.gz']:
            with self.subTest(value=value):
                self.settings['cli_archive']['filename'] = value
                self.save_settings()
                self.reject()
        self.settings['cli_archive']['filename'] = 'cli.tar.gz'
        for key in ('sha256', 'binary_sha256', 'source_sha256'):
            good = self.settings['cli_archive'][key]
            self.settings['cli_archive'][key] = 'g' * 64
            self.save_settings()
            self.reject('hash-format')
            self.settings['cli_archive'][key] = good

    def test_wrong_pinned_archive_binary_and_source_hashes(self):
        for key, reason in [('sha256', 'archive-hash'), ('binary_sha256', 'binary-hash'),
                            ('source_sha256', 'source-hash')]:
            with self.subTest(key=key):
                good = self.settings['cli_archive'][key]
                self.settings['cli_archive'][key] = '0' * 64
                self.save_settings()
                self.reject(reason)
                self.settings['cli_archive'][key] = good

    def test_config_hash_duplicates_syntax_and_fragment(self):
        original = self.config
        (self.buildroot / '.config').write_bytes(self.config + b'# changed\n')
        self.reject('config-hash')
        for suffix in [b'CONFIG_ARCH="x86_64"\n', b'# CONFIG_ARCH is not set\n']:
            self.config = original + suffix
            self.settings['config_sha256'] = pb.digest(self.config)
            (self.buildroot / '.config').write_bytes(self.config)
            self.save_settings()
            self.reject('config-duplicate')
        for text, reason in [(b'INVALID=private\n', 'config-syntax'),
                             (b'CONFIG_X=y # not generated\n', 'config-syntax'),
                             (b'CONFIG_X="bad\0value"\n', 'config-syntax'),
                             (original.replace(b'CONFIG_HAVE_DOT_CONFIG=y\n', b''), 'config-target-or-abi')]:
            self.config = text
            (self.buildroot / '.config').write_bytes(text)
            self.settings['config_sha256'] = pb.digest(text)
            self.save_settings()
            self.reject(reason)

    def test_fixed_openwrt_kconfig_output_syntax_not_an_sdk(self):
        # Synthetic records reproduce output from ONLY the fixed public
        # scripts/config/conf tool at 6dae72b163fdcc042c959463dab2e0c9bbfa587c.
        # No compiler, SDK, firmware or ELF is invoked by this regression.
        # lexer.l permits ./ (not +); confdata.c writes strings and scalar
        # spellings literally, including visible int/hex without defaults.
        suffix = ('CONFIG_PACKAGE_gstreamer1.0=y\n'
                  'CONFIG_PACKAGE_fixture/variant=m\n'
                  '# CONFIG_PACKAGE_disabled1.0 is not set\n'
                  '# CONFIG_PACKAGE_disabled/variant is not set\n'
                  'CONFIG_SYNTHETIC_NEGATIVE=-17\n'
                  'CONFIG_SYNTHETIC_HEX_LOWER=0xAbCd\n'
                  'CONFIG_SYNTHETIC_HEX_UPPER=0XAbCd\n'
                  'CONFIG_SYNTHETIC_HEX_BARE=AbCd\n'
                  'CONFIG_SYNTHETIC_EMPTY_INT=\n'
                  'CONFIG_SYNTHETIC_EMPTY_HEX=\n'
                  'CONFIG_SYNTHETIC_STRING="quote:\\" slash:\\\\ utf8:中文"\n'
                  'CONFIG_SYNTHETIC_UNICODE="A\u0085B\u2028C\u2029D"\n')
        for key in pb.TARGETS:
            with self.subTest(target=key):
                self.reset(key)
                self.config_change('# Synthetic', suffix + '# Synthetic')
                self.check()

    def test_kconfig_dot_slash_unset_records_participate_in_duplicate_checks(self):
        for symbol in ('PACKAGE_gstreamer1.0', 'PACKAGE_fixture/variant'):
            records = ('CONFIG_' + symbol + '=y\n',
                       '# CONFIG_' + symbol + ' is not set\n')
            for first, second in ((0, 1), (1, 0), (1, 1)):
                with self.subTest(symbol=symbol, order=(first, second)):
                    self.reset()
                    self.config_change('# Synthetic', records[first] + records[second] + '# Synthetic')
                    self.reject('config-duplicate')

    def test_kconfig_compatibility_keeps_bad_symbols_scalars_and_controls_rejected(self):
        records = ('CONFIG_PACKAGE_bad++=y\n', 'CONFIG_PACKAGE_bad$name=y\n',
                   'CONFIG_PACKAGE_bad name=y\n', 'CONFIG_=y\n',
                   'CONFIG_BAD=0xZZ\n', 'CONFIG_BAD=0x\n', 'CONFIG_BAD=0X\n',
                   'CONFIG_BAD=+1\n', 'CONFIG_BAD=-AB\n', 'CONFIG_BAD=12.5\n',
                   'CONFIG_BAD=nan\n', 'CONFIG_BAD=not-a-scalar\n',
                   'CONFIG_BAD=$(whoami)\n', 'CONFIG_BAD="ok"garbage\n',
                   'CONFIG_BAD="unterminated\n', 'CONFIG_BAD="bad\nline"\n',
                   'CONFIG_BAD="bad\rvalue"\n', 'CONFIG_BAD="bad\0value"\n',
                   'CONFIG_BAD="bad\x1bvalue"\n', '# bad comment\r\n',
                   'CONFIG_BAD=y\u2028CONFIG_HIDDEN=y\n')
        for record in records:
            with self.subTest(record=repr(record)):
                self.reset()
                self.config_change('# Synthetic', record + '# Synthetic')
                self.reject('config-syntax')

    def test_empty_critical_abi_values_and_other_targets_remain_rejected(self):
        critical = ('CONFIG_HAVE_DOT_CONFIG', 'CONFIG_ARCH_64BIT', 'CONFIG_x86_64',
                    'CONFIG_ARCH', 'CONFIG_USE_MUSL', 'CONFIG_LIBC', 'CONFIG_TARGET_SUFFIX',
                    'CONFIG_TARGET_ARCH_PACKAGES', 'CONFIG_TARGET_BOARD',
                    'CONFIG_TARGET_SUBTARGET', 'CONFIG_TARGET_x86', 'CONFIG_TARGET_x86_64',
                    'CONFIG_TARGET_x86_64_DEVICE_generic')
        for name in critical:
            with self.subTest(empty=name):
                self.reset()
                line = next(line for line in self.config.decode().split('\n') if line.startswith(name + '='))
                self.config_change(line, name + '=')
                self.reject('config-target-or-abi')
        for record, reason in (('CONFIG_TARGET_armsr=y\n', 'config-multiple-targets'),
                               ('CONFIG_TARGET_x86_other.name=y\n', 'config-multiple-targets'),
                               ('CONFIG_TARGET_x86_other/variant=m\n', 'config-multiple-targets'),
                               ('CONFIG_TARGET_DEVICE_x86_64_DEVICE_other.name=y\n', 'config-multiple-targets'),
                               ('CONFIG_EXTERNAL_TOOLCHAIN=\n', 'config-target-or-abi')):
            with self.subTest(record=record):
                self.reset()
                self.config_change('# Synthetic', record + '# Synthetic')
                self.reject(reason)

    def test_generated_target_dot_slash_declarations_are_real_block_boundaries(self):
        generated = self.buildroot / 'tmp/.config-target.in'
        selected = 'CONFIG_TARGET_x86_64_DEVICE_generic'
        for name in ('OTHER.name', 'OTHER/variant'):
            with self.subTest(declaration=name):
                # The next symbol's bool/depends cannot validate our incomplete
                # selected declaration, even when its name contains ./.
                incomplete = ('config TARGET_x86_64_DEVICE_generic\n\n' +
                              'config ' + name + '\n\tbool "Synthetic next symbol"\n' +
                              '\tdepends on TARGET_x86_64\n')
                generated.write_text(incomplete)
                with self.assertRaisesRegex(pb.Rejected, 'target-kconfig-device'):
                    pb.check_generated_target(incomplete.encode(), self.settings, selected)
                complete = incomplete.replace('generic\n\n',
                                              'generic\n\tbool "Synthetic selected"\n' +
                                              '\tdepends on TARGET_x86_64\n\n')
                pb.check_generated_target(complete.encode(), self.settings, selected)
        # Unicode separators do not synthesize a dependency line in Kconfig.
        false_lines = ('config TARGET_x86_64_DEVICE_generic\n' +
                       '\tbool "Synthetic"\u2028depends on TARGET_x86_64\n')
        with self.assertRaisesRegex(pb.Rejected, 'target-kconfig-device'):
            pb.check_generated_target(false_lines.encode(), self.settings, selected)

    def test_config_abi_and_multiple_device_refusals(self):
        for before, after in [('CONFIG_ARCH_64BIT=y', 'CONFIG_ARCH_64BIT=n'),
                              ('CONFIG_x86_64=y', 'CONFIG_x86_64=n'),
                              ('CONFIG_LIBC="musl"', 'CONFIG_LIBC="glibc"'),
                              ('CONFIG_USE_MUSL=y', 'CONFIG_USE_MUSL=n'),
                              ('# CONFIG_BIG_ENDIAN is not set', 'CONFIG_BIG_ENDIAN=y'),
                              ('CONFIG_TARGET_SUFFIX="musl"', 'CONFIG_TARGET_SUFFIX="gnu"'),
                              ('CONFIG_TARGET_BOARD="x86"', 'CONFIG_TARGET_BOARD="armsr"')]:
            with self.subTest(after=after):
                self.reset()
                self.config_change(before, after)
                self.reject('config-target-or-abi')
        for extra in ['CONFIG_aarch64=y', 'CONFIG_EXTERNAL_TOOLCHAIN=y',
                      'CONFIG_TARGET_MULTI_PROFILE=y', 'CONFIG_TARGET_ALL_PROFILES=y',
                      'CONFIG_TARGET_rockchip=y', 'CONFIG_TARGET_x86_generic=y',
                      'CONFIG_TARGET_armsr_armv8_DEVICE_generic=y']:
            with self.subTest(extra=extra):
                self.reset()
                self.config_change('# Synthetic', extra + '\n# Synthetic')
                self.reject()

    def test_global_generated_kconfig_has_a_separate_bounded_limit(self):
        self.assertGreater(pb.MAX_KCONFIG, pb.MAX_CONFIG)
        with patch.object(pb, 'MAX_KCONFIG', 1):
            self.reject('input-size-limit')

    def test_critical_target_makefile_checks(self):
        for text in ['ARCH:=aarch64\n', 'ARCH:=$(PRIVATE_SECRET)\n',
                     'ARCH+=x86_64\n', 'ifeq (x,x)\nARCH:=x86_64\nendif\n',
                     'include private-secret.mk\nARCH:=x86_64\n',
                     'ARCH:=x86_64\nCPU_TYPE:=generic\n',
                     'ARCH:=x86_64\nARCH_PACKAGES:=aarch64_generic\n']:
            with self.subTest(text=text):
                self.mk.write_text(text)
                self.reject()

    def test_source_version_cgo_tags_and_bindings(self):
        for key, bad, reason in [('private_version', '1.15.0', 'source-version-go-cgo-tags'),
                                 ('go_version', 'go1.26.10', 'source-version-go-cgo-tags'),
                                 ('cgo_enabled', 0, 'source-version-go-cgo-tags'),
                                 ('cgo_enabled', True, 'source-version-go-cgo-tags'),
                                 ('build_tags', pb.TAGS + ',extra', 'source-version-go-cgo-tags'),
                                 ('source_commit', 'f' * 40, 'source-binding'),
                                 ('source_tree', 'f' * 40, 'source-binding'),
                                 ('target_architecture', 'arm64', 'source-binding'),
                                 ('module_identity', 'other', 'source-module')]:
            with self.subTest(key=key):
                old = self.source[key]
                self.source[key] = bad
                self.repack()
                self.reject(reason)
                self.source[key] = old

    def test_never_relabels_cli_as_paired_commit(self):
        self.check()
        self.source['source_commit'] = self.settings['paired_commit']
        self.repack()
        self.reject('source-binding')

    def test_source_archive_binding_is_metadata_not_extraction(self):
        self.assertFalse((self.inputs / self.source['source_archive']['filename']).exists())
        self.check()
        self.source['source_archive']['filename'] = 'unbound.tar.gz'
        self.repack()
        self.reject('source-provenance-filename')

    def test_required_source_license_runtime_and_build_manifests(self):
        for name in ['SOURCE.json', 'LICENSE', 'MODIFICATION-NOTICE.md', 'licenses/LICENSES.json',
                     'licenses/GPL-3.0.txt', 'licenses/MPL-2.0.txt',
                     'build-info-amd64.txt', 'runtime-evidence-amd64.json']:
            with self.subTest(name=name):
                self.omitted = {name}
                self.repack()
                self.reject('required-cli-file-missing')

    def test_license_hash_modules_and_notice_coverage(self):
        self.blob_files[next(iter(self.blob_files))] = b'TAMPERED'
        self.repack()
        self.reject('license-notice-hash')
        self.reset()
        self.licenses['modules'] = []
        self.repack()
        self.reject('license-source-modules')
        self.reset()
        self.source['licenses_manifest_sha256'] = '0' * 64
        self.repack(update_license=False)
        self.reject('license-manifest-hash')
        self.reset()
        del self.licenses['notice_blobs'][pb.digest(self.notice)]
        self.repack()
        self.reject('license-notice-coverage')
        self.reset()
        self.license = b'WRONG ROOT'
        self.repack()
        self.reject('license-root-binding')

    def test_runtime_manifest_binding_and_optional_features(self):
        for key, value in [('schema_version', True), ('source_commit', 'f' * 40),
                           ('target_architecture', 'arm64'), ('runtime_validation', 'unproven-pass')]:
            with self.subTest(key=key):
                old = self.runtime[key]
                self.runtime[key] = value
                self.repack()
                self.reject('runtime-manifest-binding')
                self.runtime[key] = old
        self.runtime['private_features'] = {'payload': 'PRIVATE_SECRET_USER_DATA'}
        self.extra = [('private-features-amd64.json', encoded(self.runtime['private_features']), tarfile.REGTYPE)]
        self.repack()
        self.check()
        self.extra = [('private-features-amd64.json', b'{}', tarfile.REGTYPE)]
        self.repack()
        self.reject('runtime-manifest-binding')

    def test_retained_build_manifest_matches_embedded_bytes(self):
        self.build = self.build.replace(b'CGO_ENABLED=0', b'CGO_ENABLED=1')
        self.repack()
        self.reject('build-manifest-binding')

    def test_embedded_cgo_os_arch_cpu_and_toolchain(self):
        for override in [{'CGO_ENABLED': '1'}, {'GOARCH': 'arm64'}, {'GOOS': 'windows'},
                         {'GOAMD64': 'v3'}, {'-buildmode': 'pie'}, {'-tags': pb.TAGS + ',extra'}]:
            with self.subTest(override=override):
                self.binary, self.build = elf(overrides=override)
                self.repack()
                self.reject('go-build-cgo-or-abi')
        self.binary, self.build = elf(go_version='go1.26.9')
        self.repack()
        self.reject('go-build-version')
        self.reset(list(pb.TARGETS)[1])
        self.binary, self.build = elf('arm64', {'GOARM64': 'v8.2'})
        self.repack()
        self.reject('go-build-cgo-or-abi')

    def test_elf_dynamic_and_interpreter(self):
        for kind in (2, 3):
            with self.subTest(kind=kind):
                self.binary, self.build = elf(extra_kind=kind)
                self.repack()
                self.reject('elf-dynamic-or-interpreter')

    def test_elf_machine_endian_class_flags_and_header_bounds(self):
        for offset, fmt, value in [(18, '<H', 183), (16, '<H', 3), (5, 'B', 2),
                                   (4, 'B', 1), (48, '<I', 1), (8, 'B', 1),
                                   (32, '<Q', 999999), (40, '<Q', 999999),
                                   (112, '<Q', 3), (120, '<Q', 3)]:
            with self.subTest(offset=offset):
                self.binary, self.build = elf()
                data = bytearray(self.binary)
                struct.pack_into(fmt, data, offset, value)
                self.binary = bytes(data)
                self.repack()
                self.reject()
        self.binary = b'\x7fELF'
        self.repack()
        self.reject('elf-truncated')

    def test_elf_build_info_cannot_be_faked_outside_load(self):
        self.binary, self.build = elf()
        data = bytearray(self.binary)
        shoff = struct.unpack_from('<Q', data, 40)[0]
        struct.pack_into('<Q', data, shoff + 64 + 16, 0)
        self.binary = bytes(data)
        self.repack()
        self.reject('elf-build-info-location')

    def test_go_buildinfo_magic_flags_lengths_and_duplicate_settings(self):
        for offset, byte in [(4096, 0), (4096 + 14, 4), (4096 + 15, 0),
                              (4096 + 16, 1), (4096 + 32, 127)]:
            with self.subTest(offset=offset):
                self.binary, self.build = elf()
                data = bytearray(self.binary)
                data[offset] = byte
                self.binary = bytes(data)
                self.repack()
                self.reject()

    def test_tar_links_special_files_pax_and_gnu_extensions(self):
        for kind in [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE,
                     tarfile.FIFOTYPE, tarfile.GNUTYPE_SPARSE, tarfile.XHDTYPE,
                     tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK]:
            with self.subTest(kind=kind):
                self.extra = [('bad', b'', kind)]
                self.repack()
                self.reject('tar-link-special-or-extension')

    def test_tar_absolute_traversal_alias_control_and_long_paths(self):
        for name in ['/absolute', '../escape', 'licenses/../escape', 'a\\b', './a',
                     'a//b', 'a/', 'control\nname', 'a b', 'a' * 256,
                     '/'.join('x' for _ in range(17))]:
            with self.subTest(name=name):
                self.extra = [(name, b'x', tarfile.REGTYPE)]
                if len(name) > 100 and '/' not in name:
                    # A long-name extension is itself a rejected archive format.
                    self.write_archive(archive(self.base + self.extra, fmt=tarfile.GNU_FORMAT))
                else:
                    self.repack()
                self.reject()

    def test_tar_duplicate_reserved_and_file_directory_conflicts(self):
        for extra, reason in [([('LICENSE', b'x', tarfile.REGTYPE)], 'tar-duplicate-or-reserved'),
                              ([('empty', b'', tarfile.DIRTYPE), ('empty/', b'', tarfile.DIRTYPE)], 'tar-duplicate-or-reserved'),
                              ([(pb.MANIFEST, b'{}', tarfile.REGTYPE)], 'tar-duplicate-or-reserved'),
                              ([(pb.INPUT, b'{}', tarfile.REGTYPE)], 'tar-duplicate-or-reserved'),
                              ([('a', b'x', tarfile.REGTYPE), ('a/b', b'x', tarfile.REGTYPE)], 'tar-file-directory-conflict'),
                              ([('a/b', b'x', tarfile.REGTYPE), ('a', b'x', tarfile.REGTYPE)], 'tar-file-directory-conflict')]:
            with self.subTest(extra=extra):
                self.extra = extra
                self.repack()
                self.reject(reason)

    def test_tar_nul_hidden_suffix_checksum_padding_and_end(self):
        raw = bytearray(gzip.decompress(archive([('a', b'x', tarfile.REGTYPE)])))
        raw[:100] = b'a\0hidden' + b'\0' * 92
        raw[148:156] = b' ' * 8
        raw[148:156] = ('%06o\0 ' % sum(raw[:512])).encode()
        self.write_archive(gzip.compress(raw))
        self.reject('tar-path')
        raw = bytearray(gzip.decompress(archive(self.base)))
        raw[512 + len(self.binary)] = 1
        self.write_archive(gzip.compress(raw))
        self.reject('tar-nonzero-padding')
        raw = gzip.decompress(archive(self.base))
        self.write_archive(gzip.compress(raw[:-1]))
        self.reject('tar-raw-limit-or-truncated')
        self.write_archive(gzip.compress(raw + b'NOT ZERO'.ljust(512, b'\0')))
        self.reject('tar-end-or-trailing-data')

    def test_tar_setuid_and_unrelated_user_payload(self):
        self.write_archive(archive(self.base, modes={'box-private': 0o4755}))
        self.reject('tar-unsafe-metadata')
        self.extra = [('user-config.json', b'PRIVATE_SECRET_USER_DATA', tarfile.REGTYPE)]
        self.repack()
        self.reject('unexpected-cli-file')

    def test_archive_count_file_total_raw_and_compressed_limits(self):
        for key, value, reason in [('MAX_MEMBERS', 1, 'tar-count-limit'),
                                   ('MAX_FILE', 16, 'tar-file-limit'),
                                   ('MAX_TOTAL', 16, 'tar-total-limit'),
                                   ('MAX_RAW', 512, 'tar-raw-limit-or-truncated'),
                                   ('MAX_ARCHIVE', 1, 'input-size-limit')]:
            with self.subTest(key=key), patch.object(pb, key, value):
                self.reject(reason)

    def test_gzip_truncation_multiple_members_and_trailing_data(self):
        original = archive(self.base)
        for data in [original[:-8], original + b'TRAILING_PRIVATE_SECRET',
                     original + gzip.compress(b'\0' * 1024),
                     original + gzip.compress(gzip.decompress(original))]:
            with self.subTest(length=len(data)):
                self.write_archive(data)
                self.reject()

    def test_json_duplicates_nonfinite_arrays_deep_values_and_size(self):
        for data in [b'{"mode":1,"mode":2}', b'{"mode":NaN}', b'{"mode":Infinity}',
                     b'[]', b'\xffPRIVATE_SECRET', b'{"x":' + b'[' * 2000 + b'0' + b']' * 2000 + b'}']:
            (self.inputs / pb.INPUT).write_bytes(data)
            rc, stdout, stderr = self.cli(['check', '--buildroot', str(self.buildroot), '--input', str(self.inputs)])
            self.assertEqual(rc, 1)
            self.assertEqual(stdout, '')
            self.assertNotIn('PRIVATE_SECRET', stderr)
        self.save_settings()
        with patch.object(pb, 'MAX_INPUT', 1):
            self.reject('input-size-limit')

    def test_directory_symlinks_are_never_followed(self):
        for name, target, command in [('build-link', self.buildroot, 'buildroot'),
                                      ('input-link', self.inputs, 'input')]:
            link = self.root / name
            link.symlink_to(target, target_is_directory=True)
            args = ['check', '--buildroot', str(link if command == 'buildroot' else self.buildroot),
                    '--input', str(link if command == 'input' else self.inputs)]
            rc, stdout, stderr = self.cli(args)
            self.assertEqual(rc, 1)
            self.assertEqual(stdout, '')
            self.assertNotIn(str(link), stderr)
        parent_link = self.root / 'parent-link'
        parent_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(OSError):
            pb.prepare(self.buildroot, self.inputs, parent_link / 'out-link')
        self.assertFalse((self.root / 'out-link').exists())

    def test_filesystem_links_fifo_and_hardlinks_rejected(self):
        linked_inputs = self.root / 'linked-inputs'
        linked_inputs.mkdir(mode=0o700)
        (linked_inputs / pb.INPUT).write_bytes(encoded(self.settings))
        (linked_inputs / 'cli.tar.gz').symlink_to(self.inputs / 'cli.tar.gz')
        rc, stdout, _ = self.cli(['check', '--buildroot', str(self.buildroot), '--input', str(linked_inputs)])
        self.assertEqual((rc, stdout), (1, ''))
        hard_inputs = self.root / 'hard-inputs'
        hard_inputs.mkdir(mode=0o700)
        (hard_inputs / pb.INPUT).write_bytes(encoded(self.settings))
        os.link(self.inputs / 'cli.tar.gz', hard_inputs / 'cli.tar.gz')
        with self.assertRaises(pb.Rejected) as caught:
            pb.read_regular(hard_inputs, 'cli.tar.gz', pb.MAX_ARCHIVE)
        self.assertEqual(str(caught.exception), 'regular-unlinked-file-required')
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, mode=0o600)
        with self.assertRaises(pb.Rejected):
            pb.read_regular(self.root, 'fifo', 16)

    def test_prepare_output_must_be_new_external_private_owned(self):
        for out in [self.buildroot / 'private-stage', self.inputs / 'private-stage', self.root]:
            with self.subTest(out=out), self.assertRaises(pb.Rejected):
                pb.prepare(self.buildroot, self.inputs, out)
        self.out.mkdir(mode=0o700)
        with self.assertRaises(pb.Rejected) as caught:
            pb.prepare(self.buildroot, self.inputs, self.out)
        self.assertEqual(str(caught.exception), 'output-already-exists')
        public_parent = self.root / 'writable-parent'
        public_parent.mkdir(mode=0o777)
        public_parent.chmod(0o777)
        with self.assertRaises(pb.Rejected) as caught:
            pb.prepare(self.buildroot, self.inputs, public_parent / 'out')
        self.assertEqual(str(caught.exception), 'output-parent-not-private-owned')

    def test_prepare_bad_input_creates_nothing(self):
        self.binary, self.build = elf(extra_kind=2)
        self.repack()
        with self.assertRaises(pb.Rejected):
            pb.prepare(self.buildroot, self.inputs, self.out)
        self.assertFalse(self.out.exists())

    def test_partial_write_has_no_marker_and_is_not_retried(self):
        calls, real = [], pb.write_exclusive
        def fail_third(path, data, mode):
            calls.append(path.name)
            if len(calls) == 3:
                raise OSError('PRIVATE_SECRET_IO_PATH')
            return real(path, data, mode)
        with patch.object(pb, 'write_exclusive', fail_third):
            rc, stdout, stderr = self.cli(['prepare', '--buildroot', str(self.buildroot),
                                          '--input', str(self.inputs), '--out', str(self.out)])
        self.assertEqual((rc, stdout), (1, ''))
        self.assertNotIn('PRIVATE_SECRET', stderr)
        self.assertTrue(self.out.is_dir())
        self.assertFalse((self.out / pb.MANIFEST).exists())
        with self.assertRaises(pb.Rejected):
            pb.prepare(self.buildroot, self.inputs, self.out)

    def test_marker_last_and_copy_hash_failure(self):
        calls, real = [], pb.write_exclusive
        def observe(path, data, mode):
            calls.append(path.name)
            return real(path, data, mode)
        with patch.object(pb, 'write_exclusive', observe):
            pb.prepare(self.buildroot, self.inputs, self.out)
        self.assertEqual(calls[-1], pb.MANIFEST)
        with patch.object(pb, 'read_regular', return_value=b'wrong bytes'):
            with self.assertRaises(pb.Rejected) as caught:
                pb.write_exclusive(self.root / 'copy-failure', b'expected', 0o600)
        self.assertEqual(str(caught.exception), 'output-copy-hash')

    def test_changed_archive_during_prepare_prevents_marker(self):
        real = pb.write_exclusive
        changed = False
        def mutate(path, data, mode):
            nonlocal changed
            result = real(path, data, mode)
            if not changed:
                changed = True
                (self.inputs / 'cli.tar.gz').write_bytes(b'changed')
            return result
        with patch.object(pb, 'write_exclusive', mutate), self.assertRaises(pb.Rejected):
            pb.prepare(self.buildroot, self.inputs, self.out)
        self.assertFalse((self.out / pb.MANIFEST).exists())

    def test_check_prepared_rejects_mutation_permissions_and_extra_links(self):
        pb.prepare(self.buildroot, self.inputs, self.out)
        (self.out / 'box-private').write_bytes(b'changed')
        with self.assertRaises(pb.Rejected):
            pb.check_prepared(self.buildroot, self.inputs, self.out)
        (self.out / 'box-private').write_bytes(self.binary)
        (self.out / 'box-private').chmod(0o755)
        with self.assertRaises(pb.Rejected) as caught:
            pb.check_prepared(self.buildroot, self.inputs, self.out)
        self.assertEqual(str(caught.exception), 'prepared-permissions')
        (self.out / 'box-private').chmod(0o700)
        (self.out / 'extra-link').symlink_to(self.inputs / pb.INPUT)
        with self.assertRaises(pb.Rejected) as caught:
            pb.check_prepared(self.buildroot, self.inputs, self.out)
        self.assertEqual(str(caught.exception), 'prepared-inventory')

    def test_check_prepared_binds_original_inputs_config_and_target_bytes(self):
        pb.prepare(self.buildroot, self.inputs, self.out)
        self.mk.write_text(self.mk.read_text() + '# benign but changed bytes\n')
        with self.assertRaises(pb.Rejected) as caught:
            pb.check_prepared(self.buildroot, self.inputs, self.out)
        self.assertEqual(str(caught.exception), 'prepared-manifest-binding')
        self.mk.write_text('ARCH:=x86_64\nBOARDNAME:=x86_64\n')
        self.settings['paired_commit'] = '1' * 40
        self.save_settings()
        with self.assertRaises(pb.Rejected):
            pb.check_prepared(self.buildroot, self.inputs, self.out)

    def test_cli_stdout_and_errors_are_constant_not_user_metadata(self):
        self.runtime['private_features'] = {'payload': 'PRIVATE_SECRET_USER_DATA'}
        self.repack()
        rc, stdout, stderr = self.cli(['check', '--buildroot', str(self.buildroot), '--input', str(self.inputs)])
        self.assertEqual(rc, 0)
        self.assertEqual(stderr, '')
        self.assertEqual(json.loads(stdout)['preflight'], 'passed-data-only')
        self.assertNotIn('PRIVATE_SECRET', stdout)
        self.assertNotIn(str(self.root), stdout)
        for args in [['check', '--private-secret-argument=PRIVATE_SECRET'],
                     ['check', '--buildroot', '/PRIVATE_SECRET', '--input', str(self.inputs)],
                     ['prepare', '--buildroot', str(self.buildroot), '--input', str(self.inputs)],
                     ['check', '--buildroot', str(self.buildroot), '--input', str(self.inputs), '--out', 'PRIVATE_SECRET']]:
            rc, stdout, stderr = self.cli(args)
            self.assertEqual((rc, stdout), (1, ''))
            self.assertNotIn('PRIVATE_SECRET', stderr)
            self.assertNotIn(str(self.root), stderr)
        self.settings['paired_commit'] = 'PRIVATE_SECRET'
        self.save_settings()
        rc, stdout, stderr = self.cli(['check', '--buildroot', str(self.buildroot), '--input', str(self.inputs)])
        self.assertEqual((rc, stdout), (1, ''))
        self.assertNotIn('PRIVATE_SECRET', stderr)

    def test_no_network_process_go_git_or_binary_execution(self):
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')), \
             patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden')), \
             patch.object(subprocess, 'run', side_effect=AssertionError('process forbidden')), \
             patch.object(os, 'system', side_effect=AssertionError('execution forbidden')), \
             patch.object(os, 'execve', side_effect=AssertionError('execution forbidden')):
            self.check()
            pb.prepare(self.buildroot, self.inputs, self.out)
            pb.check_prepared(self.buildroot, self.inputs, self.out)
        tree = ast.parse((HERE / 'private-prebuilt.py').read_text())
        imported = {name.name.split('.')[0] for node in ast.walk(tree)
                    if isinstance(node, ast.Import) for name in node.names}
        imported.update(node.module.split('.')[0] for node in ast.walk(tree)
                        if isinstance(node, ast.ImportFrom) and node.module)
        self.assertTrue(imported.isdisjoint({'socket', 'subprocess', 'urllib', 'http', 'ctypes', 'shutil'}))
        forbidden = {'system', 'popen', 'execve', 'execv', 'spawnv', 'spawnve',
                     'extractall', 'extract', 'eval', 'exec'}
        self.assertFalse(any(isinstance(node, ast.Call) and
                             ((isinstance(node.func, ast.Attribute) and node.func.attr in forbidden) or
                              (isinstance(node.func, ast.Name) and node.func.id in forbidden | {'compile'}))
                             for node in ast.walk(tree)))
        # need() forwards only literal codes, verified at ALL its call sites below.
        for function in tree.body:
            if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and function.name == 'need':
                continue
            for node in ast.walk(function):
                if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call) and isinstance(node.exc.func, ast.Name) and node.exc.func.id == 'Rejected':
                    self.assertTrue(all(isinstance(arg, ast.Constant) for arg in node.exc.args))
        for function in tree.body:
            for node in ast.walk(function):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                    if node.func.id == 'need':
                        if isinstance(function, ast.FunctionDef) and function.name == 'hex_value':
                            self.assertIsInstance(node.args[1], ast.Name)
                            self.assertEqual(node.args[1].id, 'reason')
                        else:
                            self.assertIsInstance(node.args[1], ast.Constant)
                    elif node.func.id == 'hex_value':
                        self.assertIsInstance(node.args[2], ast.Constant)

    def test_makefile_recipes_work_with_an_offline_stub_not_an_sdk(self):
        # Stub ONLY package glue; run the actual reader and install recipes, never ELF.
        pb.prepare(self.buildroot, self.inputs, self.out)
        harness = self.root / 'make-harness'
        harness.mkdir(mode=0o700)
        include = harness / 'include'
        include.mkdir(mode=0o700)
        (harness / 'rules.mk').write_text(
            'BUILD_DIR:=$(TOPDIR)/build\n' +
            'INSTALL_DIR:=mkdir -p\nINSTALL_BIN:=install -m0755\n' +
            'INSTALL_DATA:=install -m0644\nCP:=cp -fpR\n')
        (include / 'package.mk').write_text('# Synthetic package glue, no SDK\n')
        (harness / 'private-prebuilt.py').write_bytes((HERE / 'private-prebuilt.py').read_bytes())
        driver = ('TOPDIR:=' + str(self.buildroot) + '\nINCLUDE_DIR:=' + str(include) + '\n' +
                  'include ' + str(HERE / 'prebuilt-box.Makefile') + '\n' +
                  '.PHONY: prepare compile install\nprepare:\n\t$(Build/Prepare)\n' +
                  'compile:\n\t$(Build/Compile)\ninstall:\n\t$(call Package/sing-box/install,' + str(harness / 'dest') + ')\n')
        # Actual buildroot stays a synthetic target/config fixture; only rules.mk is glue.
        (self.buildroot / 'rules.mk').write_bytes((harness / 'rules.mk').read_bytes())
        (harness / 'driver.mk').write_text(driver)
        args = ['make', '--no-print-directory', '-f', str(harness / 'driver.mk'),
                'PRIVATE_PREBUILT_INPUT=' + str(self.inputs), 'PRIVATE_PREBUILT_DIR=' + str(self.out)]
        environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        result = subprocess.run(args + ['prepare', 'compile', 'install'], cwd=harness,
                                env=environment, text=True, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        dest = harness / 'dest'
        self.assertEqual((dest / 'usr/bin/sing-box').read_bytes(), self.binary)
        self.assertEqual(stat.S_IMODE((dest / 'usr/bin/sing-box').stat().st_mode), 0o755)
        self.assertTrue((dest / 'usr/share/box-private/licenses/unlisted-THIRD-PARTY-NOTICE').is_file())
        self.assertTrue((dest / 'usr/share/box-private/SOURCE.json').is_file())
        self.assertTrue((dest / 'usr/share/box-private/PREBUILT-MANIFEST.json').is_file())
        self.assertFalse((dest / 'etc').exists())
        self.assertEqual(sorted(path.name for path in (dest / 'usr/bin').iterdir()), ['sing-box'])
        self.assertFalse((dest / 'usr/bin/box-private').exists())
        failed = subprocess.run(args + ['PRIVATE_PREBUILT_DIR=', 'compile'], cwd=harness,
                                env=environment, text=True, capture_output=True, timeout=30)
        self.assertNotEqual(failed.returncode, 0)
        (self.out / 'box-private').write_bytes(b'tamper')
        failed = subprocess.run(args + ['compile'], cwd=harness, env=environment,
                                text=True, capture_output=True, timeout=30)
        self.assertNotEqual(failed.returncode, 0)

    def test_prebuilt_makefile_is_install_only_and_fail_closed(self):
        text = (HERE / 'prebuilt-box.Makefile').read_text()
        self.assertEqual(text.count('$(call PrivatePrebuilt/Check)'), 3)
        self.assertIn('check-prepared --buildroot', text)
        self.assertIn('DEPENDS:=+ca-bundle +kmod-inet-diag +kmod-netlink-diag +kmod-tun', text)
        self.assertIn('RSTRIP:=:', text)
        self.assertIn('PKG_NAME:=sing-box', text)
        self.assertIn('  USERID:=sing-box=5566:sing-box=5566\n',
                      text.split('define Package/sing-box\n', 1)[1].split('endef', 1)[0])
        self.assertIn('PKG_VERSION:=1.15.0_alpha13', text)
        self.assertIn('PKG_RELEASE:=3', text)
        self.assertEqual(pb.VERSION, '1.15.0-alpha.13-private.3')
        self.assertIn('$(eval $(call BuildPackage,sing-box))', text)
        self.assertIn('"$(PRIVATE_PREBUILT_DIR)/box-private" $(1)/usr/bin/sing-box', text)
        self.assertNotIn('Package/box-private', text)
        self.assertNotIn('usr/bin/box-private', text)
        self.assertNotIn('PKG_CPE_ID', text)
        self.assertIn('SOURCE.json', text)
        self.assertIn('runtime-evidence-*.json', text)
        self.assertIn('build-info-*.txt', text)
        self.assertNotIn('GO_PKG', text)
        self.assertNotIn('golang/host', text)
        self.assertNotIn('DownloadMethod', text)
        self.assertNotIn('PROVIDES:=', text)
        self.assertNotIn('CONFLICTS:=', text)
        self.assertNotIn('/etc/init.d', text)
        self.assertNotIn('PRIVATE_PREBUILT_DIR?=', text)
        self.assertNotIn(' prepare --', text)


if __name__ == '__main__':
    unittest.main()
