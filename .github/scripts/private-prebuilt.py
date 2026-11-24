#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline, data-only prebuilt CLI reader. Never runs ELF, Go, Git, or a network client.

Interface (schema 3): INPUT/PREBUILT-INPUT.json and its pinned CLI .tar.gz;
check --buildroot ABS --input ABS; prepare also takes --out NEW_ABS;
check-prepared instead takes --prepared ABS. Output is the flat, validated CLI
inventory plus PREBUILT-MANIFEST.json, written LAST. No input/archive contents,
paths, commits, runtime feature data, or exception messages are printed.

cli_source_commit/tree name the CLI's historical source. paired_commit/tree name
its separately pinned export-only companion; they need not be equal. The caller
must verify both Git trees and the firmware commit independently. It must retain,
hash-check and privately publish SOURCE.json's corresponding source archive; this
reader neither extracts that archive nor claims legal completeness. Use the same
quiescent buildroot's real, resolved .config (after defconfig), not a config
fragment. Literal target Makefiles, ELF64/LE/static linkage and embedded Go build
settings are checked, not an APK's dependency ABI or device/runtime acceptance.
Keep inputs, target metadata and prepared output unchanged until packaging ends.
"""
import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import zlib

SCHEMA = 3
INPUT = 'PREBUILT-INPUT.json'
MANIFEST = 'PREBUILT-MANIFEST.json'
VERSION = '1.15.0-alpha.13-private.2'
GO_VERSION = '1.26.10'
MODULE = 'github.com/sagernet/sing-box'
TAGS = ('http2legacy,with_acme,with_clash_api,with_dhcp,with_gvisor,with_quic,'
        'with_tailscale,with_utls,with_wireguard,badlinkname,tfogo_checklinkname0')
SHA40 = re.compile(r'[0-9a-f]{40}')
SHA64 = re.compile(r'[0-9a-f]{64}')
TOKEN = re.compile(r'[a-z0-9][a-z0-9_-]{0,63}')
PATH_COMPONENT = re.compile(r'[A-Za-z0-9_.+][A-Za-z0-9_.+-]{0,254}')
MAX_ARCHIVE = 128 * 1024 * 1024
MAX_FILE = 128 * 1024 * 1024
MAX_TOTAL = 192 * 1024 * 1024
MAX_MEMBERS = 10000
MAX_RAW = MAX_TOTAL + MAX_MEMBERS * 1024 + 10240
MAX_JSON = 4 * 1024 * 1024
MAX_INPUT = 65536
MAX_CONFIG = 2 * 1024 * 1024
# Fixed OpenWrt scripts/config/lexer.l accepts literal word characters plus ./,
# not +. Share the grammar for assignments, unset records and declaration bounds.
KCONFIG_SYMBOL = r'[A-Za-z0-9_./-]+'
# Generated global Kconfig includes profiles for ALL boards, not just our target.
MAX_KCONFIG = 16 * 1024 * 1024
MAX_MK = 1024 * 1024
MAX_BUILD_INFO = 128 * 1024
FIELDS = {'schema_version', 'mode', 'firmware_commit', 'cli_source_commit',
          'cli_source_tree', 'paired_commit', 'paired_tree', 'config_sha256',
          'goarch', 'package_architecture', 'target', 'subtarget', 'device',
          'cli_archive'}
ARCHIVE_FIELDS = {'filename', 'sha256', 'binary_sha256', 'source_sha256'}
# Audited, intentionally closed mapping. New tuples require review and tests.
TARGETS = {
    ('amd64', 'x86', '64', 'x86_64', 'generic'): 'x86_64',
    ('arm64', 'armsr', 'armv8', 'aarch64_generic', 'generic'): 'aarch64',
    ('arm64', 'qualcommax', 'ipq60xx', 'aarch64_cortex-a53', 'zn_m2'): 'aarch64',
    ('arm64', 'qualcommax', 'ipq807x', 'aarch64_cortex-a53', 'redmi_ax6-stock'): 'aarch64',
}
ARCH_SYMBOLS = ('aarch64', 'aarch64_be', 'arm', 'armeb', 'i386', 'i686',
                'loongarch64', 'mips', 'mipsel', 'mips64', 'mips64el',
                'powerpc', 'powerpc64', 'riscv64', 'x86_64')
MK_VARIABLES = {'ARCH', 'BOARD', 'SUBTARGET', 'SUBTARGETS', 'ARCH_PACKAGES',
                'CPU_TYPE', 'CPU_SUBTYPE'}
GO_MAGIC = b'\xff Go buildinf:'
GO_MOD_START = bytes.fromhex('3077af0c9274080241e1c107e6d618e6')
GO_MOD_END = bytes.fromhex('f932433186182072008242104116d8f2')


class Rejected(Exception):
    """All raise sites use constant reason codes, never caller data."""


def need(value, reason):
    if not value:
        raise Rejected(reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, indent=2) + '\n').encode()


def hex_value(value, pattern, reason):
    need(isinstance(value, str) and pattern.fullmatch(value), reason)


def relative(value):
    need(isinstance(value, str) and 0 < len(value) <= 1024 and '\\' not in value,
         'relative-path')
    p = PurePosixPath(value)
    need(not p.is_absolute() and str(p) == value and 0 < len(p.parts) <= 16 and
         all(x not in ('.', '..') and PATH_COMPONENT.fullmatch(x) for x in p.parts),
         'relative-path')
    return value


def absolute(value):
    p = Path(value)
    need(p.is_absolute() and '..' not in p.parts and '\0' not in os.fspath(p),
         'absolute-path-required')
    return p


def open_directory(value):
    """Anchor at / and open EVERY component without following symlinks."""
    p = absolute(value)
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in p.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def directory(value):
    p = absolute(value)
    fd = open_directory(p)
    os.close(fd)
    return p


def snapshot(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns,
            info.st_ctime_ns, info.st_mode, info.st_nlink)


def read_regular(root, name, limit):
    """Bounded stable snapshot; reject filesystem links, FIFOs and devices."""
    parts = PurePosixPath(relative(name)).parts
    fd = open_directory(root)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
        child = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                        dir_fd=fd)
        with os.fdopen(child, 'rb') as stream:
            before = os.fstat(stream.fileno())
            need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1,
                 'regular-unlinked-file-required')
            need(0 <= before.st_size <= limit, 'input-size-limit')
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            need(len(data) <= limit and len(data) == before.st_size, 'input-size-limit')
            need(snapshot(before) == snapshot(after), 'input-changed')
            return data
    finally:
        os.close(fd)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate-json-key')
        result[key] = value
    return result


def bad_constant(_):
    raise Rejected('json-nonfinite')


def parse_json(data):
    need(len(data) <= MAX_JSON, 'json-size-limit')
    value = json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                       parse_constant=bad_constant)
    need(isinstance(value, dict), 'json-object-required')
    return value


def target_key(settings):
    return tuple(settings[k] for k in
                 ('goarch', 'target', 'subtarget', 'package_architecture', 'device'))


def check_settings(data):
    s = parse_json(data)
    need(set(s) == FIELDS and type(s['schema_version']) is int and
         s['schema_version'] == SCHEMA and s['mode'] == 'firmware-prebuilt',
         'input-schema')
    for key in ('firmware_commit', 'cli_source_commit', 'cli_source_tree',
                'paired_commit', 'paired_tree'):
        hex_value(s[key], SHA40, 'commit-or-tree-format')
    hex_value(s['config_sha256'], SHA64, 'hash-format')
    need(s['goarch'] in ('amd64', 'arm64'), 'unsupported-goarch')
    for key in ('package_architecture', 'target', 'subtarget', 'device'):
        need(isinstance(s[key], str) and TOKEN.fullmatch(s[key]), 'target-field')
    need(target_key(s) in TARGETS, 'unsupported-target-tuple')
    a = s['cli_archive']
    need(isinstance(a, dict) and set(a) == ARCHIVE_FIELDS, 'archive-schema')
    name = relative(a['filename'])
    need('/' not in name and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}\.tar\.gz', name),
         'archive-filename')
    for key in ('sha256', 'binary_sha256', 'source_sha256'):
        hex_value(a[key], SHA64, 'hash-format')
    return s


def config_symbol(value):
    # target_conf sanitizes BOARD/SUBTARGET, NOT the Device/DumpInfo profile id.
    return value.replace('/', '_').replace('-', '_').replace('.', '_')


def device_symbol(settings, multi):
    prefix = 'CONFIG_TARGET_' + ('DEVICE_' if multi else '')
    return (prefix + config_symbol(settings['target'] + '_' + settings['subtarget']) +
            '_DEVICE_' + settings['device'])


def check_config(data, settings):
    need(digest(data) == settings['config_sha256'], 'config-hash')
    text = data.decode('utf-8')
    need(not any(ord(c) < 32 and c not in '\n\t' for c in text), 'config-syntax')
    values = {}
    # confdata.c preserves optional 0x/0X hex prefixes; visible int/hex without
    # defaults can serialize an empty value. Types are not tagged in .config;
    # the security-critical target/ABI values below still require exact matches.
    value_pattern = r'(?:y|m|n|-?[0-9]+|(?:0[xX])?[0-9A-Fa-f]+|"(?:[^"\\]|\\.)*"|)'
    # Kconfig records end at LF, not Unicode separators inside quoted strings.
    for line in text.split('\n'):
        if not line or line.startswith('#'):
            match = re.fullmatch(r'# (CONFIG_' + KCONFIG_SYMBOL + ') is not set', line)
            if not match:
                continue
            key, value = match.group(1), 'n'
        else:
            match = re.fullmatch(r'(CONFIG_' + KCONFIG_SYMBOL + ')=(' + value_pattern + ')', line)
            need(match is not None, 'config-syntax')
            key, value = match.groups()
        need(key not in values, 'config-duplicate')
        values[key] = value
    arch = TARGETS[target_key(settings)]
    board, subtarget = settings['target'], settings['subtarget']
    base = 'CONFIG_TARGET_' + config_symbol(board + '_' + subtarget)
    multi = values.get('CONFIG_TARGET_MULTI_PROFILE', 'n') == 'y'
    need(values.get('CONFIG_TARGET_MULTI_PROFILE', 'n') in ('y', 'n'), 'config-target-or-abi')
    need(values.get('CONFIG_TARGET_PER_DEVICE_ROOTFS', 'n') in ('y', 'n'), 'config-target-or-abi')
    device = device_symbol(settings, multi)
    expected = {
        'CONFIG_HAVE_DOT_CONFIG': 'y',
        'CONFIG_ARCH_64BIT': 'y',
        'CONFIG_' + arch: 'y',
        'CONFIG_ARCH': json.dumps(arch),
        'CONFIG_TARGET_ARCH_PACKAGES': json.dumps(settings['package_architecture']),
        'CONFIG_TARGET_BOARD': json.dumps(board),
        'CONFIG_TARGET_SUBTARGET': json.dumps(subtarget),
        'CONFIG_TARGET_' + board: 'y', base: 'y', device: 'y',
        'CONFIG_USE_MUSL': 'y', 'CONFIG_LIBC': '"musl"', 'CONFIG_TARGET_SUFFIX': '"musl"',
    }
    need(all(values.get(k) == v for k, v in expected.items()), 'config-target-or-abi')
    need(all(values.get('CONFIG_' + other, 'n') == 'n'
             for other in ARCH_SYMBOLS if other != arch), 'config-target-or-abi')
    need(all(values.get(key, 'n') == 'n' for key in
             ('CONFIG_BIG_ENDIAN', 'CONFIG_USE_GLIBC', 'CONFIG_USE_EXTERNAL_LIBC',
              'CONFIG_EXTERNAL_TOOLCHAIN', 'CONFIG_NATIVE_TOOLCHAIN',
              'CONFIG_TARGET_ALL_PROFILES')),
         'config-target-or-abi')
    for key, value in values.items():
        if value not in ('y', 'm'):
            continue
        if re.fullmatch(r'CONFIG_TARGET_[a-z0-9]+', key):
            need(key == 'CONFIG_TARGET_' + board, 'config-multiple-targets')
        if key.startswith('CONFIG_TARGET_' + board + '_'):
            need(key in (base, device), 'config-multiple-targets')
        # This exact boolean image policy is not a target/device selector.
        # Keep the broad rejection below for every other DEVICE-shaped symbol.
        if key == 'CONFIG_TARGET_PER_DEVICE_ROOTFS':
            continue
        if re.fullmatch(r'CONFIG_TARGET_.*_DEVICE_.*', key) or key.startswith('CONFIG_TARGET_DEVICE_'):
            need(key == device, 'config-multiple-targets')
    return device


def check_generated_target(data, settings, selected):
    text = data.decode('utf-8')
    need(not any(ord(c) < 32 and c not in '\n\t' for c in text), 'target-kconfig-syntax')
    declarations = list(re.finditer(r'(?m)^[ \t]*(config|menuconfig) (' + KCONFIG_SYMBOL + r')[ \t]*$', text))
    found = []
    for index, match in enumerate(declarations):
        if 'CONFIG_' + match.group(2) != selected:
            continue
        end = declarations[index + 1].start() if index + 1 < len(declarations) else len(text)
        block = text[match.end():end]
        lines = [line.strip() for line in block.split('\n')]
        target = 'TARGET_' + config_symbol(settings['target'] + '_' + settings['subtarget'])
        need(any(re.match(r'bool(?:\s|$)', line) for line in lines) and
             'depends on ' + target in lines and
             match.group(1) == ('menuconfig' if selected.startswith('CONFIG_TARGET_DEVICE_') else 'config'),
             'target-kconfig-device')
        found.append(match.group(2))
    need(len(found) == 1, 'target-kconfig-device')


def literal_target(data, values):
    """Read only unconditional literal ABI assignments; never evaluate Make."""
    text = data.decode('utf-8')
    need('\0' not in text and '\r' not in text, 'target-mk-syntax')
    depth = 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if re.match(r'(?:define|ifeq|ifneq|ifdef|ifndef)\b', stripped):
            depth += 1
            continue
        if re.match(r'(?:endef|endif)\b', stripped):
            need(depth > 0, 'target-mk-syntax')
            depth -= 1
            continue
        if stripped == 'else' or stripped.startswith('else '):
            need(depth > 0, 'target-mk-syntax')
            continue
        match = re.fullmatch(r'(?:(?:override|export)\s+)?([A-Z_]+)\s*(:=|\?=|\+=|=)\s*(.*)', stripped)
        if match and match.group(1) in MK_VARIABLES:
            key, op, raw = match.groups()
            value = raw.partition('#')[0].strip()
            need(depth == 0 and '$' not in value and '\\' not in value and
                 (not value or all(TOKEN.fullmatch(x) for x in value.split())) and
                 (key == 'SUBTARGETS' or len(value.split()) <= 1), 'target-mk-nonliteral')
            need(op != '+=' or key == 'SUBTARGETS', 'target-mk-nonliteral')
            if op == '?=':
                values.setdefault(key, value)
            elif op == '+=':
                values[key] = (values.get(key, '') + ' ' + value).strip()
            else:
                values[key] = value
        elif re.match(r'(?:-?include|sinclude)\b', stripped):
            # These two are the reviewed OpenWrt target metadata entry points.
            need(stripped in ('include $(TOPDIR)/rules.mk',
                              'include $(INCLUDE_DIR)/target.mk'), 'target-mk-include')
        elif re.search(r'\b(?:ARCH|BOARD|SUBTARGET|SUBTARGETS|ARCH_PACKAGES|CPU_TYPE|CPU_SUBTYPE)\s*[:?+]?=', stripped):
            raise Rejected('target-mk-nonliteral')
    need(depth == 0, 'target-mk-syntax')


def check_target_files(buildroot, settings):
    base = 'target/linux/' + settings['target']
    names = (base + '/Makefile', base + '/' + settings['subtarget'] + '/target.mk')
    values, hashes = {}, {}
    for name in names:
        data = read_regular(buildroot, name, MAX_MK)
        literal_target(data, values)
        hashes[name] = digest(data)
    arch = TARGETS[target_key(settings)]
    need(values.get('BOARD') == settings['target'] and values.get('ARCH') == arch,
         'target-mk-target-or-abi')
    need(values.get('SUBTARGET', settings['subtarget']) == settings['subtarget'] and
         ('SUBTARGETS' not in values or settings['subtarget'] in values['SUBTARGETS'].split()),
         'target-mk-target-or-abi')
    cpu = values.get('CPU_TYPE', 'generic' if arch == 'aarch64' else '')
    subtype = values.get('CPU_SUBTYPE', '')
    package = values.get('ARCH_PACKAGES',
                         arch + ('_' + cpu if cpu else '') + ('_' + subtype if subtype else ''))
    need(package == settings['package_architecture'] and not subtype and
         cpu == ('cortex-a53' if settings['target'] == 'qualcommax' else
                 'generic' if arch == 'aarch64' else ''), 'target-mk-target-or-abi')
    selected = check_config(read_regular(buildroot, '.config', MAX_CONFIG), settings)
    name = 'tmp/.config-target.in'
    data = read_regular(buildroot, name, MAX_KCONFIG)
    check_generated_target(data, settings, selected)
    hashes[name] = digest(data)
    return hashes


@dataclass(frozen=True)
class Entry:
    offset: int
    size: int
    sha256: str | None
    directory: bool


@dataclass(frozen=True)
class Bundle:
    settings: dict
    input_sha256: str
    target_files_sha256: dict
    raw: bytes
    entries: dict
    buildroot: Path
    inputs: Path

    def content(self, name):
        entry = self.entries[name]
        return memoryview(self.raw)[entry.offset:entry.offset + entry.size]


def header_text(field):
    value, _, padding = field.partition(b'\0')
    need(not padding.strip(b'\0'), 'tar-path')
    return value.decode('utf-8', 'strict')


def tar_inventory(archive):
    """One bounded gzip member, strict raw USTAR headers, including the end."""
    need(len(archive) <= MAX_ARCHIVE, 'input-size-limit')
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    raw = decoder.decompress(archive, MAX_RAW + 1)
    need(len(raw) <= MAX_RAW and len(raw) % 512 == 0, 'tar-raw-limit-or-truncated')
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail,
         'gzip-extra-or-truncated')
    entries, implied_dirs, effective_names, total, offset = {}, set(), set(), 0, 0
    while offset < len(raw):
        block = raw[offset:offset + 512]
        if block == b'\0' * 512:
            need(len(raw) - offset >= 1024 and not raw[offset:].strip(b'\0'),
                 'tar-end-or-trailing-data')
            return raw, entries
        need(len(entries) < MAX_MEMBERS, 'tar-count-limit')
        item = tarfile.TarInfo.frombuf(block, 'utf-8', 'strict')
        need(item.type in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE),
             'tar-link-special-or-extension')
        need(block[257:263] == b'ustar\0' and block[263:265] == b'00', 'tar-format')
        name, prefix = header_text(block[:100]), header_text(block[345:500])
        if prefix:
            name = prefix + '/' + name
        is_dir = item.type == tarfile.DIRTYPE
        if is_dir and name.endswith('/'):
            name = name[:-1]
        relative(name)
        need(item.name == name, 'tar-path')
        need(not header_text(block[157:257]) and not item.linkname and
             not item.pax_headers and not item.sparse, 'tar-link-special-or-extension')
        need(name not in (MANIFEST, INPUT) and name not in entries, 'tar-duplicate-or-reserved')
        need(0 <= item.mode <= 0o777 and item.devmajor == item.devminor == 0,
             'tar-unsafe-metadata')
        need(0 <= item.size <= MAX_FILE and (not is_dir or item.size == 0), 'tar-file-limit')
        parts = PurePosixPath(name).parts
        parents = ['/'.join(parts[:i]) for i in range(1, len(parts))]
        need(all(p not in entries or entries[p].directory for p in parents),
             'tar-file-directory-conflict')
        need(is_dir or name not in implied_dirs, 'tar-file-directory-conflict')
        implied_dirs.update(parents)
        effective_names.update(parents)
        effective_names.add(name)
        need(len(effective_names) <= MAX_MEMBERS, 'tar-count-limit')
        total += item.size
        need(total <= MAX_TOTAL, 'tar-total-limit')
        start, end = offset + 512, offset + 512 + item.size
        padded = start + ((item.size + 511) // 512) * 512
        need(padded <= len(raw), 'tar-truncated')
        need(not raw[end:padded].strip(b'\0'), 'tar-nonzero-padding')
        entries[name] = Entry(start, item.size,
                              None if is_dir else digest(memoryview(raw)[start:end]), is_dir)
        offset = padded
    raise Rejected('tar-end-or-trailing-data')


def elf_static(data, goarch):
    """Validate the ELF ABI/linkage and locate a LOAD-backed .go.buildinfo."""
    need(len(data) >= 64, 'elf-truncated')
    ident, etype, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = struct.unpack_from('<16sHHIQQQIHHHHHH', data)
    need(ident[:7] == b'\x7fELF\x02\x01\x01' and ident[7] in (0, 3) and
         not any(ident[8:]) and etype == 2 and version == 1 and flags == 0 and
         machine == {'amd64': 62, 'arm64': 183}[goarch] and ehsize == 64,
         'elf-format-or-machine')
    need(phsize == 56 and 0 < phnum <= 128 and phoff >= 64 and
         phoff + phnum * phsize <= len(data), 'elf-program-headers')
    executable_entry, loads = False, []
    for i in range(phnum):
        kind, perms, offset, address, physical, filesz, memsz, align = struct.unpack_from('<IIQQQQQQ', data, phoff + i * phsize)
        need(kind not in (2, 3), 'elf-dynamic-or-interpreter')
        need(offset <= len(data) and filesz <= len(data) - offset and
             memsz >= filesz and address + memsz < (1 << 64), 'elf-segment-bounds')
        need(perms & ~7 == 0 and (align in (0, 1) or align & (align - 1) == 0),
             'elf-segment-flags-or-alignment')
        if kind == 1:
            need((align in (0, 1) or offset % align == address % align) and
                 perms & 3 != 3, 'elf-segment-flags-or-alignment')
            loads.append((offset, address, filesz, memsz, perms))
            if perms & 1 and address <= entry < address + filesz:
                executable_entry = True
        if kind == 0x6474e551:
            need(not perms & 1, 'elf-executable-stack')
    need(executable_entry, 'elf-executable-entry')
    need(shsize == 64 and 0 < shnum <= 256 and 0 < shstr < shnum and shoff >= 64 and
         shoff + shsize * shnum <= len(data), 'elf-section-headers')
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff + i * shsize)
                for i in range(shnum)]
    table = sections[shstr]
    need(table[1] == 3 and 0 < table[5] <= MAX_BUILD_INFO and table[4] <= len(data) and
         table[5] <= len(data) - table[4], 'elf-section-headers')
    strings = bytes(data[table[4]:table[4] + table[5]])
    seen, buildinfo = set(), None
    for nameoff, kind, perms, address, offset, size, link, info, align, entsize in sections:
        # SHT_NOBITS has no file payload: Go .noptrbss may name an offset past EOF.
        need(nameoff < len(strings) and
             (kind == 8 or (offset <= len(data) and size <= len(data) - offset)),
             'elf-section-bounds')
        if kind == 8:
            need(address + size < (1 << 64) and
                 (not perms & 2 or any(la <= address and size <= la + ms - address
                                      for lo, la, fs, ms, lp in loads)), 'elf-section-bounds')
        end = strings.find(b'\0', nameoff)
        need(end >= nameoff and end - nameoff <= 255, 'elf-section-headers')
        name = strings[nameoff:end].decode('ascii')
        need(not name or name not in seen, 'elf-section-headers')
        seen.add(name)
        need(kind not in (6, 11) and name not in ('.dynamic', '.dynsym', '.interp'),
             'elf-dynamic-or-interpreter')
        if name == '.go.buildinfo':
            need(kind == 1 and perms == 3 and 32 <= size <= MAX_BUILD_INFO and
                 offset % 16 == 0 and address % 16 == 0 and
                 any(lo <= offset and size <= lo + fs - offset and
                     address == la + offset - lo and lp & 2
                     for lo, la, fs, ms, lp in loads), 'elf-build-info-location')
            buildinfo = bytes(data[offset:offset + size])
    need(buildinfo is not None, 'elf-build-info-missing')
    return buildinfo


def uvarint(data, offset):
    value = 0
    for i in range(10):
        need(offset + i < len(data), 'go-build-info-format')
        byte = data[offset + i]
        need(i < 9 or byte <= 1, 'go-build-info-format')
        value |= (byte & 127) << (7 * i)
        if byte < 128:
            need(i == 0 or byte != 0, 'go-build-info-format')
            return value, offset + i + 1
    raise Rejected('go-build-info-format')


def go_build_info(data):
    need(data[:14] == GO_MAGIC and data[14:16] == b'\x08\x02' and
         not any(data[16:32]), 'go-build-info-format')
    strings, offset = [], 32
    for _ in range(2):
        size, offset = uvarint(data, offset)
        need(size <= MAX_BUILD_INFO and size <= len(data) - offset, 'go-build-info-format')
        strings.append(data[offset:offset + size])
        offset += size
    version, module = strings
    need(not any(data[offset:]) and len(module) >= 32 and
         module[:16] == GO_MOD_START and module[-16:] == GO_MOD_END,
         'go-build-info-format')
    return version.decode('ascii'), module[16:-16].decode('utf-8')


def go_lines(text):
    need(not any(ord(c) < 32 and c not in '\n\t' for c in text), 'go-build-info-format')
    # `go version -m` omits blank separators after replacement-module records.
    lines = [line.rstrip('\t') for line in text.splitlines() if line]
    need(all(re.match(r'(?:path|mod|dep|=>|build)\t', line) for line in lines),
         'go-build-info-format')
    return lines


def check_build_info(bundle, source):
    version, text = go_build_info(elf_static(bundle.content('box-private'), bundle.settings['goarch']))
    need(version == 'go' + source['go_version'], 'go-build-version')
    embedded = go_lines(text)
    artifact = bytes(bundle.content('build-info-' + bundle.settings['goarch'] + '.txt')).decode('utf-8')
    first, separator, body = artifact.partition('\n')
    need(separator and first == 'box-private: ' + version and
         all(not line or line.startswith('\t') for line in body.splitlines()),
         'build-manifest-binding')
    retained = go_lines('\n'.join(line[1:] for line in body.splitlines() if line))
    need(retained == embedded, 'build-manifest-binding')
    paths, modules, settings, dependencies = [], [], {}, set()
    for line in embedded:
        fields = line.split('\t')
        if fields[0] == 'path':
            paths.append(fields[1:])
        elif fields[0] == 'mod':
            modules.append(fields[1:])
        elif fields[0] == 'dep':
            need(len(fields) >= 3, 'go-build-info-format')
            dependencies.add(fields[1])
        elif fields[0] == 'build':
            need(len(fields) == 2, 'go-build-info-format')
            key, sep, value = fields[1].partition('=')
            need(sep and key not in settings, 'go-build-info-format')
            settings[key] = value
    need(paths == [[MODULE + '/cmd/sing-box']] and len(modules) == 1 and
         modules[0] and modules[0][0] == MODULE, 'go-build-module')
    arch = bundle.settings['goarch']
    required = {'-buildmode': 'exe', '-compiler': 'gc', '-tags': source['build_tags'],
                'CGO_ENABLED': '0', 'GOOS': 'linux', 'GOARCH': arch,
                'GOAMD64' if arch == 'amd64' else 'GOARM64': 'v1' if arch == 'amd64' else 'v8.0'}
    need(all(settings.get(key) == value for key, value in required.items()),
         'go-build-cgo-or-abi')
    declared = {record.get('module') for record in source['modules']
                if isinstance(record.get('module'), str)}
    need(dependencies <= declared, 'go-build-license-coverage')


def check_source(bundle):
    s, entries = bundle.settings, bundle.entries
    required = {'box-private', 'SOURCE.json', 'LICENSE', 'MODIFICATION-NOTICE.md',
                'licenses/LICENSES.json', 'licenses/GPL-3.0.txt', 'licenses/MPL-2.0.txt',
                'build-info-' + s['goarch'] + '.txt', 'runtime-evidence-' + s['goarch'] + '.json'}
    for name in required:
        need(name in entries and not entries[name].directory and entries[name].size > 0,
             'required-cli-file-missing')
    roots = required | {'private-features-' + s['goarch'] + '.json'}
    for name, entry in entries.items():
        need((name in roots and not entry.directory) or
             (name == 'licenses' and entry.directory) or name.startswith('licenses/'),
             'unexpected-cli-file')
    a = s['cli_archive']
    need(entries['box-private'].sha256 == a['binary_sha256'], 'binary-hash')
    need(entries['SOURCE.json'].sha256 == a['source_sha256'], 'source-hash')
    source = parse_json(bytes(bundle.content('SOURCE.json')))
    need(type(source.get('schema_version')) is int and source['schema_version'] == 1 and
         source.get('implementation') == 'box-private', 'source-schema')
    need(source.get('module_identity') == MODULE, 'source-module')
    need(source.get('go_version') == GO_VERSION and source.get('private_version') == VERSION and
         source.get('cgo_enabled') is False and source.get('build_tags') == TAGS,
         'source-version-go-cgo-tags')
    need(source.get('source_commit') == s['cli_source_commit'] and
         source.get('source_tree') == s['cli_source_tree'] and
         source.get('target_architecture') == s['goarch'], 'source-binding')
    hex_value(source.get('git_archive_sha256'), SHA64, 'source-provenance-hash')
    artifact = source.get('source_archive')
    need(isinstance(artifact, dict) and set(artifact) == {'filename', 'sha256'} and
         artifact.get('filename') == 'box-private-source-' + s['cli_source_commit'] + '-' + s['goarch'] + '.tar.gz',
         'source-provenance-filename')
    hex_value(artifact.get('sha256'), SHA64, 'source-provenance-hash')
    need(entries['licenses/LICENSES.json'].sha256 == source.get('licenses_manifest_sha256'),
         'license-manifest-hash')
    licenses = parse_json(bytes(bundle.content('licenses/LICENSES.json')))
    need(type(licenses.get('schema_version')) is int and licenses['schema_version'] == 1 and
         isinstance(source.get('modules'), list) and 0 < len(source['modules']) <= 4096 and
         licenses.get('modules') == source['modules'], 'license-source-modules')
    supplemental, blobs = licenses.get('supplemental_license_texts'), licenses.get('notice_blobs')
    need(isinstance(supplemental, dict) and set(supplemental) == {'GPL-3.0.txt', 'MPL-2.0.txt'} and
         isinstance(blobs, dict) and 0 < len(blobs) <= MAX_MEMBERS, 'license-layout')
    for name, hash_value in supplemental.items():
        need(entries['licenses/' + name].sha256 == hash_value, 'license-notice-hash')
    for hash_value, record in blobs.items():
        hex_value(hash_value, SHA64, 'license-notice-hash')
        need(isinstance(record, dict), 'license-layout')
        name = relative(record.get('archive_path'))
        need(name in ('LICENSE', 'MODIFICATION-NOTICE.md') or name.startswith('licenses/'),
             'license-layout')
        need(name in entries and not entries[name].directory and entries[name].size > 0 and
             entries[name].sha256 == hash_value, 'license-notice-hash')
    main, identifiers = [], set()
    for record in source['modules']:
        need(isinstance(record, dict) and isinstance(record.get('id'), str) and
             re.fullmatch(r'[A-Za-z0-9_-]{1,64}', record['id']) and
             record['id'] not in identifiers, 'license-source-modules')
        identifiers.add(record['id'])
        need(record.get('main') in (None, False, True) and
             (record.get('main') is None or type(record['main']) is bool), 'license-source-modules')
        if record.get('main') is True:
            main.append(record)
        for field in ('notices', 'source_notice_files'):
            notices = record.get(field, {})
            need(isinstance(notices, dict), 'license-layout')
            for name, hash_value in notices.items():
                relative(name)
                hex_value(hash_value, SHA64, 'license-notice-hash')
                need(hash_value in blobs, 'license-notice-coverage')
    need(len(main) == 1 and main[0].get('module') == MODULE and
         main[0].get('notices', {}).get('LICENSE') == entries['LICENSE'].sha256 and
         any(PurePosixPath(path).name == 'MODIFICATION-NOTICE.md' and
             hash_value == entries['MODIFICATION-NOTICE.md'].sha256
             for path, hash_value in main[0].get('notices', {}).items()),
         'license-root-binding')
    check_build_info(bundle, source)
    runtime = parse_json(bytes(bundle.content('runtime-evidence-' + s['goarch'] + '.json')))
    need(type(runtime.get('schema_version')) is int and runtime['schema_version'] == 1 and
         runtime.get('source_commit') == s['cli_source_commit'] and
         runtime.get('target_architecture') == s['goarch'] and
         runtime.get('runtime_validation') in ('native-passed', 'cross-built-not-run', 'not-run'),
         'runtime-manifest-binding')
    feature_name = 'private-features-' + s['goarch'] + '.json'
    if feature_name in entries:
        features = parse_json(bytes(bundle.content(feature_name)))
        need(features == runtime.get('private_features'), 'runtime-manifest-binding')
    # Feature payload is retained as evidence only; no private protocol logic here.


def check(buildroot, inputs):
    buildroot, inputs = directory(buildroot), directory(inputs)
    data = read_regular(inputs, INPUT, MAX_INPUT)
    settings = check_settings(data)
    check_config(read_regular(buildroot, '.config', MAX_CONFIG), settings)
    target_hashes = check_target_files(buildroot, settings)
    archive = read_regular(inputs, settings['cli_archive']['filename'], MAX_ARCHIVE)
    need(digest(archive) == settings['cli_archive']['sha256'], 'archive-hash')
    raw, entries = tar_inventory(archive)
    bundle = Bundle(settings, digest(data), target_hashes, raw, entries, buildroot, inputs)
    check_source(bundle)
    return bundle


def still_current(bundle):
    need(digest(read_regular(bundle.inputs, INPUT, MAX_INPUT)) == bundle.input_sha256,
         'input-changed')
    check_config(read_regular(bundle.buildroot, '.config', MAX_CONFIG), bundle.settings)
    need(check_target_files(bundle.buildroot, bundle.settings) == bundle.target_files_sha256,
         'target-files-changed')
    need(digest(read_regular(bundle.inputs, bundle.settings['cli_archive']['filename'], MAX_ARCHIVE)) ==
         bundle.settings['cli_archive']['sha256'], 'archive-hash')


def fresh_output(out, buildroot, inputs):
    out = absolute(out)
    relative(out.name)
    parent = directory(out.parent)
    info = parent.stat()
    need(info.st_uid == os.geteuid() and not info.st_mode & 0o022,
         'output-parent-not-private-owned')
    need(not os.path.lexists(out), 'output-already-exists')
    need(not any(out.is_relative_to(root) or root.is_relative_to(out)
                 for root in (buildroot, inputs)), 'output-not-external')
    return out


def write_exclusive(path, data, mode):
    path = absolute(path)
    fd = open_directory(path.parent)
    try:
        child = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        mode, dir_fd=fd)
        with os.fdopen(child, 'wb') as stream:
            need(stream.write(data) == len(data), 'output-copy-hash')
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        need(digest(read_regular(path.parent, path.name, MAX_FILE)) == digest(data),
             'output-copy-hash')
    finally:
        os.close(fd)


def output_directories(bundle):
    dirs = {name for name, entry in bundle.entries.items() if entry.directory}
    for name in bundle.entries:
        dirs.update(str(p) for p in PurePosixPath(name).parents if str(p) != '.')
    return dirs


def manifest_for(bundle):
    return {'schema_version': SCHEMA, 'mode': 'firmware-prebuilt', 'complete': True,
            'status': 'complete-data-only', 'input_sha256': bundle.input_sha256,
            'inputs': bundle.settings, 'config_sha256': bundle.settings['config_sha256'],
            'target_files_sha256': bundle.target_files_sha256,
            'files_sha256': {name: entry.sha256 for name, entry in bundle.entries.items()
                             if not entry.directory},
            'git_history_verified': False, 'paired_git_verified': False,
            'corresponding_source_archive_verified': False,
            'apk_build_claimed': False, 'package_dependency_abi_verified': False,
            'runtime_execution_claimed': False}


def prepare(buildroot, inputs, out):
    # Validate all archive data and output eligibility before the first write.
    bundle = check(buildroot, inputs)
    out = fresh_output(out, bundle.buildroot, bundle.inputs)
    still_current(bundle)
    parent_fd = open_directory(out.parent)
    try:
        os.mkdir(out.name, mode=0o700, dir_fd=parent_fd)
        fd = os.open(out.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                     dir_fd=parent_fd)
        try:
            os.fchmod(fd, 0o700)
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)
    # I/O failure deliberately leaves an incomplete private directory, never removed/retried.
    for name in sorted(output_directories(bundle), key=lambda n: (n.count('/'), n)):
        parent_fd = open_directory((out / name).parent)
        try:
            os.mkdir(PurePosixPath(name).name, mode=0o700, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
    for name, entry in sorted(bundle.entries.items()):
        if not entry.directory:
            write_exclusive(out / name, bundle.content(name), 0o700 if name == 'box-private' else 0o600)
    still_current(bundle)
    write_exclusive(out / MANIFEST, encoded(manifest_for(bundle)), 0o600)  # LAST
    return out


def prepared_inventory(out, expected_files, expected_dirs):
    """Reject unexpected entries before reading them; never follow tree links."""
    result, directories, visited = set(), set(), set()
    fd = open_directory(out)
    try:
        info = os.fstat(fd)
        need(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700,
             'prepared-permissions')
        def walk(parent_fd, prefix, depth):
            need(depth <= 16, 'prepared-inventory')
            names = os.listdir(parent_fd)
            need(len(visited) + len(names) <= MAX_MEMBERS + 1, 'prepared-inventory')
            for leaf in names:
                name = (prefix + '/' if prefix else '') + leaf
                relative(name)
                visited.add(name)
                info = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                need(info.st_uid == os.geteuid(), 'prepared-permissions')
                if stat.S_ISDIR(info.st_mode):
                    need(name in expected_dirs and stat.S_IMODE(info.st_mode) == 0o700,
                         'prepared-inventory')
                    directories.add(name)
                    child_fd = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=parent_fd)
                    try:
                        walk(child_fd, name, depth + 1)
                    finally:
                        os.close(child_fd)
                else:
                    need(name in expected_files and stat.S_ISREG(info.st_mode) and
                         info.st_nlink == 1, 'prepared-inventory')
                    need(stat.S_IMODE(info.st_mode) == (0o700 if name == 'box-private' else 0o600),
                         'prepared-permissions')
                    result.add(name)
        walk(fd, '', 0)
    finally:
        os.close(fd)
    need(result == expected_files and directories == expected_dirs, 'prepared-inventory')


def check_prepared(buildroot, inputs, prepared):
    bundle = check(buildroot, inputs)
    out = directory(prepared)
    need(not any(out.is_relative_to(root) or root.is_relative_to(out)
                 for root in (bundle.buildroot, bundle.inputs)), 'output-not-external')
    files = {name for name, entry in bundle.entries.items() if not entry.directory}
    prepared_inventory(out, files | {MANIFEST}, output_directories(bundle))
    need(read_regular(out, MANIFEST, MAX_JSON) == encoded(manifest_for(bundle)),
         'prepared-manifest-binding')
    for name in sorted(files):
        entry = bundle.entries[name]
        data = read_regular(out, name, min(MAX_FILE, entry.size))
        need(len(data) == entry.size and digest(data) == entry.sha256, 'prepared-file-hash')
    still_current(bundle)
    return bundle


class ConstantParser(argparse.ArgumentParser):
    def error(self, _message):
        raise Rejected('arguments')


def main(argv=None):
    parser = ConstantParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('command', choices=('check', 'prepare', 'check-prepared'))
    parser.add_argument('--buildroot', required=True)
    parser.add_argument('--input', required=True)
    parser.add_argument('--out')
    parser.add_argument('--prepared')
    try:
        args = parser.parse_args(argv)
        need((args.command == 'prepare') == (args.out is not None) and
             (args.command == 'check-prepared') == (args.prepared is not None), 'arguments')
        if args.command == 'prepare':
            prepare(args.buildroot, args.input, args.out)
        elif args.command == 'check-prepared':
            check_prepared(args.buildroot, args.input, args.prepared)
        else:
            check(args.buildroot, args.input)
        print(json.dumps({'schema_version': SCHEMA, 'mode': 'firmware-prebuilt',
                          'preflight': 'passed-data-only', 'git_history_verified': False,
                          'paired_git_verified': False, 'apk_build_claimed': False,
                          'runtime_execution_claimed': False}))
        return 0
    except Rejected as error:
        reason = str(error)  # constant codes at every raise site, no caller data
    except Exception:
        # No traceback, paths, archive contents, JSON values or exception message.
        reason = 'missing-or-invalid-controlled-input'
    print(json.dumps({'schema_version': SCHEMA, 'preflight': 'rejected', 'reason': reason}),
          file=sys.stderr)
    return 1


if __name__ == '__main__':
    sys.exit(main())
