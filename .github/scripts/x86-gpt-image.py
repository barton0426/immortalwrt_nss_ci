#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Repair the pinned X86 GPT recipe and check newly built EFI images."""
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
import zlib

ORIGINAL_SHA256 = 'af862c05616e986320ba5f89e7a77ef5d1f4791ad45c74c0b0e0897d31747195'
GUID_PADDING = b'    [ -n "$PADDING" ] && dd if=/dev/zero of="$OUTPUT" bs=512 seek="$((ROOTFSOFFSET + ROOTFSSIZE))" conv=notrunc count="$sect"\n'


def repaired_recipe(original):
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('unexpected pinned X86 image recipe')
    if original.count(b'${GUID:+-g}') != 1 or original.count(GUID_PADDING) != 1:
        raise ValueError('unexpected GPT recipe shape')
    # -d 0 asks ptgen to write a real backup GPT sized to the partitions.
    # Do not extend that disk afterwards with the legacy 63-sector padding.
    return original.replace(b'${GUID:+-g}', b'${GUID:+-g -d 0}').replace(GUID_PADDING, b'')


def recipe_path(root):
    path = root / 'scripts/gen_image_generic.sh'
    if path.is_symlink() or path.resolve(strict=True) != path:
        raise ValueError('image recipe must be an ordinary buildroot file')
    return path


def prepare(root, state):
    path = recipe_path(root)
    original = path.read_bytes()
    fixed = repaired_recipe(original)
    with (state / 'x86-gpt-generator.original.sh').open('xb') as out:
        out.write(original)
    path.write_bytes(fixed)
    recheck(root, state)
    print('X86 GPT recipe fixed; BIOS/MBR branch and partition inputs unchanged')


def recheck(root, state):
    expected = repaired_recipe((state / 'x86-gpt-generator.original.sh').read_bytes())
    if recipe_path(root).read_bytes() != expected:
        raise ValueError('X86 GPT recipe changed after private build preparation')


def header(block, expected_lba):
    if len(block) != 512 or block[:8] != b'EFI PART':
        raise ValueError('GPT header missing at its advertised LBA')
    revision, size, crc, reserved = struct.unpack_from('<4I', block, 8)
    if revision != 0x10000 or size != 92 or reserved:
        raise ValueError('unexpected GPT header format')
    checked = bytearray(block[:size])
    checked[16:20] = b'\0' * 4
    if zlib.crc32(checked) & 0xffffffff != crc:
        raise ValueError('GPT header CRC mismatch')
    current, alternate, first, last = struct.unpack_from('<4Q', block, 24)
    entries_lba, count, entry_size, entries_crc = struct.unpack_from('<Q3I', block, 72)
    if current != expected_lba or count != 128 or entry_size != 128 or first != 34:
        raise ValueError('unexpected pinned ptgen layout')
    return {'current': current, 'alternate': alternate, 'first': first, 'last': last,
            'guid': block[56:72], 'entries_lba': entries_lba, 'entries_crc': entries_crc}


def validate_gpt(size, prefix, tail):
    if size % 512 or size < 2 * 17408:
        raise ValueError('EFI image is not a complete sector-aligned disk')
    eof_lba = size // 512 - 1
    primary = header(prefix[512:1024], 1)
    backup = header(tail[-512:], eof_lba)
    if primary['alternate'] != eof_lba or backup['alternate'] != 1:
        raise ValueError('backup GPT is not at physical EOF')
    for key in ('first', 'last', 'guid', 'entries_crc'):
        if primary[key] != backup[key]:
            raise ValueError('primary/backup GPT disagree')
    if primary['entries_lba'] != 2 or backup['entries_lba'] != eof_lba - 32:
        raise ValueError('unexpected GPT entry table location')
    if primary['last'] != backup['entries_lba'] - 1:
        raise ValueError('GPT usable range overlaps its backup')
    entries = prefix[1024:17408]
    if len(entries) != 16384 or tail[-16896:-512] != entries:
        raise ValueError('GPT entry tables differ')
    if zlib.crc32(entries) & 0xffffffff != primary['entries_crc']:
        raise ValueError('GPT partition entry CRC mismatch')
    partitions = []
    for index in range(128):
        entry = entries[index * 128:(index + 1) * 128]
        if not any(entry[:16]):
            continue
        first, last, attrs = struct.unpack_from('<3Q', entry, 32)
        if first < primary['first'] or first > last or last > primary['last']:
            raise ValueError('GPT partition outside usable disk')
        partitions.append({'index': index + 1, 'first_lba': first, 'last_lba': last,
                           'attributes': attrs})
    # Upstream ptgen reserves entry 128 for BIOS boot, in addition to boot/root.
    if [p['index'] for p in partitions] != [1, 2, 128]:
        raise ValueError('boot, root or BIOS partition was lost')
    if partitions[2]['first_lba'] != 34 or partitions[2]['last_lba'] != 511:
        raise ValueError('BIOS boot reservation changed')
    ordered = sorted(partitions, key=lambda p: p['first_lba'])
    if any(a['last_lba'] >= b['first_lba'] for a, b in zip(ordered, ordered[1:])):
        raise ValueError('GPT partitions overlap')
    return {'raw_size': size, 'backup_lba': eof_lba, 'partitions': partitions}


def verify_images(root, state):
    recheck(root, state)
    paths = sorted((root / 'bin/targets/x86/64').glob('*combined-efi.img.gz'))
    if not paths:
        raise ValueError('no newly built X86 EFI image')
    results = {}
    for path in paths:
        if path.is_symlink() or path.resolve(strict=True) != path:
            raise ValueError('EFI image must be an ordinary buildroot file')
        size, prefix, tail = 0, b'', b''
        with gzip.open(path, 'rb') as image:
            while chunk := image.read(1024 * 1024):
                size += len(chunk)
                if size > 8 * 1024**3:
                    raise ValueError('unexpectedly large X86 disk image')
                prefix = (prefix + chunk)[:17408] if len(prefix) < 17408 else prefix
                tail = (tail + chunk)[-17408:]
        results[path.name] = validate_gpt(size, prefix, tail)
    with (state / 'X86-GPT.json').open('x', encoding='utf-8') as out:
        json.dump(results, out, sort_keys=True, indent=2)
        out.write('\n')
    print('New EFI images passed primary/backup GPT and physical EOF checks')


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ('prepare', 'recheck', 'verify'):
        raise SystemExit('usage: x86-gpt-image.py prepare|recheck|verify BUILDROOT STATE')
    root, state = (Path(p).resolve(strict=True) for p in sys.argv[2:])
    if not root.is_dir() or not state.is_dir():
        raise ValueError('buildroot/state directories required')
    {'prepare': prepare, 'recheck': recheck, 'verify': verify_images}[sys.argv[1]](root, state)


if __name__ == '__main__':
    main()
