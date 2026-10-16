"""Synthetic ELF fixtures for the native AROS admission audit."""
import importlib.util
from pathlib import Path
import struct
import tempfile
import unittest


AUDIT_PATH = Path(__file__).resolve().parents[1] / 'elf_audit.py'
SPEC = importlib.util.spec_from_file_location('elf_audit', AUDIT_PATH)
ELF_AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ELF_AUDIT)


def make_elf(text_size=128, bss_size=1024, machine=62, relocation_type=None):
    """Build a small ET_REL with the required AROS ABI marker and entry symbol."""
    ident = b'\x7fELF\x02\x01\x01\x0f\x01' + b'\0' * 7
    strtab = b'\0__startup_entry\0'
    symbols = b'\0' * 24 + struct.pack('<IBBHQQ', 1, 0x10, 0, 1, 0, 0)

    data = bytearray(64)
    text_offset = len(data)
    data.extend(b'\0' * text_size)
    strtab_offset = len(data)
    data.extend(strtab)
    symtab_offset = len(data)
    data.extend(symbols)
    relocation_offset = None
    if relocation_type is not None:
        relocation_offset = len(data)
        data.extend(struct.pack('<QQq', 0, (1 << 32) | relocation_type, 0))

    section_names = [b'', b'.text', b'.bss', b'.strtab', b'.symtab']
    if relocation_type is not None:
        section_names.append(b'.rela.text')
    section_names.append(b'.shstrtab')
    shstrtab = b'\0' + b'\0'.join(section_names[1:]) + b'\0'
    shstrtab_offset = len(data)
    data.extend(shstrtab)
    section_header_offset = len(data)
    section_count = len(section_names)

    name_offsets = {}
    cursor = 1
    for section_name in section_names[1:]:
        name_offsets[section_name.decode()] = cursor
        cursor += len(section_name) + 1

    sections = [b'\0' * 64]
    sections.append(struct.pack(
        '<IIQQQQIIQQ', name_offsets['.text'], 1, 0x6, 0, text_offset,
        text_size, 0, 0, 16, 0,
    ))
    sections.append(struct.pack(
        '<IIQQQQIIQQ', name_offsets['.bss'], 8, 0x3, 0, 0,
        bss_size, 0, 0, 16, 0,
    ))
    sections.append(struct.pack(
        '<IIQQQQIIQQ', name_offsets['.strtab'], 3, 0, 0, strtab_offset,
        len(strtab), 0, 0, 1, 0,
    ))
    sections.append(struct.pack(
        '<IIQQQQIIQQ', name_offsets['.symtab'], 2, 0, 0, symtab_offset,
        len(symbols), 3, 1, 8, 24,
    ))
    if relocation_type is not None:
        sections.append(struct.pack(
            '<IIQQQQIIQQ', name_offsets['.rela.text'], 4, 0, 0,
            relocation_offset, 24, 4, 1, 8, 24,
        ))
    sections.append(struct.pack(
        '<IIQQQQIIQQ', name_offsets['.shstrtab'], 3, 0, 0,
        shstrtab_offset, len(shstrtab), 0, 0, 1, 0,
    ))
    data.extend(b''.join(sections))
    struct.pack_into(
        '<16sHHIQQQIHHHHHH', data, 0, ident, 1, machine, 1, 0, 0,
        section_header_offset, 0, 64, 0, 0, 64, section_count,
        section_count - 1,
    )
    return data


class ElfAuditTests(unittest.TestCase):
    def audit_bytes(self, content, variant='core'):
        with tempfile.TemporaryDirectory(prefix='elf-audit-') as directory:
            path = Path(directory) / 'AMIRUST'
            path.write_bytes(content)
            return ELF_AUDIT.audit(path, variant)

    def test_small_reference_object_reports_measurements_and_thresholds(self):
        content = make_elf(text_size=128, bss_size=1024)
        result = self.audit_bytes(content)

        self.assertEqual(result['result'], 'PASS')
        self.assertEqual(result['file_bytes'], len(content))
        self.assertEqual(result['code_ro_bytes'], 128)
        self.assertEqual(result['writable_bss_bytes'], 1024)
        self.assertEqual(result['allocated_static_bytes'], 128 + 1024)
        self.assertEqual(result['static_owned_estimate_bytes'], 128 + 1024 + 131072)
        self.assertEqual(result['limits'], {
            'file': 1024 * 1024,
            'code_ro': 512 * 1024,
            'static_owned': 32 * 1024 * 1024,
        })
        self.assertFalse(result['limits_are_product_constraints'])
        self.assertEqual(result['limits_scope'], 'reference-test-thresholds')
        self.assertTrue(result['reference_status']['within_reference_limits'])

    def test_valid_large_application_is_accepted_above_reference_thresholds(self):
        content = make_elf(
            text_size=4 * 1024 * 1024 + 1,
            bss_size=33 * 1024 * 1024,
        )

        for variant in ('core', 'deps'):
            with self.subTest(variant=variant):
                result = self.audit_bytes(content, variant=variant)
                self.assertEqual(result['result'], 'PASS')
                self.assertGreater(result['file_bytes'], result['limits']['file'])
                self.assertGreater(result['code_ro_bytes'], result['limits']['code_ro'])
                self.assertGreater(result['allocated_static_bytes'], 32 * 1024 * 1024)
                self.assertFalse(result['reference_status']['within_reference_limits'])
                self.assertEqual(
                    set(result['reference_status']['observations'].values()),
                    {'above-reference-threshold'},
                )

    def test_wrong_abi_marker_is_rejected(self):
        content = make_elf()
        content[7] = 0
        with self.assertRaisesRegex(AssertionError, 'wrong ELF identity/ABI marker'):
            self.audit_bytes(content)

    def test_unsupported_relocation_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, 'unsupported AROS relocation'):
            self.audit_bytes(make_elf(relocation_type=255))

    def test_unresolved_strong_symbol_is_rejected(self):
        content = make_elf()
        section_header_offset = struct.unpack_from('<Q', content, 40)[0]
        symbol_header_offset = section_header_offset + 4 * 64
        symbol_table_offset = struct.unpack_from('<Q', content, symbol_header_offset + 24)[0]
        struct.pack_into('<H', content, symbol_table_offset + 24 + 6, 0)
        with self.assertRaisesRegex(AssertionError, 'unresolved strong symbols'):
            self.audit_bytes(content)

    def test_startup_symbol_must_begin_first_allocated_code_section(self):
        content = make_elf()
        section_header_offset = struct.unpack_from('<Q', content, 40)[0]
        symbol_header_offset = section_header_offset + 4 * 64
        symbol_table_offset = struct.unpack_from('<Q', content, symbol_header_offset + 24)[0]
        struct.pack_into('<H', content, symbol_table_offset + 24 + 6, 2)
        with self.assertRaisesRegex(AssertionError, 'startup mustenter firsttext at0'):
            self.audit_bytes(content)

    def test_truncated_allocated_section_is_rejected(self):
        content = make_elf()
        section_header_offset = struct.unpack_from('<Q', content, 40)[0]
        struct.pack_into('<Q', content, section_header_offset + 64 + 32, len(content))
        with self.assertRaisesRegex(AssertionError, 'bad section data range'):
            self.audit_bytes(content)


if __name__ == '__main__':
    unittest.main()
