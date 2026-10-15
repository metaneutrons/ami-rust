"""Admission boundaries for the actual measured standard-host profiles."""
import copy
import runpy
from pathlib import Path
import unittest

BUILD = runpy.run_path(str(Path(__file__).resolve().parents[1]/'build.py'))
CHECK = BUILD['require_host_capacity']
GiB = 1024**3


class HostCapacity(unittest.TestCase):
    def setUp(self):
        self.manifest = {'host_capacity': {
            'schema': 'ami-rust-host-capacity-v1', 'ram_minimum_bytes': 6*GiB,
            'disk_free_minimum_bytes': 24*GiB}, 'budgets': {'build_rss_bytes': 4*GiB}}

    def test_measured_standard_hosts(self):
        CHECK(self.manifest, 7516192768, 103125716992)
        CHECK(self.manifest, 16766414848, 92126691328)

    def test_legacy_sdk_keeps_original_requirement(self):
        for ram in [7516192768, 16766414848]:
            with self.assertRaises(ValueError):
                CHECK({}, ram, 100*GiB)
        CHECK({}, 16*GiB, 24*GiB)

    def test_ram_and_disk_boundaries(self):
        CHECK(self.manifest, 6*GiB, 24*GiB)
        for ram, disk in [(6*GiB-1, 24*GiB), (6*GiB, 24*GiB-1)]:
            with self.assertRaises(ValueError):
                CHECK(self.manifest, ram, disk)

    def test_no_schema_or_scalar_downgrade(self):
        for name, value in [('ram_minimum_bytes', True),
                            ('ram_minimum_bytes', 6*GiB-1),
                            ('disk_free_minimum_bytes', 24*GiB-1),
                            ('schema', 'unreviewed'), ('extra', 1)]:
            manifest = copy.deepcopy(self.manifest)
            manifest['host_capacity'][name] = value
            with self.assertRaises(ValueError):
                CHECK(manifest, 32*GiB, 100*GiB)

    def test_hosted_profile_cannot_retain_oversized_rss_cap(self):
        for value in [0, True, 4*GiB+1, 8*GiB]:
            manifest = copy.deepcopy(self.manifest)
            manifest['budgets']['build_rss_bytes'] = value
            with self.assertRaises(ValueError):
                CHECK(manifest, 32*GiB, 100*GiB)


if __name__ == '__main__':
    unittest.main()
