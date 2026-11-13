"""Loopback labels from the shared extractor and both platform pipelines."""
import tempfile
import unittest
from pathlib import Path

from src.features.pipeline import WindowsFeaturePipeline, LinuxFeaturePipeline
from src.preprocessing.normalizer import extract_ip_labels


class NetworkFeatureTests(unittest.TestCase):
    def test_localhost_in_host_arguments_urls_and_unc_paths(self):
        for command in (
            'ping localhost', 'curl http://LOCALHOST:8080/api',
            'ssh user@localhost', r'dir \\localhost\share',
            'curl http://localhost/ localhost 127.0.0.1',
        ):
            with self.subTest(command=command):
                self.assertEqual(extract_ip_labels(command).count('IP_LOOPBACK'), 1)

    def test_longer_domains_identifiers_and_filenames_are_excluded(self):
        for command in (
            'ping localhost.example.com', 'ping mylocalhost',
            'ping localhost-backup', 'ping example.localhost',
            'type localhost.txt', 'echo localhost_name',
        ):
            with self.subTest(command=command):
                self.assertNotIn('IP_LOOPBACK', extract_ip_labels(command))

    def test_ipv4_classification_is_preserved(self):
        for address, label in (
            ('127.0.0.1', 'IP_LOOPBACK'), ('127.1.2.3', 'IP_LOOPBACK'),
            ('192.168.1.10', 'IP_PRIVATE'), ('169.254.1.1', 'IP_LINK_LOCAL'),
            ('224.0.0.1', 'IP_MULTICAST'), ('8.8.8.8', 'IP_PUBLIC'),
            ('0.0.0.0', 'IP_UNSPECIFIED'),
        ):
            with self.subTest(address=address):
                self.assertEqual(extract_ip_labels(address), [label])

    def test_any_tool_on_both_platforms_uses_the_shared_label(self):
        with tempfile.TemporaryDirectory() as directory:
            corpus = Path(directory) / 'empty.corpus'
            corpus.write_text('', encoding='utf-8')
            for pipeline_class in (WindowsFeaturePipeline, LinuxFeaturePipeline):
                pipeline = pipeline_class(str(corpus))
                for command in ('ping localhost', 'curl http://localhost:8080/',
                                'ssh localhost "cmd /c calc.exe"'):
                    with self.subTest(platform=pipeline_class.__name__, command=command):
                        self.assertIn('IP_LOOPBACK', pipeline(command, training=True))


if __name__ == '__main__':
    unittest.main()
