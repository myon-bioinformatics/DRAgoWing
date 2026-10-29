"""Stdlib-only tests: no real perf syscall, fork or browser is needed."""
import ctypes
import errno
import importlib.util
from pathlib import Path
import struct
import unittest
from unittest.mock import mock_open, patch

spec = importlib.util.spec_from_file_location(
    'check_perf_admission', Path(__file__).parents[1] / 'scripts/check_perf_admission.py')
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class PerfAdmissionTests(unittest.TestCase):
    def child_case(self, error=None):
        with patch.object(probe.os, 'pipe', return_value=(10, 11)), \
             patch.object(probe.os, 'fork', return_value=123), \
             patch.object(probe.os, 'close') as close, \
             patch.object(probe.os, 'waitpid') as wait, \
             patch.object(probe, 'perf_open', return_value=12, side_effect=error) as op:
            result = probe.probe_child()
        op.assert_called_once_with(123)
        wait.assert_called_once_with(123, 0)
        self.assertEqual([x.args[0] for x in close.call_args_list],
                         [10, 11] if error else [10, 12, 11])
        return result

    def test_admitted(self):
        self.assertEqual(self.child_case(), {'status': 'admitted', 'errno': None})

    def test_denied_no_retry(self):
        for code in (errno.EACCES, errno.EPERM):
            with self.subTest(code=code):
                self.assertEqual(self.child_case(OSError(code, 'private message')),
                                 {'status': 'permission_denied', 'errno': code})

    def test_unavailable_no_retry(self):
        self.assertEqual(self.child_case(OSError(errno.ENOSYS, 'secret')),
                         {'status': 'unavailable', 'errno': errno.ENOSYS})

    def test_fork_failure_closes_both_descriptors(self):
        with patch.object(probe.os, 'pipe', return_value=(10, 11)), \
             patch.object(probe.os, 'fork', side_effect=OSError(errno.EAGAIN, 'fork')), \
             patch.object(probe.os, 'close') as close, \
             patch.object(probe, 'perf_open') as op:
            with self.assertRaises(OSError):
                probe.probe_child()
        self.assertEqual([x.args[0] for x in close.call_args_list], [10, 11])
        op.assert_not_called()

    def test_syscall_is_disabled_user_only_and_owned_pid(self):
        with patch.object(probe.ctypes, 'CDLL') as load:
            libc = load.return_value
            def syscall(number, attr, pid, cpu, group, flags):
                self.assertEqual((number.value, pid.value, cpu.value, group.value, flags.value),
                                 (298, 123, -1, -1, 8))
                fields = struct.unpack_from('=IIQQQQQ', ctypes.string_at(attr, 128))
                self.assertEqual(fields, (1, 128, 2, 1, 15, 0, 97))
                return 12
            libc.syscall.side_effect = syscall
            self.assertEqual(probe.perf_open(123), 12)
            libc.syscall.assert_called_once()

    def test_syscall_errno_is_preserved_without_private_details(self):
        with patch.object(probe.ctypes, 'CDLL') as load:
            def denied(*_args):
                ctypes.set_errno(errno.EPERM)
                return -1
            load.return_value.syscall.side_effect = denied
            with self.assertRaises(OSError) as caught:
                probe.perf_open(123)
            self.assertEqual(caught.exception.errno, errno.EPERM)
            self.assertEqual(caught.exception.strerror, 'perf admission failed')
            load.return_value.syscall.assert_called_once()

    def test_unsupported_arch_never_probes(self):
        with patch.object(probe, 'read_paranoid', return_value=4), \
             patch.object(probe.platform, 'machine', return_value='aarch64'), \
             patch.object(probe, 'probe_child') as op:
            self.assertEqual(probe.check()['status'], 'unsupported_platform')
            op.assert_not_called()

    def test_paranoid_missing_or_malformed_is_null(self):
        for value in ('private text', '', '1' * 32):
            with patch.object(probe.Path, 'open', mock_open(read_data=value)):
                self.assertIsNone(probe.read_paranoid())
        with patch.object(probe.Path, 'open', side_effect=PermissionError):
            self.assertIsNone(probe.read_paranoid())
        with patch.object(probe.Path, 'open', mock_open(read_data='4\n')):
            self.assertEqual(probe.read_paranoid(), 4)


if __name__ == '__main__':
    unittest.main()
