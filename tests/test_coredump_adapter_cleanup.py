from unittest.mock import patch

import coredump_adapter


class _Pipe:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    def readline(self, _limit):
        return b""


class _Process:
    def __init__(self):
        self.stdout = _Pipe()

    def wait(self, timeout=None):
        return 0


def test_coredump_reader_closes_stream():
    process = _Process()
    with patch("subprocess.Popen", return_value=process), patch("select.select", return_value=([process.stdout], [], [])):
        assert coredump_adapter.get_systemd_coredumps() == []
    assert process.stdout.closed
