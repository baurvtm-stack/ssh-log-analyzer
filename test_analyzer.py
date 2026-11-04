from analyzer import parse_log
from datetime import datetime
from analyzer import parse_timestamp
from analyzer import collect_attempts, parse_log, parse_timestamp
from analyzer import is_brute_force


def test_counts_failed_attemtps(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Sep  8 10:14:22 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "Sep  8 10:14:25 server sshd[2]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "Sep  8 10:14:28 server sshd[3]: Failed password for admin from 2.2.2.2 port 22 ssh2\n"
    )
    result = parse_log(log)
    assert result == {"1.1.1.1": 2, "2.2.2.2": 1}


def test_ignores_accepted_password(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Sep  8 10:14:22 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "Sep  8 10:14:22 server sshd[1]: Accepted password for root from 3.3.3.3 port 22 ssh2\n"
    )
    result = parse_log(log)
    assert result == {"1.1.1.1": 1}


def test_skips_malformed_lines(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Sep  8 10:14:22 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "Sep  8 10:15:00 server sshd[4]: Failed password for root\n"
    )
    result = parse_log(log)
    assert result == {"1.1.1.1": 1}


def test_empty_files(tmp_path):
    log = tmp_path / "test.log"
    log.write_text("")

    result = parse_log(log)
    assert result == {}


def test_parse_timestamp():
    line = "Sep  8 10:14:22 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2"
    result = parse_timestamp(line)
    assert result == datetime(2026, 9, 8, 10, 14, 22)


def test_collect_attempts(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Sep  8 10:14:22 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "Sep  8 10:14:25 server sshd[2]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "Sep  8 10:14:28 server sshd[3]: Failed password for admin from 2.2.2.2 port 22 ssh2\n"
    )
    result = collect_attempts(log)
    assert result == {
        "1.1.1.1": [datetime(2026, 9, 8, 10, 14, 22),datetime(2026, 9, 8, 10, 14, 25)],
        "2.2.2.2": [datetime(2026, 9, 8, 10, 14, 28)],
    }
def test_brute_force_detected():
    times = [
        datetime(2026, 9, 8, 10, 0, 0),
        datetime(2026, 9, 8, 10, 0, 5),
        datetime(2026, 9, 8, 10, 0, 10),
        datetime(2026, 9, 8, 10, 5, 0),
    ]
    assert is_brute_force(times, 3, 30) is True