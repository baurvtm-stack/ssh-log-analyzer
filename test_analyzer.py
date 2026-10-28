from analyzer import parse_log

def test_counts_failed_attemtps(tmp_path):
    log = tmp_path / "test.log"
    log.write_text(
        "Sep  8 10:14:22 server sshd[1]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "Sep  8 10:14:25 server sshd[2]: Failed password for root from 1.1.1.1 port 22 ssh2\n"
        "Sep  8 10:14:28 server sshd[3]: Failed password for admin from 2.2.2.2 port 22 ssh2\n"
    )
    result = parse_log(log)
    assert result == {"1.1.1.1": 2, '2.2.2.2' : 1}
    
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