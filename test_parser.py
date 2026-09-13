from sentinelai.parsers import parse_logs

def test_failed_login():
    e=parse_logs('2026-09-03T10:00:00Z FAILED_LOGIN user=admin src=1.2.3.4 service=ssh')
    assert len(e)==1
    assert e[0].source_ip=='1.2.3.4'
    assert e[0].event_type=='FAILED_LOGIN'
