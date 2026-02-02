-- XDR Platform ClickHouse Detection Rules
-- 보안 탐지 규칙 (SQL 기반)

-- ============================================
-- 1. 초기 접근 (Initial Access)
-- ============================================

-- 1.1 피싱 첨부파일 실행 체인
-- MITRE: T1566.001
CREATE VIEW IF NOT EXISTS xdr.rule_phishing_attachment AS
SELECT
    p1.event_time,
    p1.host_name,
    p1.user_name,
    p1.process_name as office_app,
    p2.process_name as spawned_process,
    p2.process_command_line,
    'T1566.001' as mitre_technique,
    'Initial Access' as mitre_tactic,
    'high' as severity
FROM xdr.edr_process p1
INNER JOIN xdr.edr_process p2
    ON p1.host_name = p2.host_name
    AND p1.process_pid = p2.parent_pid
    AND p2.event_time BETWEEN p1.event_time AND p1.event_time + INTERVAL 5 MINUTE
WHERE p1.process_name IN ('WINWORD.EXE', 'EXCEL.EXE', 'POWERPNT.EXE', 'OUTLOOK.EXE')
  AND p2.process_name IN ('cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe', 'mshta.exe')
  AND p1.event_time > now() - INTERVAL 1 HOUR;

-- ============================================
-- 2. 실행 (Execution)
-- ============================================

-- 2.1 인코딩된 PowerShell
-- MITRE: T1059.001
CREATE VIEW IF NOT EXISTS xdr.rule_encoded_powershell AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    parent_name,
    'T1059.001' as mitre_technique,
    'Execution' as mitre_tactic,
    'high' as severity
FROM xdr.edr_process
WHERE process_name IN ('powershell.exe', 'pwsh.exe')
  AND (
      lower(process_command_line) LIKE '%-enc%'
      OR lower(process_command_line) LIKE '%-encodedcommand%'
      OR lower(process_command_line) LIKE '%frombase64string%'
  )
  AND event_time > now() - INTERVAL 1 HOUR;

-- 2.2 LOLBAS - Certutil 다운로드
-- MITRE: T1105
CREATE VIEW IF NOT EXISTS xdr.rule_certutil_download AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1105' as mitre_technique,
    'Command and Control' as mitre_tactic,
    'high' as severity
FROM xdr.edr_process
WHERE process_name = 'certutil.exe'
  AND (
      lower(process_command_line) LIKE '%-urlcache%'
      OR lower(process_command_line) LIKE '%-split%'
  )
  AND event_time > now() - INTERVAL 1 HOUR;

-- 2.3 WMI 프로세스 생성
-- MITRE: T1047
CREATE VIEW IF NOT EXISTS xdr.rule_wmi_execution AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1047' as mitre_technique,
    'Execution' as mitre_tactic,
    'medium' as severity
FROM xdr.edr_process
WHERE process_name = 'wmic.exe'
  AND lower(process_command_line) LIKE '%process%call%create%'
  AND event_time > now() - INTERVAL 1 HOUR;

-- ============================================
-- 3. 지속성 (Persistence)
-- ============================================

-- 3.1 스케줄 작업 생성
-- MITRE: T1053.005
CREATE VIEW IF NOT EXISTS xdr.rule_scheduled_task_creation AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1053.005' as mitre_technique,
    'Persistence' as mitre_tactic,
    'medium' as severity
FROM xdr.edr_process
WHERE process_name = 'schtasks.exe'
  AND lower(process_command_line) LIKE '%/create%'
  AND event_time > now() - INTERVAL 1 HOUR;

-- 3.2 서비스 생성
-- MITRE: T1543.003
CREATE VIEW IF NOT EXISTS xdr.rule_service_creation AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1543.003' as mitre_technique,
    'Persistence' as mitre_tactic,
    'high' as severity
FROM xdr.edr_process
WHERE process_name = 'sc.exe'
  AND lower(process_command_line) LIKE '%create%'
  AND event_time > now() - INTERVAL 1 HOUR;

-- ============================================
-- 4. 권한 상승 (Privilege Escalation)
-- ============================================

-- 4.1 UAC 우회 시도
-- MITRE: T1548.002
CREATE VIEW IF NOT EXISTS xdr.rule_uac_bypass AS
SELECT
    event_time,
    host_name,
    user_name,
    process_name,
    process_command_line,
    parent_name,
    'T1548.002' as mitre_technique,
    'Privilege Escalation' as mitre_tactic,
    'high' as severity
FROM xdr.edr_process
WHERE (
    -- eventvwr.exe bypass
    (parent_name = 'eventvwr.exe' AND process_name NOT IN ('mmc.exe'))
    -- fodhelper.exe bypass
    OR (parent_name = 'fodhelper.exe' AND process_name NOT IN ('fodhelper.exe'))
    -- computerdefaults.exe bypass
    OR (parent_name = 'computerdefaults.exe')
)
  AND event_time > now() - INTERVAL 1 HOUR;

-- ============================================
-- 5. 방어 회피 (Defense Evasion)
-- ============================================

-- 5.1 보안 도구 비활성화
-- MITRE: T1562.001
CREATE VIEW IF NOT EXISTS xdr.rule_disable_security_tools AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1562.001' as mitre_technique,
    'Defense Evasion' as mitre_tactic,
    'critical' as severity
FROM xdr.edr_process
WHERE (
    -- Disable Windows Defender
    lower(process_command_line) LIKE '%set-mppreference%disablerealtimemonitoring%'
    OR lower(process_command_line) LIKE '%sc%stop%windefend%'
    -- Disable firewall
    OR lower(process_command_line) LIKE '%netsh%firewall%off%'
    OR lower(process_command_line) LIKE '%netsh%advfirewall%off%'
    -- Stop security services
    OR (lower(process_command_line) LIKE '%net%stop%'
        AND lower(process_command_line) LIKE '%defender%')
)
  AND event_time > now() - INTERVAL 1 HOUR;

-- 5.2 로그 삭제
-- MITRE: T1070.001
CREATE VIEW IF NOT EXISTS xdr.rule_log_clearing AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1070.001' as mitre_technique,
    'Defense Evasion' as mitre_tactic,
    'critical' as severity
FROM xdr.edr_process
WHERE (
    (process_name = 'wevtutil.exe' AND lower(process_command_line) LIKE '%cl %')
    OR lower(process_command_line) LIKE '%clear-eventlog%'
)
  AND event_time > now() - INTERVAL 1 HOUR;

-- ============================================
-- 6. 자격 증명 접근 (Credential Access)
-- ============================================

-- 6.1 LSASS 메모리 접근
-- MITRE: T1003.001
CREATE VIEW IF NOT EXISTS xdr.rule_lsass_access AS
SELECT
    event_time,
    host_name,
    user_name,
    process_name,
    process_command_line,
    'T1003.001' as mitre_technique,
    'Credential Access' as mitre_tactic,
    'critical' as severity
FROM xdr.edr_process
WHERE (
    -- Direct LSASS tools
    lower(process_command_line) LIKE '%sekurlsa%'
    OR lower(process_command_line) LIKE '%logonpasswords%'
    -- Procdump on LSASS
    OR (lower(process_command_line) LIKE '%procdump%' AND lower(process_command_line) LIKE '%lsass%')
    -- comsvcs.dll MiniDump
    OR (lower(process_command_line) LIKE '%comsvcs%' AND lower(process_command_line) LIKE '%minidump%')
)
  AND event_time > now() - INTERVAL 1 HOUR;

-- 6.2 SAM/SYSTEM 레지스트리 덤프
-- MITRE: T1003.002
CREATE VIEW IF NOT EXISTS xdr.rule_registry_dump AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1003.002' as mitre_technique,
    'Credential Access' as mitre_tactic,
    'critical' as severity
FROM xdr.edr_process
WHERE process_name = 'reg.exe'
  AND lower(process_command_line) LIKE '%save%'
  AND (
      lower(process_command_line) LIKE '%sam%'
      OR lower(process_command_line) LIKE '%system%'
      OR lower(process_command_line) LIKE '%security%'
  )
  AND event_time > now() - INTERVAL 1 HOUR;

-- ============================================
-- 7. 측면 이동 (Lateral Movement)
-- ============================================

-- 7.1 PsExec 사용
-- MITRE: T1021.002
CREATE VIEW IF NOT EXISTS xdr.rule_psexec AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1021.002' as mitre_technique,
    'Lateral Movement' as mitre_tactic,
    'high' as severity
FROM xdr.edr_process
WHERE (
    lower(process_name) LIKE '%psexec%'
    OR (process_name = 'cmd.exe' AND lower(process_command_line) LIKE '%\\\\%')
)
  AND event_time > now() - INTERVAL 1 HOUR;

-- 7.2 WMI 원격 실행
-- MITRE: T1021.003
CREATE VIEW IF NOT EXISTS xdr.rule_wmi_lateral AS
SELECT
    event_time,
    host_name,
    user_name,
    process_command_line,
    'T1021.003' as mitre_technique,
    'Lateral Movement' as mitre_tactic,
    'high' as severity
FROM xdr.edr_process
WHERE process_name = 'wmic.exe'
  AND lower(process_command_line) LIKE '%/node:%'
  AND event_time > now() - INTERVAL 1 HOUR;

-- ============================================
-- 8. C2 통신 (Command and Control)
-- ============================================

-- 8.1 비콘 패턴 탐지 (주기적 통신)
-- MITRE: T1071
CREATE VIEW IF NOT EXISTS xdr.rule_c2_beaconing AS
WITH intervals AS (
    SELECT
        src_ip,
        dst_ip,
        dst_port,
        ts,
        dateDiff('second', lagInFrame(ts) OVER (
            PARTITION BY src_ip, dst_ip, dst_port ORDER BY ts
        ), ts) as interval_sec
    FROM xdr.ndr_conn
    WHERE ts > now() - INTERVAL 1 HOUR
)
SELECT
    src_ip,
    dst_ip,
    dst_port,
    count() as beacon_count,
    round(avg(interval_sec), 1) as avg_interval,
    round(stddevPop(interval_sec), 2) as interval_stddev,
    'T1071' as mitre_technique,
    'Command and Control' as mitre_tactic,
    'high' as severity
FROM intervals
WHERE interval_sec > 0 AND interval_sec < 3600
GROUP BY src_ip, dst_ip, dst_port
HAVING beacon_count >= 10 AND interval_stddev < 10;

-- 8.2 DNS 터널링 의심
-- MITRE: T1071.004
CREATE VIEW IF NOT EXISTS xdr.rule_dns_tunneling AS
SELECT
    src_ip,
    query,
    length(query) as query_length,
    count() as query_count,
    'T1071.004' as mitre_technique,
    'Command and Control' as mitre_tactic,
    'high' as severity
FROM xdr.ndr_dns
WHERE ts > now() - INTERVAL 1 HOUR
  AND length(query) > 50
GROUP BY src_ip, query
HAVING query_count > 5;

-- ============================================
-- 9. 데이터 유출 (Exfiltration)
-- ============================================

-- 9.1 대용량 외부 전송
-- MITRE: T1048
CREATE VIEW IF NOT EXISTS xdr.rule_data_exfiltration AS
SELECT
    src_ip,
    dst_ip,
    dst_port,
    sum(orig_bytes) as total_bytes_out,
    formatReadableSize(sum(orig_bytes)) as readable_size,
    count() as connection_count,
    'T1048' as mitre_technique,
    'Exfiltration' as mitre_tactic,
    'high' as severity
FROM xdr.ndr_conn
WHERE ts > now() - INTERVAL 1 HOUR
  AND NOT (
      dst_ip BETWEEN toIPv4('10.0.0.0') AND toIPv4('10.255.255.255')
      OR dst_ip BETWEEN toIPv4('172.16.0.0') AND toIPv4('172.31.255.255')
      OR dst_ip BETWEEN toIPv4('192.168.0.0') AND toIPv4('192.168.255.255')
  )
GROUP BY src_ip, dst_ip, dst_port
HAVING total_bytes_out > 100000000;  -- 100MB

-- ============================================
-- 통합 탐지 쿼리 (모든 규칙 실행)
-- ============================================

-- 모든 활성 알림 조회
CREATE VIEW IF NOT EXISTS xdr.active_detections AS
SELECT * FROM xdr.rule_encoded_powershell
UNION ALL SELECT * FROM xdr.rule_certutil_download
UNION ALL SELECT * FROM xdr.rule_wmi_execution
UNION ALL SELECT * FROM xdr.rule_scheduled_task_creation
UNION ALL SELECT * FROM xdr.rule_service_creation
UNION ALL SELECT * FROM xdr.rule_disable_security_tools
UNION ALL SELECT * FROM xdr.rule_log_clearing
UNION ALL SELECT * FROM xdr.rule_lsass_access
UNION ALL SELECT * FROM xdr.rule_registry_dump
UNION ALL SELECT * FROM xdr.rule_psexec
UNION ALL SELECT * FROM xdr.rule_wmi_lateral;
