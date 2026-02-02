-- XDR Platform ClickHouse Schema
-- 보안 로그 분석을 위한 테이블 정의

-- ============================================
-- 데이터베이스 생성
-- ============================================
CREATE DATABASE IF NOT EXISTS xdr;

-- ============================================
-- 공통 딕셔너리 테이블
-- ============================================

-- MITRE ATT&CK 매핑 테이블
CREATE TABLE IF NOT EXISTS xdr.mitre_mapping
(
    technique_id String,
    technique_name String,
    tactic_id String,
    tactic_name String,
    description String
)
ENGINE = MergeTree()
ORDER BY technique_id;

-- 위협 인텔리전스 IOC 테이블
CREATE TABLE IF NOT EXISTS xdr.threat_intel
(
    ioc_type LowCardinality(String),  -- ip, domain, hash, url
    ioc_value String,
    source LowCardinality(String),
    confidence UInt8,
    severity LowCardinality(String),
    tags Array(String),
    first_seen DateTime,
    last_seen DateTime,
    expiration DateTime,
    INDEX idx_ioc_value ioc_value TYPE bloom_filter GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(first_seen)
ORDER BY (ioc_type, ioc_value)
TTL expiration;

-- ============================================
-- EDR 로그 테이블
-- ============================================

-- 프로세스 이벤트 (메인 테이블)
CREATE TABLE IF NOT EXISTS xdr.edr_process
(
    event_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    event_date Date DEFAULT toDate(event_time),
    event_id UUID DEFAULT generateUUIDv4(),

    -- 호스트 정보
    host_name LowCardinality(String),
    host_ip IPv4,
    host_os LowCardinality(String),

    -- 사용자 정보
    user_name LowCardinality(String),
    user_domain LowCardinality(String),

    -- 프로세스 정보
    process_name LowCardinality(String),
    process_path String,
    process_pid UInt32,
    process_command_line String,
    process_hash_sha256 FixedString(64),
    process_hash_md5 FixedString(32),

    -- 부모 프로세스
    parent_name LowCardinality(String),
    parent_path String,
    parent_pid UInt32,
    parent_command_line String,

    -- 이벤트 유형
    event_type LowCardinality(String),  -- create, terminate, access
    event_action LowCardinality(String),

    -- 메타데이터
    raw_event String CODEC(ZSTD(3)),

    -- 인덱스
    INDEX idx_process_name process_name TYPE set(1000) GRANULARITY 4,
    INDEX idx_command_line command_line TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4,
    INDEX idx_hash_sha256 process_hash_sha256 TYPE bloom_filter GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (host_name, event_time, process_name)
TTL event_date + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- 네트워크 연결 이벤트
CREATE TABLE IF NOT EXISTS xdr.edr_network
(
    event_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    event_date Date DEFAULT toDate(event_time),
    event_id UUID DEFAULT generateUUIDv4(),

    -- 호스트 정보
    host_name LowCardinality(String),
    host_ip IPv4,

    -- 프로세스 정보
    process_name LowCardinality(String),
    process_pid UInt32,

    -- 연결 정보
    src_ip IPv4,
    src_port UInt16,
    dst_ip IPv4,
    dst_port UInt16,
    protocol LowCardinality(String),
    direction LowCardinality(String),  -- inbound, outbound
    bytes_sent UInt64,
    bytes_recv UInt64,

    -- DNS (선택)
    dns_query String,

    -- 인덱스
    INDEX idx_dst_ip dst_ip TYPE set(10000) GRANULARITY 4,
    INDEX idx_dst_port dst_port TYPE set(1000) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (host_name, event_time, dst_ip)
TTL event_date + INTERVAL 30 DAY DELETE;

-- 파일 이벤트
CREATE TABLE IF NOT EXISTS xdr.edr_file
(
    event_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    event_date Date DEFAULT toDate(event_time),
    event_id UUID DEFAULT generateUUIDv4(),

    -- 호스트/사용자
    host_name LowCardinality(String),
    user_name LowCardinality(String),

    -- 프로세스
    process_name LowCardinality(String),
    process_pid UInt32,

    -- 파일 정보
    file_path String,
    file_name String,
    file_extension LowCardinality(String),
    file_size UInt64,
    file_hash_sha256 FixedString(64),

    -- 이벤트 유형
    event_type LowCardinality(String),  -- create, modify, delete, rename

    INDEX idx_file_hash file_hash_sha256 TYPE bloom_filter GRANULARITY 1,
    INDEX idx_file_path file_path TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (host_name, event_time)
TTL event_date + INTERVAL 30 DAY DELETE;

-- ============================================
-- NDR 로그 테이블
-- ============================================

-- Zeek Conn 로그
CREATE TABLE IF NOT EXISTS xdr.ndr_conn
(
    ts DateTime64(6) CODEC(DoubleDelta, ZSTD(1)),
    event_date Date DEFAULT toDate(ts),
    uid String,

    -- 연결 정보
    src_ip IPv4,
    src_port UInt16,
    dst_ip IPv4,
    dst_port UInt16,
    proto LowCardinality(String),

    -- 서비스
    service LowCardinality(String),

    -- 상태
    duration Float64,
    orig_bytes UInt64,
    resp_bytes UInt64,
    conn_state LowCardinality(String),

    -- JA3/JA3S
    ja3 FixedString(32),
    ja3s FixedString(32),

    -- 센서
    sensor_name LowCardinality(String),

    INDEX idx_dst_ip dst_ip TYPE set(10000) GRANULARITY 4,
    INDEX idx_ja3 ja3 TYPE bloom_filter GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (ts, src_ip, dst_ip)
TTL event_date + INTERVAL 30 DAY DELETE;

-- Zeek DNS 로그
CREATE TABLE IF NOT EXISTS xdr.ndr_dns
(
    ts DateTime64(6) CODEC(DoubleDelta, ZSTD(1)),
    event_date Date DEFAULT toDate(ts),
    uid String,

    src_ip IPv4,
    src_port UInt16,
    dst_ip IPv4,
    dst_port UInt16,

    -- DNS 정보
    query String,
    qtype LowCardinality(String),
    rcode LowCardinality(String),
    answers Array(String),

    INDEX idx_query query TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (ts, src_ip)
TTL event_date + INTERVAL 30 DAY DELETE;

-- Zeek HTTP 로그
CREATE TABLE IF NOT EXISTS xdr.ndr_http
(
    ts DateTime64(6) CODEC(DoubleDelta, ZSTD(1)),
    event_date Date DEFAULT toDate(ts),
    uid String,

    src_ip IPv4,
    src_port UInt16,
    dst_ip IPv4,
    dst_port UInt16,

    -- HTTP 정보
    method LowCardinality(String),
    host String,
    uri String,
    user_agent String,
    status_code UInt16,
    request_body_len UInt64,
    response_body_len UInt64,

    INDEX idx_host host TYPE set(10000) GRANULARITY 4,
    INDEX idx_uri uri TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (ts, src_ip)
TTL event_date + INTERVAL 30 DAY DELETE;

-- Suricata 알림
CREATE TABLE IF NOT EXISTS xdr.ndr_alert
(
    timestamp DateTime64(6) CODEC(DoubleDelta, ZSTD(1)),
    event_date Date DEFAULT toDate(timestamp),

    -- 연결 정보
    src_ip IPv4,
    src_port UInt16,
    dst_ip IPv4,
    dst_port UInt16,
    proto LowCardinality(String),

    -- 알림 정보
    alert_signature_id UInt32,
    alert_signature String,
    alert_category LowCardinality(String),
    alert_severity UInt8,

    -- 메타데이터
    sensor_name LowCardinality(String),
    raw_event String CODEC(ZSTD(3)),

    INDEX idx_sig_id alert_signature_id TYPE set(10000) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (timestamp, alert_severity)
TTL event_date + INTERVAL 90 DAY DELETE;

-- ============================================
-- SIEM 알림 테이블
-- ============================================

CREATE TABLE IF NOT EXISTS xdr.alerts
(
    alert_time DateTime64(3) CODEC(DoubleDelta, ZSTD(1)),
    alert_date Date DEFAULT toDate(alert_time),
    alert_id UUID DEFAULT generateUUIDv4(),

    -- 알림 정보
    rule_name String,
    rule_id String,
    severity LowCardinality(String),
    confidence UInt8,

    -- 대상
    host_name LowCardinality(String),
    user_name LowCardinality(String),
    src_ip Nullable(IPv4),
    dst_ip Nullable(IPv4),

    -- MITRE
    mitre_tactics Array(String),
    mitre_techniques Array(String),

    -- IOC
    iocs Nested(
        type String,
        value String
    ),

    -- 상태
    status LowCardinality(String) DEFAULT 'new',  -- new, investigating, resolved, false_positive
    assignee LowCardinality(String),

    -- 설명
    description String,
    evidence String CODEC(ZSTD(3))
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(alert_date)
ORDER BY (alert_time, severity)
TTL alert_date + INTERVAL 365 DAY DELETE;

-- ============================================
-- 뷰 및 Materialized View
-- ============================================

-- 실시간 호스트 활동 요약
CREATE MATERIALIZED VIEW IF NOT EXISTS xdr.mv_host_activity
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (event_date, host_name)
AS SELECT
    toDate(event_time) as event_date,
    host_name,
    count() as total_events,
    uniq(process_name) as unique_processes,
    uniq(user_name) as unique_users
FROM xdr.edr_process
GROUP BY event_date, host_name;

-- 네트워크 연결 통계
CREATE MATERIALIZED VIEW IF NOT EXISTS xdr.mv_network_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(event_date)
ORDER BY (event_date, dst_ip, dst_port)
AS SELECT
    toDate(ts) as event_date,
    dst_ip,
    dst_port,
    count() as connection_count,
    sum(orig_bytes + resp_bytes) as total_bytes,
    uniq(src_ip) as unique_sources
FROM xdr.ndr_conn
GROUP BY event_date, dst_ip, dst_port;

-- ============================================
-- 상관분석 쿼리 예시
-- ============================================

-- 1. 의심스러운 PowerShell 실행
-- SELECT * FROM xdr.edr_process
-- WHERE process_name = 'powershell.exe'
--   AND (command_line LIKE '%encodedcommand%'
--        OR command_line LIKE '%downloadstring%')
--   AND event_time > now() - INTERVAL 1 HOUR;

-- 2. C2 비콘 탐지 (주기적 통신)
-- WITH connection_intervals AS (
--     SELECT
--         src_ip,
--         dst_ip,
--         dst_port,
--         ts,
--         ts - lagInFrame(ts) OVER (PARTITION BY src_ip, dst_ip ORDER BY ts) as interval
--     FROM xdr.ndr_conn
--     WHERE ts > now() - INTERVAL 1 HOUR
-- )
-- SELECT src_ip, dst_ip, dst_port,
--        count() as conn_count,
--        avg(interval) as avg_interval,
--        stddevPop(interval) as interval_stddev
-- FROM connection_intervals
-- GROUP BY src_ip, dst_ip, dst_port
-- HAVING conn_count > 10 AND interval_stddev < 5;

-- 3. IOC 매칭
-- SELECT p.*, t.source, t.severity
-- FROM xdr.edr_process p
-- INNER JOIN xdr.threat_intel t ON p.process_hash_sha256 = t.ioc_value
-- WHERE t.ioc_type = 'hash'
--   AND p.event_time > now() - INTERVAL 24 HOUR;
