#!/usr/bin/env python3
"""
ClickHouse Connector for XDR Platform
보안 로그 분석 및 상관분석을 위한 ClickHouse 연동 모듈
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Generator
from dataclasses import dataclass, asdict
import clickhouse_connect
from clickhouse_connect.driver import Client

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# 설정
CONFIG = {
    "host": "localhost",
    "port": 8123,
    "database": "xdr",
    "username": "xdr_reader",
    "password": "YOUR_PASSWORD",
    "secure": False,
    "connect_timeout": 10,
    "query_timeout": 300
}


@dataclass
class SecurityAlert:
    """보안 알림 데이터 클래스"""
    alert_id: str
    alert_time: datetime
    rule_name: str
    severity: str
    host_name: str
    user_name: Optional[str]
    src_ip: Optional[str]
    dst_ip: Optional[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    description: str
    evidence: Dict


class ClickHouseConnector:
    """ClickHouse 연동 클래스"""

    def __init__(self, config: Dict = None):
        self.config = config or CONFIG
        self.client: Optional[Client] = None

    def connect(self) -> Client:
        """ClickHouse 연결"""
        if self.client is None:
            self.client = clickhouse_connect.get_client(
                host=self.config["host"],
                port=self.config["port"],
                database=self.config["database"],
                username=self.config["username"],
                password=self.config["password"],
                secure=self.config.get("secure", False),
                connect_timeout=self.config.get("connect_timeout", 10)
            )
            logger.info(f"Connected to ClickHouse: {self.config['host']}")
        return self.client

    def close(self):
        """연결 종료"""
        if self.client:
            self.client.close()
            self.client = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ============================================
    # 조회 메서드
    # ============================================

    def get_process_events(
        self,
        host_name: str = None,
        process_name: str = None,
        time_range_hours: int = 24,
        limit: int = 1000
    ) -> List[Dict]:
        """프로세스 이벤트 조회"""
        client = self.connect()

        conditions = [f"event_time > now() - INTERVAL {time_range_hours} HOUR"]
        params = {}

        if host_name:
            conditions.append("host_name = {host_name:String}")
            params["host_name"] = host_name

        if process_name:
            conditions.append("process_name = {process_name:String}")
            params["process_name"] = process_name

        query = f"""
            SELECT
                event_time,
                host_name,
                user_name,
                process_name,
                process_path,
                process_pid,
                process_command_line,
                process_hash_sha256,
                parent_name,
                parent_pid,
                event_type
            FROM edr_process
            WHERE {' AND '.join(conditions)}
            ORDER BY event_time DESC
            LIMIT {limit}
        """

        result = client.query(query, parameters=params)
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def get_network_connections(
        self,
        src_ip: str = None,
        dst_ip: str = None,
        dst_port: int = None,
        time_range_hours: int = 24,
        limit: int = 1000
    ) -> List[Dict]:
        """네트워크 연결 조회"""
        client = self.connect()

        conditions = [f"event_time > now() - INTERVAL {time_range_hours} HOUR"]
        params = {}

        if src_ip:
            conditions.append("src_ip = toIPv4({src_ip:String})")
            params["src_ip"] = src_ip

        if dst_ip:
            conditions.append("dst_ip = toIPv4({dst_ip:String})")
            params["dst_ip"] = dst_ip

        if dst_port:
            conditions.append("dst_port = {dst_port:UInt16}")
            params["dst_port"] = dst_port

        query = f"""
            SELECT
                event_time,
                host_name,
                process_name,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
                protocol,
                direction,
                bytes_sent,
                bytes_recv
            FROM edr_network
            WHERE {' AND '.join(conditions)}
            ORDER BY event_time DESC
            LIMIT {limit}
        """

        result = client.query(query, parameters=params)
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def search_ioc(
        self,
        ioc_type: str,
        ioc_value: str,
        time_range_hours: int = 24
    ) -> Dict[str, List[Dict]]:
        """IOC 검색 (다중 테이블)"""
        client = self.connect()
        results = {}

        if ioc_type == "ip":
            # 네트워크 연결에서 검색
            query = """
                SELECT event_time, host_name, process_name, src_ip, dst_ip, dst_port
                FROM edr_network
                WHERE (src_ip = toIPv4({ip:String}) OR dst_ip = toIPv4({ip:String}))
                  AND event_time > now() - INTERVAL {hours:UInt32} HOUR
                ORDER BY event_time DESC
                LIMIT 100
            """
            result = client.query(query, parameters={"ip": ioc_value, "hours": time_range_hours})
            results["edr_network"] = [dict(zip(result.column_names, row)) for row in result.result_rows]

            # NDR Conn에서 검색
            query = """
                SELECT ts, src_ip, dst_ip, dst_port, proto, service, orig_bytes, resp_bytes
                FROM ndr_conn
                WHERE (src_ip = toIPv4({ip:String}) OR dst_ip = toIPv4({ip:String}))
                  AND ts > now() - INTERVAL {hours:UInt32} HOUR
                ORDER BY ts DESC
                LIMIT 100
            """
            result = client.query(query, parameters={"ip": ioc_value, "hours": time_range_hours})
            results["ndr_conn"] = [dict(zip(result.column_names, row)) for row in result.result_rows]

        elif ioc_type == "hash":
            # 프로세스에서 해시 검색
            query = """
                SELECT event_time, host_name, user_name, process_name, process_path, process_command_line
                FROM edr_process
                WHERE process_hash_sha256 = {hash:FixedString(64)}
                  AND event_time > now() - INTERVAL {hours:UInt32} HOUR
                ORDER BY event_time DESC
                LIMIT 100
            """
            result = client.query(query, parameters={"hash": ioc_value.lower(), "hours": time_range_hours})
            results["edr_process"] = [dict(zip(result.column_names, row)) for row in result.result_rows]

            # 파일에서 해시 검색
            query = """
                SELECT event_time, host_name, user_name, file_path, file_name, event_type
                FROM edr_file
                WHERE file_hash_sha256 = {hash:FixedString(64)}
                  AND event_time > now() - INTERVAL {hours:UInt32} HOUR
                ORDER BY event_time DESC
                LIMIT 100
            """
            result = client.query(query, parameters={"hash": ioc_value.lower(), "hours": time_range_hours})
            results["edr_file"] = [dict(zip(result.column_names, row)) for row in result.result_rows]

        elif ioc_type == "domain":
            # DNS 쿼리에서 검색
            query = """
                SELECT ts, src_ip, query, qtype, answers
                FROM ndr_dns
                WHERE query LIKE {domain:String}
                  AND ts > now() - INTERVAL {hours:UInt32} HOUR
                ORDER BY ts DESC
                LIMIT 100
            """
            result = client.query(query, parameters={"domain": f"%{ioc_value}%", "hours": time_range_hours})
            results["ndr_dns"] = [dict(zip(result.column_names, row)) for row in result.result_rows]

        return results

    # ============================================
    # 상관분석 쿼리
    # ============================================

    def detect_suspicious_powershell(self, time_range_hours: int = 1) -> List[Dict]:
        """의심스러운 PowerShell 실행 탐지"""
        client = self.connect()

        query = """
            SELECT
                event_time,
                host_name,
                user_name,
                process_command_line,
                parent_name,
                parent_pid
            FROM edr_process
            WHERE process_name IN ('powershell.exe', 'pwsh.exe')
              AND (
                  lower(process_command_line) LIKE '%encodedcommand%'
                  OR lower(process_command_line) LIKE '%-enc %'
                  OR lower(process_command_line) LIKE '%downloadstring%'
                  OR lower(process_command_line) LIKE '%invoke-expression%'
                  OR lower(process_command_line) LIKE '%iex%'
                  OR lower(process_command_line) LIKE '%bypass%'
                  OR lower(process_command_line) LIKE '%hidden%'
              )
              AND event_time > now() - INTERVAL {hours:UInt32} HOUR
            ORDER BY event_time DESC
        """

        result = client.query(query, parameters={"hours": time_range_hours})
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def detect_c2_beaconing(
        self,
        time_range_hours: int = 1,
        min_connections: int = 10,
        max_interval_stddev: float = 5.0
    ) -> List[Dict]:
        """C2 비콘 패턴 탐지"""
        client = self.connect()

        query = """
            WITH connection_intervals AS (
                SELECT
                    src_ip,
                    dst_ip,
                    dst_port,
                    ts,
                    dateDiff('second', lagInFrame(ts) OVER (
                        PARTITION BY src_ip, dst_ip, dst_port ORDER BY ts
                    ), ts) as interval_sec
                FROM ndr_conn
                WHERE ts > now() - INTERVAL {hours:UInt32} HOUR
                  AND dst_port IN (80, 443, 8080, 8443)
            )
            SELECT
                src_ip,
                dst_ip,
                dst_port,
                count() as connection_count,
                round(avg(interval_sec), 2) as avg_interval,
                round(stddevPop(interval_sec), 2) as interval_stddev,
                min(ts) as first_seen,
                max(ts) as last_seen
            FROM connection_intervals
            WHERE interval_sec > 0
            GROUP BY src_ip, dst_ip, dst_port
            HAVING connection_count >= {min_conn:UInt32}
               AND interval_stddev < {max_stddev:Float64}
               AND interval_stddev > 0
            ORDER BY connection_count DESC
        """

        result = client.query(query, parameters={
            "hours": time_range_hours,
            "min_conn": min_connections,
            "max_stddev": max_interval_stddev
        })
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def detect_lateral_movement(self, time_range_hours: int = 24) -> List[Dict]:
        """측면 이동 탐지 (PsExec, WMI 등)"""
        client = self.connect()

        query = """
            SELECT
                event_time,
                host_name,
                user_name,
                process_name,
                process_command_line,
                parent_name
            FROM edr_process
            WHERE (
                -- PsExec
                lower(process_name) LIKE '%psexec%'
                -- WMI
                OR (process_name = 'wmic.exe' AND lower(process_command_line) LIKE '%/node:%')
                -- Remote PowerShell
                OR (process_name IN ('powershell.exe', 'pwsh.exe')
                    AND lower(process_command_line) LIKE '%invoke-command%')
                -- WinRM
                OR process_name = 'winrs.exe'
                -- Service creation
                OR (process_name = 'sc.exe'
                    AND lower(process_command_line) LIKE '%\\\\%'
                    AND lower(process_command_line) LIKE '%create%')
            )
              AND event_time > now() - INTERVAL {hours:UInt32} HOUR
            ORDER BY event_time DESC
        """

        result = client.query(query, parameters={"hours": time_range_hours})
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def detect_credential_access(self, time_range_hours: int = 24) -> List[Dict]:
        """자격 증명 접근 탐지"""
        client = self.connect()

        query = """
            SELECT
                event_time,
                host_name,
                user_name,
                process_name,
                process_command_line,
                parent_name
            FROM edr_process
            WHERE (
                -- Mimikatz patterns
                lower(process_command_line) LIKE '%sekurlsa%'
                OR lower(process_command_line) LIKE '%logonpasswords%'
                -- LSASS dump
                OR (lower(process_command_line) LIKE '%lsass%'
                    AND lower(process_command_line) LIKE '%dump%')
                -- Credential tools
                OR lower(process_name) IN ('mimikatz.exe', 'procdump.exe', 'comsvcs.dll')
                -- Registry credential access
                OR (process_name = 'reg.exe'
                    AND lower(process_command_line) LIKE '%save%'
                    AND (lower(process_command_line) LIKE '%sam%'
                         OR lower(process_command_line) LIKE '%system%'
                         OR lower(process_command_line) LIKE '%security%'))
                -- NTDS.dit access
                OR lower(process_command_line) LIKE '%ntds.dit%'
            )
              AND event_time > now() - INTERVAL {hours:UInt32} HOUR
            ORDER BY event_time DESC
        """

        result = client.query(query, parameters={"hours": time_range_hours})
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    def detect_data_exfiltration(
        self,
        time_range_hours: int = 24,
        min_bytes: int = 100_000_000  # 100MB
    ) -> List[Dict]:
        """데이터 유출 탐지"""
        client = self.connect()

        query = """
            SELECT
                src_ip,
                dst_ip,
                dst_port,
                count() as connection_count,
                sum(orig_bytes) as total_bytes_out,
                formatReadableSize(sum(orig_bytes)) as readable_bytes,
                min(ts) as first_seen,
                max(ts) as last_seen
            FROM ndr_conn
            WHERE ts > now() - INTERVAL {hours:UInt32} HOUR
              AND orig_bytes > 0
              AND NOT (
                  dst_ip BETWEEN toIPv4('10.0.0.0') AND toIPv4('10.255.255.255')
                  OR dst_ip BETWEEN toIPv4('172.16.0.0') AND toIPv4('172.31.255.255')
                  OR dst_ip BETWEEN toIPv4('192.168.0.0') AND toIPv4('192.168.255.255')
              )
            GROUP BY src_ip, dst_ip, dst_port
            HAVING total_bytes_out >= {min_bytes:UInt64}
            ORDER BY total_bytes_out DESC
            LIMIT 100
        """

        result = client.query(query, parameters={
            "hours": time_range_hours,
            "min_bytes": min_bytes
        })
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    # ============================================
    # 알림 관리
    # ============================================

    def create_alert(self, alert: SecurityAlert) -> str:
        """보안 알림 생성"""
        client = self.connect()

        query = """
            INSERT INTO alerts (
                alert_time, alert_id, rule_name, severity,
                host_name, user_name, src_ip, dst_ip,
                mitre_tactics, mitre_techniques, description, evidence
            ) VALUES
        """

        data = [[
            alert.alert_time,
            alert.alert_id,
            alert.rule_name,
            alert.severity,
            alert.host_name,
            alert.user_name,
            alert.src_ip,
            alert.dst_ip,
            alert.mitre_tactics,
            alert.mitre_techniques,
            alert.description,
            json.dumps(alert.evidence)
        ]]

        client.insert('alerts', data, column_names=[
            'alert_time', 'alert_id', 'rule_name', 'severity',
            'host_name', 'user_name', 'src_ip', 'dst_ip',
            'mitre_tactics', 'mitre_techniques', 'description', 'evidence'
        ])

        logger.info(f"Alert created: {alert.alert_id}")
        return alert.alert_id

    def get_alerts(
        self,
        severity: str = None,
        status: str = None,
        time_range_hours: int = 24,
        limit: int = 100
    ) -> List[Dict]:
        """알림 조회"""
        client = self.connect()

        conditions = [f"alert_time > now() - INTERVAL {time_range_hours} HOUR"]
        params = {}

        if severity:
            conditions.append("severity = {severity:String}")
            params["severity"] = severity

        if status:
            conditions.append("status = {status:String}")
            params["status"] = status

        query = f"""
            SELECT *
            FROM alerts
            WHERE {' AND '.join(conditions)}
            ORDER BY alert_time DESC
            LIMIT {limit}
        """

        result = client.query(query, parameters=params)
        return [dict(zip(result.column_names, row)) for row in result.result_rows]

    # ============================================
    # 위협 인텔리전스
    # ============================================

    def add_iocs(self, iocs: List[Dict]) -> int:
        """IOC 추가"""
        client = self.connect()

        data = []
        for ioc in iocs:
            data.append([
                ioc['type'],
                ioc['value'],
                ioc.get('source', 'manual'),
                ioc.get('confidence', 50),
                ioc.get('severity', 'medium'),
                ioc.get('tags', []),
                datetime.utcnow(),
                datetime.utcnow(),
                datetime.utcnow() + timedelta(days=ioc.get('ttl_days', 30))
            ])

        client.insert('threat_intel', data, column_names=[
            'ioc_type', 'ioc_value', 'source', 'confidence', 'severity',
            'tags', 'first_seen', 'last_seen', 'expiration'
        ])

        logger.info(f"Added {len(iocs)} IOCs")
        return len(iocs)

    def match_iocs(self, time_range_hours: int = 1) -> List[Dict]:
        """IOC 매칭 (실시간)"""
        client = self.connect()

        # 해시 매칭
        hash_query = """
            SELECT
                p.event_time,
                p.host_name,
                p.user_name,
                p.process_name,
                p.process_hash_sha256 as matched_ioc,
                t.source as ioc_source,
                t.severity as ioc_severity,
                t.tags as ioc_tags
            FROM edr_process p
            INNER JOIN threat_intel t ON p.process_hash_sha256 = t.ioc_value
            WHERE p.event_time > now() - INTERVAL {hours:UInt32} HOUR
              AND t.ioc_type IN ('hash_sha256', 'hash')
              AND t.expiration > now()
        """

        # IP 매칭
        ip_query = """
            SELECT
                n.event_time,
                n.host_name,
                n.process_name,
                toString(n.dst_ip) as matched_ioc,
                t.source as ioc_source,
                t.severity as ioc_severity,
                t.tags as ioc_tags
            FROM edr_network n
            INNER JOIN threat_intel t ON toString(n.dst_ip) = t.ioc_value
            WHERE n.event_time > now() - INTERVAL {hours:UInt32} HOUR
              AND t.ioc_type = 'ip'
              AND t.expiration > now()
        """

        results = []

        hash_result = client.query(hash_query, parameters={"hours": time_range_hours})
        results.extend([dict(zip(hash_result.column_names, row)) for row in hash_result.result_rows])

        ip_result = client.query(ip_query, parameters={"hours": time_range_hours})
        results.extend([dict(zip(ip_result.column_names, row)) for row in ip_result.result_rows])

        return results


def main():
    """테스트 함수"""
    with ClickHouseConnector(CONFIG) as ch:
        # 의심스러운 PowerShell 탐지
        print("=== Suspicious PowerShell ===")
        results = ch.detect_suspicious_powershell(time_range_hours=24)
        for r in results[:5]:
            print(f"  {r['event_time']} | {r['host_name']} | {r['process_command_line'][:80]}...")

        # C2 비콘 탐지
        print("\n=== C2 Beaconing ===")
        results = ch.detect_c2_beaconing(time_range_hours=24)
        for r in results[:5]:
            print(f"  {r['src_ip']} -> {r['dst_ip']}:{r['dst_port']} | "
                  f"Count: {r['connection_count']} | Stddev: {r['interval_stddev']}")

        # 측면 이동 탐지
        print("\n=== Lateral Movement ===")
        results = ch.detect_lateral_movement(time_range_hours=24)
        for r in results[:5]:
            print(f"  {r['event_time']} | {r['host_name']} | {r['process_name']}")


if __name__ == "__main__":
    main()
