#!/usr/bin/env python3
"""
SIEM-EDR 연동 스크립트
XDR 플랫폼을 위한 SIEM과 EDR 간 양방향 연동
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# 설정 (실제 환경에서는 환경변수 또는 설정 파일 사용)
CONFIG = {
    "siem": {
        "type": "splunk",  # splunk 또는 elastic
        "url": "https://splunk.example.com:8089",
        "token": "YOUR_SPLUNK_TOKEN",
        "index": "xdr_alerts"
    },
    "edr": {
        "type": "crowdstrike",  # crowdstrike, defender, elastic_defend
        "url": "https://api.crowdstrike.com",
        "client_id": "YOUR_CLIENT_ID",
        "client_secret": "YOUR_CLIENT_SECRET"
    },
    "sync_interval": 60,  # 초
    "batch_size": 100
}


@dataclass
class Alert:
    """통합 알림 데이터 클래스"""
    id: str
    source: str
    timestamp: str
    severity: str
    title: str
    description: str
    host: str
    user: Optional[str]
    mitre_tactics: List[str]
    mitre_techniques: List[str]
    iocs: Dict[str, List[str]]
    raw_data: Dict


class SIEMConnector(ABC):
    """SIEM 연동 추상 클래스"""

    @abstractmethod
    def send_alert(self, alert: Alert) -> bool:
        pass

    @abstractmethod
    def get_alerts(self, time_range: int) -> List[Alert]:
        pass

    @abstractmethod
    def create_notable_event(self, alert: Alert) -> str:
        pass


class EDRConnector(ABC):
    """EDR 연동 추상 클래스"""

    @abstractmethod
    def get_detections(self, time_range: int) -> List[Alert]:
        pass

    @abstractmethod
    def isolate_host(self, hostname: str) -> bool:
        pass

    @abstractmethod
    def get_host_details(self, hostname: str) -> Dict:
        pass


class SplunkConnector(SIEMConnector):
    """Splunk SIEM 연동"""

    def __init__(self, config: Dict):
        self.url = config["url"]
        self.token = config["token"]
        self.index = config["index"]
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        })
        return session

    def send_alert(self, alert: Alert) -> bool:
        """EDR 알림을 Splunk로 전송"""
        try:
            url = f"{self.url}/services/collector/event"
            payload = {
                "index": self.index,
                "sourcetype": "xdr:edr:alert",
                "event": asdict(alert)
            }

            response = self.session.post(url, json=payload, verify=False)
            response.raise_for_status()

            logger.info(f"Alert sent to Splunk: {alert.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send alert to Splunk: {e}")
            return False

    def get_alerts(self, time_range: int = 300) -> List[Alert]:
        """Splunk에서 알림 조회"""
        try:
            url = f"{self.url}/services/search/jobs"
            query = f"""
                search index={self.index} earliest=-{time_range}s
                | where severity IN ("high", "critical")
                | table _time, alert_id, title, severity, host, user, mitre_*
            """

            # 검색 작업 생성
            response = self.session.post(
                url,
                data={"search": query, "output_mode": "json"},
                verify=False
            )
            response.raise_for_status()
            job_id = response.json()["sid"]

            # 결과 대기 및 조회
            time.sleep(2)
            results_url = f"{self.url}/services/search/jobs/{job_id}/results"
            results = self.session.get(
                results_url,
                params={"output_mode": "json"},
                verify=False
            )

            alerts = []
            for result in results.json().get("results", []):
                alert = Alert(
                    id=result.get("alert_id", ""),
                    source="splunk",
                    timestamp=result.get("_time", ""),
                    severity=result.get("severity", ""),
                    title=result.get("title", ""),
                    description="",
                    host=result.get("host", ""),
                    user=result.get("user"),
                    mitre_tactics=result.get("mitre_tactics", "").split(","),
                    mitre_techniques=result.get("mitre_techniques", "").split(","),
                    iocs={},
                    raw_data=result
                )
                alerts.append(alert)

            return alerts

        except Exception as e:
            logger.error(f"Failed to get alerts from Splunk: {e}")
            return []

    def create_notable_event(self, alert: Alert) -> str:
        """Splunk ES Notable Event 생성"""
        try:
            url = f"{self.url}/services/notable_update"
            payload = {
                "rule_name": f"XDR_EDR_{alert.title}",
                "security_domain": "endpoint",
                "severity": alert.severity,
                "status": "1",  # New
                "owner": "unassigned",
                "comment": f"EDR Detection: {alert.description}"
            }

            response = self.session.post(url, data=payload, verify=False)
            response.raise_for_status()

            logger.info(f"Notable event created for alert: {alert.id}")
            return response.json().get("event_id", "")

        except Exception as e:
            logger.error(f"Failed to create notable event: {e}")
            return ""


class ElasticConnector(SIEMConnector):
    """Elastic SIEM 연동"""

    def __init__(self, config: Dict):
        self.url = config["url"]
        self.api_key = config.get("api_key", "")
        self.index = config.get("index", "xdr-alerts")
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            "Authorization": f"ApiKey {self.api_key}",
            "Content-Type": "application/json"
        })
        return session

    def send_alert(self, alert: Alert) -> bool:
        """EDR 알림을 Elastic으로 전송"""
        try:
            url = f"{self.url}/{self.index}/_doc"
            payload = {
                "@timestamp": alert.timestamp,
                "event": {
                    "kind": "alert",
                    "category": ["intrusion_detection"],
                    "type": ["info"],
                    "severity": self._map_severity(alert.severity)
                },
                "rule": {
                    "name": alert.title,
                    "description": alert.description
                },
                "host": {"name": alert.host},
                "user": {"name": alert.user} if alert.user else None,
                "threat": {
                    "tactic": {"name": alert.mitre_tactics},
                    "technique": {"name": alert.mitre_techniques}
                },
                "xdr": {
                    "source": alert.source,
                    "alert_id": alert.id,
                    "iocs": alert.iocs
                }
            }

            response = self.session.post(url, json=payload)
            response.raise_for_status()

            logger.info(f"Alert sent to Elastic: {alert.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to send alert to Elastic: {e}")
            return False

    def _map_severity(self, severity: str) -> int:
        mapping = {"low": 25, "medium": 50, "high": 75, "critical": 100}
        return mapping.get(severity.lower(), 50)

    def get_alerts(self, time_range: int = 300) -> List[Alert]:
        """Elastic에서 알림 조회"""
        try:
            url = f"{self.url}/{self.index}/_search"
            query = {
                "query": {
                    "bool": {
                        "must": [
                            {"range": {"@timestamp": {"gte": f"now-{time_range}s"}}},
                            {"terms": {"event.severity": [75, 100]}}
                        ]
                    }
                },
                "size": CONFIG["batch_size"]
            }

            response = self.session.post(url, json=query)
            response.raise_for_status()

            alerts = []
            for hit in response.json().get("hits", {}).get("hits", []):
                source = hit["_source"]
                alert = Alert(
                    id=source.get("xdr", {}).get("alert_id", hit["_id"]),
                    source="elastic",
                    timestamp=source.get("@timestamp", ""),
                    severity=self._reverse_map_severity(source.get("event", {}).get("severity", 50)),
                    title=source.get("rule", {}).get("name", ""),
                    description=source.get("rule", {}).get("description", ""),
                    host=source.get("host", {}).get("name", ""),
                    user=source.get("user", {}).get("name"),
                    mitre_tactics=source.get("threat", {}).get("tactic", {}).get("name", []),
                    mitre_techniques=source.get("threat", {}).get("technique", {}).get("name", []),
                    iocs=source.get("xdr", {}).get("iocs", {}),
                    raw_data=source
                )
                alerts.append(alert)

            return alerts

        except Exception as e:
            logger.error(f"Failed to get alerts from Elastic: {e}")
            return []

    def _reverse_map_severity(self, score: int) -> str:
        if score >= 75:
            return "critical" if score >= 90 else "high"
        elif score >= 50:
            return "medium"
        return "low"

    def create_notable_event(self, alert: Alert) -> str:
        """Elastic Security 알림 생성"""
        # Elastic Security에서는 Detection Rule을 통해 처리
        return self.send_alert(alert)


class CrowdStrikeConnector(EDRConnector):
    """CrowdStrike EDR 연동"""

    def __init__(self, config: Dict):
        self.url = config["url"]
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.token = None
        self.token_expiry = None
        self.session = requests.Session()

    def _authenticate(self):
        """OAuth2 인증"""
        if self.token and self.token_expiry and datetime.now() < self.token_expiry:
            return

        try:
            url = f"{self.url}/oauth2/token"
            response = self.session.post(
                url,
                data={
                    "client_id": self.client_id,
                    "client_secret": self.client_secret
                }
            )
            response.raise_for_status()

            data = response.json()
            self.token = data["access_token"]
            self.token_expiry = datetime.now() + timedelta(seconds=data["expires_in"] - 60)
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})

            logger.info("CrowdStrike authentication successful")

        except Exception as e:
            logger.error(f"CrowdStrike authentication failed: {e}")
            raise

    def get_detections(self, time_range: int = 300) -> List[Alert]:
        """CrowdStrike 탐지 조회"""
        self._authenticate()

        try:
            # 탐지 ID 조회
            url = f"{self.url}/detects/queries/detects/v1"
            params = {
                "filter": f"created_timestamp:>'{(datetime.utcnow() - timedelta(seconds=time_range)).isoformat()}Z'",
                "limit": CONFIG["batch_size"]
            }

            response = self.session.get(url, params=params)
            response.raise_for_status()

            detection_ids = response.json().get("resources", [])
            if not detection_ids:
                return []

            # 탐지 상세 조회
            details_url = f"{self.url}/detects/entities/summaries/GET/v1"
            details_response = self.session.post(
                details_url,
                json={"ids": detection_ids}
            )
            details_response.raise_for_status()

            alerts = []
            for detection in details_response.json().get("resources", []):
                behaviors = detection.get("behaviors", [{}])[0]

                alert = Alert(
                    id=detection.get("detection_id", ""),
                    source="crowdstrike",
                    timestamp=detection.get("created_timestamp", ""),
                    severity=self._map_severity(detection.get("max_severity", 0)),
                    title=behaviors.get("scenario", ""),
                    description=behaviors.get("description", ""),
                    host=detection.get("device", {}).get("hostname", ""),
                    user=behaviors.get("user_name"),
                    mitre_tactics=[behaviors.get("tactic", "")],
                    mitre_techniques=[behaviors.get("technique", "")],
                    iocs={
                        "sha256": [behaviors.get("sha256", "")] if behaviors.get("sha256") else [],
                        "md5": [behaviors.get("md5", "")] if behaviors.get("md5") else [],
                        "ip": [],
                        "domain": []
                    },
                    raw_data=detection
                )
                alerts.append(alert)

            return alerts

        except Exception as e:
            logger.error(f"Failed to get CrowdStrike detections: {e}")
            return []

    def _map_severity(self, score: int) -> str:
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        return "low"

    def isolate_host(self, hostname: str) -> bool:
        """호스트 네트워크 격리"""
        self._authenticate()

        try:
            # 호스트 ID 조회
            query_url = f"{self.url}/devices/queries/devices/v1"
            response = self.session.get(
                query_url,
                params={"filter": f"hostname:'{hostname}'"}
            )
            response.raise_for_status()

            device_ids = response.json().get("resources", [])
            if not device_ids:
                logger.warning(f"Host not found: {hostname}")
                return False

            # 격리 실행
            action_url = f"{self.url}/devices/entities/devices-actions/v2"
            action_response = self.session.post(
                action_url,
                params={"action_name": "contain"},
                json={"ids": device_ids}
            )
            action_response.raise_for_status()

            logger.info(f"Host isolated: {hostname}")
            return True

        except Exception as e:
            logger.error(f"Failed to isolate host: {e}")
            return False

    def get_host_details(self, hostname: str) -> Dict:
        """호스트 상세 정보 조회"""
        self._authenticate()

        try:
            query_url = f"{self.url}/devices/queries/devices/v1"
            response = self.session.get(
                query_url,
                params={"filter": f"hostname:'{hostname}'"}
            )
            response.raise_for_status()

            device_ids = response.json().get("resources", [])
            if not device_ids:
                return {}

            details_url = f"{self.url}/devices/entities/devices/v2"
            details_response = self.session.get(
                details_url,
                params={"ids": device_ids[0]}
            )
            details_response.raise_for_status()

            return details_response.json().get("resources", [{}])[0]

        except Exception as e:
            logger.error(f"Failed to get host details: {e}")
            return {}


class SIEMEDRIntegration:
    """SIEM-EDR 통합 관리 클래스"""

    def __init__(self, config: Dict):
        self.config = config
        self.siem = self._init_siem(config["siem"])
        self.edr = self._init_edr(config["edr"])
        self.processed_alerts = set()

    def _init_siem(self, config: Dict) -> SIEMConnector:
        siem_type = config.get("type", "").lower()
        if siem_type == "splunk":
            return SplunkConnector(config)
        elif siem_type == "elastic":
            return ElasticConnector(config)
        else:
            raise ValueError(f"Unsupported SIEM type: {siem_type}")

    def _init_edr(self, config: Dict) -> EDRConnector:
        edr_type = config.get("type", "").lower()
        if edr_type == "crowdstrike":
            return CrowdStrikeConnector(config)
        else:
            raise ValueError(f"Unsupported EDR type: {edr_type}")

    def sync_edr_to_siem(self):
        """EDR 탐지를 SIEM으로 동기화"""
        logger.info("Syncing EDR detections to SIEM...")

        detections = self.edr.get_detections(self.config["sync_interval"])
        synced_count = 0

        for detection in detections:
            if detection.id in self.processed_alerts:
                continue

            if self.siem.send_alert(detection):
                self.processed_alerts.add(detection.id)
                synced_count += 1

                # 심각도 높은 알림은 Notable Event 생성
                if detection.severity in ("critical", "high"):
                    self.siem.create_notable_event(detection)

        logger.info(f"Synced {synced_count} EDR detections to SIEM")

    def sync_siem_to_edr(self):
        """SIEM 알림 기반 EDR 조치"""
        logger.info("Processing SIEM alerts for EDR actions...")

        alerts = self.siem.get_alerts(self.config["sync_interval"])
        actions_count = 0

        for alert in alerts:
            if alert.id in self.processed_alerts:
                continue

            # 호스트 격리 조건 확인
            if self._should_isolate(alert):
                if self.edr.isolate_host(alert.host):
                    logger.info(f"Host isolated based on SIEM alert: {alert.host}")
                    actions_count += 1

            self.processed_alerts.add(alert.id)

        logger.info(f"Executed {actions_count} EDR actions based on SIEM alerts")

    def _should_isolate(self, alert: Alert) -> bool:
        """격리 조건 확인"""
        # 자동 격리 조건 정의
        auto_isolate_tactics = [
            "Execution",
            "Credential Access",
            "Lateral Movement"
        ]

        if alert.severity == "critical":
            for tactic in alert.mitre_tactics:
                if tactic in auto_isolate_tactics:
                    return True

        return False

    def run(self):
        """연동 루프 실행"""
        logger.info("Starting SIEM-EDR integration...")

        while True:
            try:
                self.sync_edr_to_siem()
                self.sync_siem_to_edr()

                # 처리된 알림 캐시 정리 (최근 1000개만 유지)
                if len(self.processed_alerts) > 1000:
                    self.processed_alerts = set(list(self.processed_alerts)[-500:])

            except Exception as e:
                logger.error(f"Integration error: {e}")

            time.sleep(self.config["sync_interval"])


def main():
    """메인 함수"""
    integration = SIEMEDRIntegration(CONFIG)
    integration.run()


if __name__ == "__main__":
    main()
