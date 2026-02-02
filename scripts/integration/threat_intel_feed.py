#!/usr/bin/env python3
"""
위협 인텔리전스 자동 피드 스크립트
XDR 플랫폼을 위한 TI 자동 수집 및 배포
"""

import json
import logging
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, asdict, field
from abc import ABC, abstractmethod
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# 설정
CONFIG = {
    "feeds": {
        "otx": {
            "enabled": True,
            "api_key": "YOUR_OTX_API_KEY",
            "url": "https://otx.alienvault.com/api/v1"
        },
        "abuse_ch": {
            "enabled": True,
            "urls": {
                "malware_bazaar": "https://bazaar.abuse.ch/export/json/recent/",
                "feodo_tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                "urlhaus": "https://urlhaus.abuse.ch/downloads/json_recent/"
            }
        },
        "misp": {
            "enabled": True,
            "url": "https://misp.example.com",
            "api_key": "YOUR_MISP_API_KEY",
            "verify_ssl": False
        }
    },
    "destinations": {
        "siem": {
            "type": "splunk",
            "url": "https://splunk.example.com:8089",
            "token": "YOUR_SPLUNK_TOKEN",
            "index": "threat_intel"
        },
        "edr": {
            "type": "crowdstrike",
            "url": "https://api.crowdstrike.com",
            "client_id": "YOUR_CLIENT_ID",
            "client_secret": "YOUR_CLIENT_SECRET"
        },
        "firewall": {
            "type": "paloalto",
            "url": "https://firewall.example.com",
            "api_key": "YOUR_PAN_API_KEY"
        }
    },
    "update_interval": 3600,  # 1시간
    "ioc_ttl_days": 30,
    "max_workers": 5
}


@dataclass
class IOC:
    """IOC 데이터 클래스"""
    type: str  # ip, domain, url, hash_md5, hash_sha256, email
    value: str
    source: str
    confidence: int  # 0-100
    severity: str  # low, medium, high, critical
    tags: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    expiration: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    raw_data: Dict = field(default_factory=dict)

    def __hash__(self):
        return hash(f"{self.type}:{self.value}")

    def __eq__(self, other):
        return self.type == other.type and self.value == other.value


class ThreatFeed(ABC):
    """위협 피드 추상 클래스"""

    @abstractmethod
    def fetch_iocs(self) -> List[IOC]:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass


class OTXFeed(ThreatFeed):
    """AlienVault OTX 피드"""

    def __init__(self, config: Dict):
        self.api_key = config["api_key"]
        self.url = config["url"]
        self.session = requests.Session()
        self.session.headers.update({"X-OTX-API-KEY": self.api_key})

    def get_name(self) -> str:
        return "AlienVault OTX"

    def fetch_iocs(self) -> List[IOC]:
        iocs = []
        try:
            # 최근 수정된 Pulse 조회
            url = f"{self.url}/pulses/subscribed"
            params = {"modified_since": (datetime.utcnow() - timedelta(hours=24)).isoformat()}

            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()

            for pulse in response.json().get("results", []):
                pulse_iocs = self._parse_pulse(pulse)
                iocs.extend(pulse_iocs)

            logger.info(f"OTX: Fetched {len(iocs)} IOCs")

        except Exception as e:
            logger.error(f"OTX fetch error: {e}")

        return iocs

    def _parse_pulse(self, pulse: Dict) -> List[IOC]:
        iocs = []
        pulse_name = pulse.get("name", "")
        tags = pulse.get("tags", [])

        # MITRE ATT&CK 매핑
        mitre_tactics = []
        mitre_techniques = []
        for attack_id in pulse.get("attack_ids", []):
            if attack_id.startswith("TA"):
                mitre_tactics.append(attack_id)
            elif attack_id.startswith("T"):
                mitre_techniques.append(attack_id)

        for indicator in pulse.get("indicators", []):
            ioc_type = self._map_indicator_type(indicator.get("type", ""))
            if not ioc_type:
                continue

            ioc = IOC(
                type=ioc_type,
                value=indicator.get("indicator", ""),
                source="otx",
                confidence=70,
                severity=self._map_severity(pulse.get("adversary", "")),
                tags=tags,
                description=f"{pulse_name}: {indicator.get('description', '')}",
                first_seen=indicator.get("created"),
                last_seen=pulse.get("modified"),
                expiration=(datetime.utcnow() + timedelta(days=CONFIG["ioc_ttl_days"])).isoformat(),
                mitre_tactics=mitre_tactics,
                mitre_techniques=mitre_techniques,
                raw_data=indicator
            )
            iocs.append(ioc)

        return iocs

    def _map_indicator_type(self, otx_type: str) -> Optional[str]:
        mapping = {
            "IPv4": "ip",
            "IPv6": "ip",
            "domain": "domain",
            "hostname": "domain",
            "URL": "url",
            "FileHash-MD5": "hash_md5",
            "FileHash-SHA256": "hash_sha256",
            "FileHash-SHA1": "hash_sha1",
            "email": "email"
        }
        return mapping.get(otx_type)

    def _map_severity(self, adversary: str) -> str:
        if adversary:
            return "high"
        return "medium"


class AbuseCHFeed(ThreatFeed):
    """Abuse.ch 피드 (MalwareBazaar, Feodo Tracker, URLhaus)"""

    def __init__(self, config: Dict):
        self.urls = config["urls"]
        self.session = requests.Session()

    def get_name(self) -> str:
        return "Abuse.ch"

    def fetch_iocs(self) -> List[IOC]:
        iocs = []

        # MalwareBazaar - 악성코드 해시
        try:
            response = self.session.get(self.urls["malware_bazaar"], timeout=30)
            if response.status_code == 200:
                for entry in response.json().get("data", [])[:1000]:
                    ioc = IOC(
                        type="hash_sha256",
                        value=entry.get("sha256_hash", ""),
                        source="malware_bazaar",
                        confidence=90,
                        severity="high",
                        tags=entry.get("tags", []),
                        description=f"Malware: {entry.get('signature', 'Unknown')}",
                        first_seen=entry.get("first_seen"),
                        last_seen=entry.get("last_seen"),
                        expiration=(datetime.utcnow() + timedelta(days=CONFIG["ioc_ttl_days"])).isoformat(),
                        raw_data=entry
                    )
                    iocs.append(ioc)
                logger.info(f"MalwareBazaar: Fetched {len(iocs)} IOCs")
        except Exception as e:
            logger.error(f"MalwareBazaar fetch error: {e}")

        # Feodo Tracker - C2 IP
        try:
            response = self.session.get(self.urls["feodo_tracker"], timeout=30)
            if response.status_code == 200:
                feodo_count = 0
                for entry in response.json():
                    ioc = IOC(
                        type="ip",
                        value=entry.get("ip_address", ""),
                        source="feodo_tracker",
                        confidence=95,
                        severity="critical",
                        tags=["c2", "botnet", entry.get("malware", "")],
                        description=f"Feodo C2: {entry.get('malware', '')}",
                        first_seen=entry.get("first_seen"),
                        last_seen=entry.get("last_seen"),
                        expiration=(datetime.utcnow() + timedelta(days=CONFIG["ioc_ttl_days"])).isoformat(),
                        raw_data=entry
                    )
                    iocs.append(ioc)
                    feodo_count += 1
                logger.info(f"Feodo Tracker: Fetched {feodo_count} IOCs")
        except Exception as e:
            logger.error(f"Feodo Tracker fetch error: {e}")

        # URLhaus - 악성 URL
        try:
            response = self.session.get(self.urls["urlhaus"], timeout=30)
            if response.status_code == 200:
                urlhaus_count = 0
                for entry in response.json().get("urls", [])[:1000]:
                    ioc = IOC(
                        type="url",
                        value=entry.get("url", ""),
                        source="urlhaus",
                        confidence=85,
                        severity="high",
                        tags=entry.get("tags", []),
                        description=f"Malicious URL: {entry.get('threat', '')}",
                        first_seen=entry.get("date_added"),
                        expiration=(datetime.utcnow() + timedelta(days=CONFIG["ioc_ttl_days"])).isoformat(),
                        raw_data=entry
                    )
                    iocs.append(ioc)
                    urlhaus_count += 1
                logger.info(f"URLhaus: Fetched {urlhaus_count} IOCs")
        except Exception as e:
            logger.error(f"URLhaus fetch error: {e}")

        return iocs


class MISPFeed(ThreatFeed):
    """MISP 피드"""

    def __init__(self, config: Dict):
        self.url = config["url"]
        self.api_key = config["api_key"]
        self.verify_ssl = config.get("verify_ssl", True)
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

    def get_name(self) -> str:
        return "MISP"

    def fetch_iocs(self) -> List[IOC]:
        iocs = []
        try:
            url = f"{self.url}/attributes/restSearch"
            payload = {
                "timestamp": "1d",  # 최근 1일
                "published": True,
                "enforceWarninglist": True,
                "limit": 10000
            }

            response = self.session.post(
                url,
                json=payload,
                verify=self.verify_ssl,
                timeout=60
            )
            response.raise_for_status()

            attributes = response.json().get("response", {}).get("Attribute", [])

            for attr in attributes:
                ioc_type = self._map_misp_type(attr.get("type", ""))
                if not ioc_type:
                    continue

                # 태그 추출
                tags = [t.get("name", "") for t in attr.get("Tag", [])]

                ioc = IOC(
                    type=ioc_type,
                    value=attr.get("value", ""),
                    source="misp",
                    confidence=80,
                    severity=self._get_severity_from_tags(tags),
                    tags=tags,
                    description=attr.get("comment", ""),
                    first_seen=attr.get("first_seen"),
                    last_seen=attr.get("last_seen"),
                    expiration=(datetime.utcnow() + timedelta(days=CONFIG["ioc_ttl_days"])).isoformat(),
                    raw_data=attr
                )
                iocs.append(ioc)

            logger.info(f"MISP: Fetched {len(iocs)} IOCs")

        except Exception as e:
            logger.error(f"MISP fetch error: {e}")

        return iocs

    def _map_misp_type(self, misp_type: str) -> Optional[str]:
        mapping = {
            "ip-src": "ip",
            "ip-dst": "ip",
            "domain": "domain",
            "hostname": "domain",
            "url": "url",
            "md5": "hash_md5",
            "sha256": "hash_sha256",
            "sha1": "hash_sha1",
            "email-src": "email",
            "email-dst": "email"
        }
        return mapping.get(misp_type)

    def _get_severity_from_tags(self, tags: List[str]) -> str:
        for tag in tags:
            tag_lower = tag.lower()
            if "critical" in tag_lower:
                return "critical"
            elif "high" in tag_lower:
                return "high"
            elif "medium" in tag_lower:
                return "medium"
        return "medium"


class IOCDestination(ABC):
    """IOC 대상 추상 클래스"""

    @abstractmethod
    def push_iocs(self, iocs: List[IOC]) -> int:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass


class SplunkDestination(IOCDestination):
    """Splunk IOC 대상"""

    def __init__(self, config: Dict):
        self.url = config["url"]
        self.token = config["token"]
        self.index = config["index"]
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json"
        })

    def get_name(self) -> str:
        return "Splunk"

    def push_iocs(self, iocs: List[IOC]) -> int:
        success_count = 0
        batch_size = 100

        for i in range(0, len(iocs), batch_size):
            batch = iocs[i:i + batch_size]
            events = []

            for ioc in batch:
                event = {
                    "index": self.index,
                    "sourcetype": f"threat_intel:{ioc.source}",
                    "event": asdict(ioc)
                }
                events.append(json.dumps(event))

            try:
                url = f"{self.url}/services/collector/event"
                response = self.session.post(
                    url,
                    data="\n".join(events),
                    verify=False,
                    timeout=30
                )
                response.raise_for_status()
                success_count += len(batch)

            except Exception as e:
                logger.error(f"Splunk push error: {e}")

        logger.info(f"Splunk: Pushed {success_count} IOCs")
        return success_count


class CrowdStrikeDestination(IOCDestination):
    """CrowdStrike IOC 대상"""

    def __init__(self, config: Dict):
        self.url = config["url"]
        self.client_id = config["client_id"]
        self.client_secret = config["client_secret"]
        self.token = None
        self.session = requests.Session()

    def get_name(self) -> str:
        return "CrowdStrike"

    def _authenticate(self):
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
            self.token = response.json()["access_token"]
            self.session.headers.update({"Authorization": f"Bearer {self.token}"})
        except Exception as e:
            logger.error(f"CrowdStrike auth error: {e}")
            raise

    def push_iocs(self, iocs: List[IOC]) -> int:
        self._authenticate()
        success_count = 0

        # IOC 타입별 분류
        indicators = []
        for ioc in iocs:
            cs_type = self._map_ioc_type(ioc.type)
            if not cs_type:
                continue

            indicator = {
                "type": cs_type,
                "value": ioc.value,
                "source": f"XDR_TI:{ioc.source}",
                "description": ioc.description,
                "severity": ioc.severity.upper(),
                "tags": ioc.tags,
                "expiration": ioc.expiration,
                "action": "detect"  # detect 또는 prevent
            }
            indicators.append(indicator)

        # 배치 전송
        batch_size = 200
        for i in range(0, len(indicators), batch_size):
            batch = indicators[i:i + batch_size]

            try:
                url = f"{self.url}/iocs/entities/indicators/v1"
                response = self.session.post(
                    url,
                    json={"indicators": batch},
                    timeout=60
                )
                response.raise_for_status()
                success_count += len(batch)

            except Exception as e:
                logger.error(f"CrowdStrike push error: {e}")

        logger.info(f"CrowdStrike: Pushed {success_count} IOCs")
        return success_count

    def _map_ioc_type(self, ioc_type: str) -> Optional[str]:
        mapping = {
            "ip": "ipv4",
            "domain": "domain",
            "hash_md5": "md5",
            "hash_sha256": "sha256"
        }
        return mapping.get(ioc_type)


class PaloAltoDestination(IOCDestination):
    """Palo Alto Firewall IOC 대상 (External Dynamic List)"""

    def __init__(self, config: Dict):
        self.url = config["url"]
        self.api_key = config["api_key"]
        self.session = requests.Session()

    def get_name(self) -> str:
        return "Palo Alto"

    def push_iocs(self, iocs: List[IOC]) -> int:
        # IP와 Domain을 별도 리스트로 분리
        ip_list = []
        domain_list = []

        for ioc in iocs:
            if ioc.type == "ip" and ioc.severity in ("high", "critical"):
                ip_list.append(ioc.value)
            elif ioc.type == "domain" and ioc.severity in ("high", "critical"):
                domain_list.append(ioc.value)

        success_count = 0

        # IP 블록리스트 업데이트
        if ip_list:
            if self._update_edl("xdr-threat-ips", ip_list):
                success_count += len(ip_list)

        # 도메인 블록리스트 업데이트
        if domain_list:
            if self._update_edl("xdr-threat-domains", domain_list):
                success_count += len(domain_list)

        logger.info(f"Palo Alto: Pushed {success_count} IOCs to EDL")
        return success_count

    def _update_edl(self, edl_name: str, values: List[str]) -> bool:
        """External Dynamic List 업데이트"""
        try:
            # EDL 파일 생성 (실제 환경에서는 웹서버에 호스팅)
            edl_content = "\n".join(values)

            # 여기서는 로컬 파일로 저장 (실제로는 웹서버에 업로드)
            with open(f"/var/www/html/edl/{edl_name}.txt", "w") as f:
                f.write(edl_content)

            # PAN-OS에 EDL 새로고침 요청
            url = f"{self.url}/api/"
            params = {
                "type": "op",
                "cmd": f"<request><system><external-list><refresh><type><ip><name>{edl_name}</name></ip></type></refresh></external-list></system></request>",
                "key": self.api_key
            }

            response = self.session.get(url, params=params, verify=False, timeout=30)
            return response.status_code == 200

        except Exception as e:
            logger.error(f"Palo Alto EDL update error: {e}")
            return False


class ThreatIntelManager:
    """위협 인텔리전스 관리 클래스"""

    def __init__(self, config: Dict):
        self.config = config
        self.feeds: List[ThreatFeed] = []
        self.destinations: List[IOCDestination] = []
        self.ioc_cache: Set[IOC] = set()

        self._init_feeds()
        self._init_destinations()

    def _init_feeds(self):
        feeds_config = self.config["feeds"]

        if feeds_config.get("otx", {}).get("enabled"):
            self.feeds.append(OTXFeed(feeds_config["otx"]))

        if feeds_config.get("abuse_ch", {}).get("enabled"):
            self.feeds.append(AbuseCHFeed(feeds_config["abuse_ch"]))

        if feeds_config.get("misp", {}).get("enabled"):
            self.feeds.append(MISPFeed(feeds_config["misp"]))

        logger.info(f"Initialized {len(self.feeds)} threat feeds")

    def _init_destinations(self):
        dest_config = self.config["destinations"]

        if dest_config.get("siem", {}).get("type") == "splunk":
            self.destinations.append(SplunkDestination(dest_config["siem"]))

        if dest_config.get("edr", {}).get("type") == "crowdstrike":
            self.destinations.append(CrowdStrikeDestination(dest_config["edr"]))

        if dest_config.get("firewall", {}).get("type") == "paloalto":
            self.destinations.append(PaloAltoDestination(dest_config["firewall"]))

        logger.info(f"Initialized {len(self.destinations)} IOC destinations")

    def fetch_all_feeds(self) -> List[IOC]:
        """모든 피드에서 IOC 수집"""
        all_iocs = []

        with ThreadPoolExecutor(max_workers=self.config["max_workers"]) as executor:
            futures = {executor.submit(feed.fetch_iocs): feed for feed in self.feeds}

            for future in as_completed(futures):
                feed = futures[future]
                try:
                    iocs = future.result()
                    all_iocs.extend(iocs)
                    logger.info(f"{feed.get_name()}: {len(iocs)} IOCs collected")
                except Exception as e:
                    logger.error(f"{feed.get_name()} error: {e}")

        # 중복 제거
        unique_iocs = list(set(all_iocs))
        logger.info(f"Total unique IOCs: {len(unique_iocs)}")

        return unique_iocs

    def distribute_iocs(self, iocs: List[IOC]):
        """모든 대상에 IOC 배포"""
        # 새로운 IOC만 필터링
        new_iocs = [ioc for ioc in iocs if ioc not in self.ioc_cache]

        if not new_iocs:
            logger.info("No new IOCs to distribute")
            return

        logger.info(f"Distributing {len(new_iocs)} new IOCs")

        for destination in self.destinations:
            try:
                count = destination.push_iocs(new_iocs)
                logger.info(f"{destination.get_name()}: {count} IOCs pushed")
            except Exception as e:
                logger.error(f"{destination.get_name()} distribution error: {e}")

        # 캐시 업데이트
        self.ioc_cache.update(new_iocs)

        # 캐시 크기 제한 (최근 100,000개만 유지)
        if len(self.ioc_cache) > 100000:
            self.ioc_cache = set(list(self.ioc_cache)[-50000:])

    def run(self):
        """피드 수집 및 배포 루프"""
        logger.info("Starting Threat Intelligence Manager...")

        while True:
            try:
                # IOC 수집
                iocs = self.fetch_all_feeds()

                # IOC 배포
                self.distribute_iocs(iocs)

                # 통계 출력
                self._print_stats(iocs)

            except Exception as e:
                logger.error(f"TI Manager error: {e}")

            logger.info(f"Sleeping for {self.config['update_interval']} seconds...")
            time.sleep(self.config["update_interval"])

    def _print_stats(self, iocs: List[IOC]):
        """통계 출력"""
        stats = {
            "total": len(iocs),
            "by_type": {},
            "by_severity": {},
            "by_source": {}
        }

        for ioc in iocs:
            stats["by_type"][ioc.type] = stats["by_type"].get(ioc.type, 0) + 1
            stats["by_severity"][ioc.severity] = stats["by_severity"].get(ioc.severity, 0) + 1
            stats["by_source"][ioc.source] = stats["by_source"].get(ioc.source, 0) + 1

        logger.info(f"IOC Stats: {json.dumps(stats, indent=2)}")


def main():
    """메인 함수"""
    manager = ThreatIntelManager(CONFIG)
    manager.run()


if __name__ == "__main__":
    main()
