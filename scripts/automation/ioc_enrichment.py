#!/usr/bin/env python3
"""
IOC Enrichment Script
XDR 플랫폼을 위한 IOC 자동 enrichment 스크립트
"""

import json
import hashlib
import requests
from datetime import datetime
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict

# 설정 (실제 환경에서는 환경변수 또는 설정 파일 사용)
CONFIG = {
    "virustotal_api_key": "YOUR_VT_API_KEY",
    "misp_url": "https://misp.example.com",
    "misp_api_key": "YOUR_MISP_API_KEY",
    "abuseipdb_api_key": "YOUR_ABUSEIPDB_KEY",
    "output_path": "./enriched_iocs.json"
}


@dataclass
class IOCResult:
    """IOC 조회 결과 데이터 클래스"""
    ioc_type: str
    ioc_value: str
    is_malicious: bool
    confidence: int
    sources: List[str]
    tags: List[str]
    first_seen: Optional[str]
    last_seen: Optional[str]
    details: Dict


class IOCEnricher:
    """IOC Enrichment 클래스"""

    def __init__(self, config: Dict):
        self.config = config
        self.session = requests.Session()

    def enrich_hash(self, file_hash: str) -> IOCResult:
        """파일 해시 enrichment"""
        results = {
            "virustotal": self._check_virustotal_hash(file_hash),
            "misp": self._check_misp(file_hash, "md5")
        }

        # 결과 집계
        is_malicious = any(r.get("malicious", False) for r in results.values() if r)
        confidence = self._calculate_confidence(results)

        return IOCResult(
            ioc_type="hash",
            ioc_value=file_hash,
            is_malicious=is_malicious,
            confidence=confidence,
            sources=[k for k, v in results.items() if v],
            tags=self._extract_tags(results),
            first_seen=self._get_first_seen(results),
            last_seen=self._get_last_seen(results),
            details=results
        )

    def enrich_ip(self, ip_address: str) -> IOCResult:
        """IP 주소 enrichment"""
        results = {
            "virustotal": self._check_virustotal_ip(ip_address),
            "abuseipdb": self._check_abuseipdb(ip_address),
            "misp": self._check_misp(ip_address, "ip-dst")
        }

        is_malicious = any(r.get("malicious", False) for r in results.values() if r)
        confidence = self._calculate_confidence(results)

        return IOCResult(
            ioc_type="ip",
            ioc_value=ip_address,
            is_malicious=is_malicious,
            confidence=confidence,
            sources=[k for k, v in results.items() if v],
            tags=self._extract_tags(results),
            first_seen=self._get_first_seen(results),
            last_seen=self._get_last_seen(results),
            details=results
        )

    def enrich_domain(self, domain: str) -> IOCResult:
        """도메인 enrichment"""
        results = {
            "virustotal": self._check_virustotal_domain(domain),
            "misp": self._check_misp(domain, "domain")
        }

        is_malicious = any(r.get("malicious", False) for r in results.values() if r)
        confidence = self._calculate_confidence(results)

        return IOCResult(
            ioc_type="domain",
            ioc_value=domain,
            is_malicious=is_malicious,
            confidence=confidence,
            sources=[k for k, v in results.items() if v],
            tags=self._extract_tags(results),
            first_seen=self._get_first_seen(results),
            last_seen=self._get_last_seen(results),
            details=results
        )

    def _check_virustotal_hash(self, file_hash: str) -> Optional[Dict]:
        """VirusTotal 해시 조회"""
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.config["virustotal_api_key"]}

            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

                return {
                    "malicious": stats.get("malicious", 0) > 0,
                    "positives": stats.get("malicious", 0),
                    "total": sum(stats.values()),
                    "tags": data.get("data", {}).get("attributes", {}).get("tags", [])
                }
            return None
        except Exception as e:
            print(f"VirusTotal 조회 오류: {e}")
            return None

    def _check_virustotal_ip(self, ip_address: str) -> Optional[Dict]:
        """VirusTotal IP 조회"""
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
            headers = {"x-apikey": self.config["virustotal_api_key"]}

            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

                return {
                    "malicious": stats.get("malicious", 0) > 0,
                    "positives": stats.get("malicious", 0),
                    "country": data.get("data", {}).get("attributes", {}).get("country", ""),
                    "as_owner": data.get("data", {}).get("attributes", {}).get("as_owner", "")
                }
            return None
        except Exception as e:
            print(f"VirusTotal IP 조회 오류: {e}")
            return None

    def _check_virustotal_domain(self, domain: str) -> Optional[Dict]:
        """VirusTotal 도메인 조회"""
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": self.config["virustotal_api_key"]}

            response = self.session.get(url, headers=headers, timeout=30)

            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

                return {
                    "malicious": stats.get("malicious", 0) > 0,
                    "positives": stats.get("malicious", 0),
                    "categories": data.get("data", {}).get("attributes", {}).get("categories", {})
                }
            return None
        except Exception as e:
            print(f"VirusTotal 도메인 조회 오류: {e}")
            return None

    def _check_abuseipdb(self, ip_address: str) -> Optional[Dict]:
        """AbuseIPDB 조회"""
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                "Key": self.config["abuseipdb_api_key"],
                "Accept": "application/json"
            }
            params = {"ipAddress": ip_address, "maxAgeInDays": 90}

            response = self.session.get(url, headers=headers, params=params, timeout=30)

            if response.status_code == 200:
                data = response.json().get("data", {})

                return {
                    "malicious": data.get("abuseConfidenceScore", 0) > 50,
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", ""),
                    "isp": data.get("isp", "")
                }
            return None
        except Exception as e:
            print(f"AbuseIPDB 조회 오류: {e}")
            return None

    def _check_misp(self, ioc_value: str, ioc_type: str) -> Optional[Dict]:
        """MISP 조회"""
        try:
            url = f"{self.config['misp_url']}/attributes/restSearch"
            headers = {
                "Authorization": self.config["misp_api_key"],
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
            payload = {
                "value": ioc_value,
                "type": ioc_type
            }

            response = self.session.post(url, headers=headers, json=payload, timeout=30, verify=False)

            if response.status_code == 200:
                data = response.json()
                attributes = data.get("response", {}).get("Attribute", [])

                if attributes:
                    return {
                        "malicious": True,
                        "event_count": len(attributes),
                        "tags": [t.get("name") for attr in attributes for t in attr.get("Tag", [])]
                    }
            return None
        except Exception as e:
            print(f"MISP 조회 오류: {e}")
            return None

    def _calculate_confidence(self, results: Dict) -> int:
        """신뢰도 계산"""
        malicious_count = sum(1 for r in results.values() if r and r.get("malicious"))
        total_sources = sum(1 for r in results.values() if r)

        if total_sources == 0:
            return 0

        return int((malicious_count / total_sources) * 100)

    def _extract_tags(self, results: Dict) -> List[str]:
        """태그 추출"""
        tags = set()
        for result in results.values():
            if result and "tags" in result:
                tags.update(result["tags"])
        return list(tags)

    def _get_first_seen(self, results: Dict) -> Optional[str]:
        """최초 발견 시간"""
        # 실제 구현에서는 각 소스의 first_seen 필드 확인
        return None

    def _get_last_seen(self, results: Dict) -> Optional[str]:
        """마지막 발견 시간"""
        return datetime.utcnow().isoformat()


def main():
    """메인 함수"""
    enricher = IOCEnricher(CONFIG)

    # 테스트 IOC
    test_iocs = [
        {"type": "hash", "value": "44d88612fea8a8f36de82e1278abb02f"},  # EICAR test
        {"type": "ip", "value": "8.8.8.8"},
        {"type": "domain", "value": "example.com"}
    ]

    results = []
    for ioc in test_iocs:
        print(f"[*] Enriching {ioc['type']}: {ioc['value']}")

        if ioc["type"] == "hash":
            result = enricher.enrich_hash(ioc["value"])
        elif ioc["type"] == "ip":
            result = enricher.enrich_ip(ioc["value"])
        elif ioc["type"] == "domain":
            result = enricher.enrich_domain(ioc["value"])
        else:
            continue

        results.append(asdict(result))
        print(f"    - Malicious: {result.is_malicious}")
        print(f"    - Confidence: {result.confidence}%")

    # 결과 저장
    with open(CONFIG["output_path"], "w") as f:
        json.dump(results, f, indent=2)

    print(f"\n[+] Results saved to {CONFIG['output_path']}")


if __name__ == "__main__":
    main()
