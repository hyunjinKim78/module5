# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 저장소 개요

이 저장소는 XDR(Extended Detection and Response) 구축 계획을 위한 **보안 문서 저장소**입니다. 소스 코드가 아닌 한국어 기술 문서를 포함합니다.

## skills
  **Git commit**: 사용자가 git commit을 요청했을때 ./skills/git.commit/SKILL.md를 참고하여 git commit을 진행해줘

## 구성

```
module_5/
├── CLAUDE.md                    # 프로젝트 가이드
├── docs/                        # 문서
│   ├── proposal/               # 제안서
│   │   └── xdr-proposal.md     # XDR 구축 제안서
│   ├── correlation/            # 상관분석
│   │   └── correlation-guide.md # 상관분석 가이드
│   └── architecture/           # 아키텍처
│       └── xdr-architecture.md # XDR 아키텍처 설계
├── rules/                       # 탐지 규칙
│   ├── sigma/                  # Sigma 규칙 (범용)
│   ├── splunk/                 # Splunk SPL 규칙
│   └── elastic/                # Elastic EQL 규칙
├── playbooks/                   # SOAR 플레이북
│   ├── incident-response/      # 침해 대응
│   └── threat-hunting/         # 위협 헌팅
├── configs/                     # 설정 템플릿
│   ├── siem/                   # SIEM 설정
│   ├── edr/                    # EDR 설정
│   └── ndr/                    # NDR 설정
├── scripts/                     # 자동화 스크립트
│   ├── automation/             # 자동화 도구
│   └── integration/            # 연동 스크립트
└── threat-intel/                # 위협 인텔리전스
    ├── ioc/                    # IOC 관리
    └── mitre-mapping/          # ATT&CK 매핑
```

## 배경

현재 운영 중인 보안 시스템:
- **SIEM** - 로그 수집 및 상관분석
- **SOAR** - 자동화된 대응 및 오케스트레이션

목표: EDR, NDR, 크로스 레이어 상관분석 기능을 추가하여 XDR로 확장

## 추천 기술스택

### Option A: ClickHouse 기반 (오픈소스 중심)

| 계층 | 솔루션 | 역할 |
|------|--------|------|
| SIEM | ClickHouse + Grafana | 로그 저장, 분석, 시각화 |
| SOAR | Shuffle / n8n | 자동화 워크플로우, 대응 오케스트레이션 |
| EDR | Wazuh / Velociraptor | 엔드포인트 탐지 및 대응 |
| NDR | Zeek + Suricata | 네트워크 트래픽 분석, IDS |
| 로그 파이프라인 | Vector / Fluent Bit | 로그 수집 및 전처리 |
| 위협 인텔리전스 | MISP + OpenCTI | IOC 관리, 위협 정보 공유 |
| 데이터 저장소 | ClickHouse (컬럼 기반 OLAP) | 고속 로그 저장 및 분석 |
| 메시지 큐 | Kafka / Redpanda | 데이터 버퍼링 및 스트리밍 |

### Option B: Splunk 기반 (상용 중심)

| 계층 | 솔루션 | 역할 |
|------|--------|------|
| SIEM | Splunk Enterprise Security | 로그 수집, 상관분석, 탐지 |
| SOAR | Splunk SOAR (Phantom) | 자동화 플레이북, 대응 오케스트레이션 |
| EDR | CrowdStrike Falcon / MS Defender | 엔드포인트 탐지 및 대응 |
| NDR | Vectra AI / Darktrace | 네트워크 이상 탐지, AI 기반 분석 |
| 로그 파이프라인 | Splunk Universal Forwarder | 로그 수집 및 전송 |
| 위협 인텔리전스 | Splunk TI Framework + ThreatConnect | IOC 관리, 위협 피드 연동 |
| 데이터 저장소 | Splunk Indexer | 로그 저장 및 검색 |

### 공통 권장 구성요소

- **자동화 스크립트**: Python 3.x (pandas, requests, pymisp)
- **인프라 자동화**: Ansible, Terraform
- **컨테이너 오케스트레이션**: Docker, Kubernetes (선택)
- **MITRE ATT&CK 매핑**: ATT&CK Navigator, Sigma Rules
- **케이스 관리**: TheHive, DFIR-IRIS

## 문서 작성 표준

- 언어: 한국어
- 형식: Markdown + ASCII 다이어그램
- 상관분석 규칙은 YAML 예시 포함 (Splunk SPL, Elastic EQL)
- 위협 매핑은 MITRE ATT&CK 프레임워크 참조
