# XDR 상관분석 가이드

## 1. 개요

### 1.1 상관분석이란?
여러 데이터 소스의 이벤트를 연결하여 단일 이벤트로는 탐지할 수 없는 위협을 식별하는 기법

### 1.2 XDR 상관분석의 특징
- **크로스 레이어**: EDR + NDR + SIEM 데이터 통합 분석
- **컨텍스트 기반**: 자산, 사용자, 위협 인텔리전스 연계
- **시계열 분석**: 공격 체인 전체 추적

## 2. 데이터 소스 매핑

### 2.1 데이터 소스별 필드 정규화
```yaml
# 공통 필드 스키마 (ECS 기반)
common_fields:
  timestamp: "@timestamp"
  source_ip: "source.ip"
  destination_ip: "destination.ip"
  user: "user.name"
  host: "host.name"
  process: "process.name"
  action: "event.action"
```

### 2.2 소스별 매핑
| 소스 | 원본 필드 | 정규화 필드 |
|------|-----------|-------------|
| EDR | src_ip | source.ip |
| NDR | srcaddr | source.ip |
| Firewall | source | source.ip |

## 3. 상관분석 규칙 유형

### 3.1 시퀀스 기반 (Attack Chain)
연속된 이벤트 패턴 탐지

```yaml
# Elastic EQL 예시: 초기 접근 → 실행 → 지속성
sequence by host.name with maxspan=1h
  [process where event.action == "start" and process.name == "powershell.exe"]
  [file where event.action == "creation" and file.path : "*\\Startup\\*"]
  [network where destination.port == 443]
```

### 3.2 집계 기반 (Threshold)
임계값 초과 탐지

```spl
# Splunk SPL 예시: 다수 호스트 로그인 실패
index=auth action=failure
| stats count by src_ip, user
| where count > 10
```

### 3.3 크로스 소스 기반
여러 데이터 소스 조인

```spl
# Splunk SPL 예시: EDR 프로세스 + NDR 트래픽 연계
index=edr process_name=powershell.exe
| join host [search index=ndr dest_port=4444]
| table _time host process_name dest_ip dest_port
```

## 4. MITRE ATT&CK 매핑

### 4.1 탐지 커버리지 매트릭스
| Tactic | Technique | 데이터 소스 | 규칙 ID |
|--------|-----------|-------------|---------|
| Initial Access | T1566 Phishing | Email, EDR | CR-001 |
| Execution | T1059 Command Line | EDR | CR-002 |
| Persistence | T1547 Boot/Logon | EDR | CR-003 |
| C2 | T1071 Application Layer | NDR | CR-004 |
| Exfiltration | T1048 Exfiltration Over Alt Protocol | NDR | CR-005 |

### 4.2 공격 시나리오 기반 규칙

#### 시나리오: 피싱 → 악성코드 실행 → C2 통신
```yaml
name: "Phishing Attack Chain"
mitre:
  - T1566.001  # Spearphishing Attachment
  - T1059.001  # PowerShell
  - T1071.001  # Web Protocols

correlation:
  - source: email
    condition: attachment.extension in [".exe", ".js", ".vbs"]
  - source: edr
    condition: process.parent == "outlook.exe" AND process.name == "powershell.exe"
    within: 5m
  - source: ndr
    condition: destination.port == 443 AND bytes_out > 1000000
    within: 30m
```

## 5. 규칙 개발 가이드라인

### 5.1 명명 규칙
```
[소스]-[전술]-[기법]-[설명]
예: XDR-EXEC-T1059-PowerShell_Encoded_Command
```

### 5.2 심각도 분류
| Level | 기준 | 대응 |
|-------|------|------|
| Critical | 확정 침해, 데이터 유출 | 즉시 대응 |
| High | 높은 확신의 악성 활동 | 1시간 내 조사 |
| Medium | 의심 활동, 추가 확인 필요 | 4시간 내 조사 |
| Low | 이상 징후, 모니터링 | 일일 리뷰 |

### 5.3 오탐 최소화
- 베이스라인 학습 기간 설정
- 화이트리스트 관리
- 튜닝 프로세스 정의

## 6. 상관분석 규칙 템플릿

```yaml
---
id: CR-XXX
name: "규칙 이름"
description: "규칙 설명"
author: "작성자"
created: "YYYY-MM-DD"
modified: "YYYY-MM-DD"

mitre:
  tactic: "Tactic Name"
  technique: "TXXXX"
  subtechnique: "TXXXX.XXX"

severity: high
confidence: medium

data_sources:
  - EDR
  - NDR
  - SIEM

detection:
  # 탐지 로직

false_positives:
  - "알려진 오탐 케이스"

references:
  - "https://attack.mitre.org/techniques/TXXXX"
```
