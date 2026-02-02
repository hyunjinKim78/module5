# XDR 위협 헌팅 쿼리 모음

## 1. 초기 접근 (Initial Access)

### 1.1 피싱 이메일 헌팅
```spl
# Splunk: 의심스러운 첨부파일 수신
index=email
| where match(attachment_name, "\.(exe|js|vbs|ps1|bat|cmd|scr|hta)$")
| stats count by sender, recipient, attachment_name, subject
| sort -count
```

```eql
# Elastic: 매크로 포함 Office 문서 실행
sequence by host.name with maxspan=5m
  [file where file.extension in ("doc", "docm", "xls", "xlsm")
   and file.path : "*Downloads*"]
  [process where process.name in ("WINWORD.EXE", "EXCEL.EXE")]
  [process where process.parent.name in ("WINWORD.EXE", "EXCEL.EXE")
   and process.name in ("cmd.exe", "powershell.exe")]
```

## 2. 실행 (Execution)

### 2.1 의심스러운 PowerShell 활동
```spl
# Splunk: 인코딩된 PowerShell 명령
index=edr process_name="powershell.exe"
| where match(command_line, "(?i)(-enc|-encodedcommand|-e\s)")
| table _time, host, user, command_line
```

```spl
# Splunk: PowerShell 다운로드 크래들
index=edr process_name="powershell.exe"
| where match(command_line, "(?i)(downloadstring|downloadfile|invoke-webrequest|wget|curl|bitstransfer)")
| stats count by host, user, command_line
```

### 2.2 LOLBAS (Living Off the Land)
```spl
# Splunk: 의심스러운 certutil 사용
index=edr process_name="certutil.exe"
| where match(command_line, "(?i)(-urlcache|-decode|-encode)")
| table _time, host, user, command_line, parent_process
```

```spl
# Splunk: mshta 원격 실행
index=edr process_name="mshta.exe"
| where match(command_line, "(?i)(http|javascript|vbscript)")
| table _time, host, user, command_line
```

## 3. 지속성 (Persistence)

### 3.1 레지스트리 기반 지속성
```spl
# Splunk: Run 키 수정
index=edr event_type="registry_modification"
| where match(registry_path, "(?i)(Run|RunOnce)")
| stats count by host, registry_path, registry_value
```

### 3.2 스케줄 작업
```spl
# Splunk: schtasks를 통한 작업 생성
index=edr process_name="schtasks.exe"
| where match(command_line, "(?i)/create")
| table _time, host, user, command_line
```

## 4. 권한 상승 (Privilege Escalation)

### 4.1 UAC 우회
```spl
# Splunk: eventvwr UAC 우회
index=edr process_name="eventvwr.exe"
| transaction host maxspan=1m
| where eventcount > 1
| table _time, host, command_line
```

## 5. 방어 회피 (Defense Evasion)

### 5.1 보안 도구 비활성화
```spl
# Splunk: Windows Defender 비활성화 시도
index=edr
| where match(command_line, "(?i)(Set-MpPreference|DisableRealtimeMonitoring|DisableBehaviorMonitoring)")
| table _time, host, user, process_name, command_line
```

### 5.2 로그 삭제
```spl
# Splunk: 이벤트 로그 삭제
index=wineventlog EventCode=1102
| stats count by host, user
```

## 6. 자격 증명 접근 (Credential Access)

### 6.1 LSASS 접근
```spl
# Splunk: LSASS 메모리 접근
index=edr event_type="process_access" target_process="lsass.exe"
| where NOT match(source_process, "(?i)(wmiprvse|taskmgr|procexp)")
| table _time, host, source_process, granted_access
```

### 6.2 SAM/SYSTEM 파일 접근
```spl
# Splunk: 레지스트리 하이브 저장
index=edr process_name="reg.exe"
| where match(command_line, "(?i)save.*(sam|system|security)")
| table _time, host, user, command_line
```

## 7. 내부 이동 (Lateral Movement)

### 7.1 원격 서비스
```spl
# Splunk: PsExec 사용
index=edr
| where process_name="psexec.exe" OR process_name="psexec64.exe"
| stats count by host, user, command_line
```

### 7.2 WMI 원격 실행
```spl
# Splunk: WMIC 원격 프로세스 생성
index=edr process_name="wmic.exe"
| where match(command_line, "(?i)/node:")
| table _time, host, user, command_line
```

## 8. 수집 (Collection)

### 8.1 아카이브 생성
```spl
# Splunk: 대용량 압축 파일 생성
index=edr event_type="file_creation"
| where match(file_name, "\.(zip|rar|7z)$") AND file_size > 104857600
| table _time, host, user, file_path, file_size
```

## 9. C2 통신 (Command and Control)

### 9.1 비콘 탐지
```spl
# Splunk: 주기적 외부 통신
index=ndr direction="outbound" dest_port=443
| bin _time span=1h
| stats count dc(dest_ip) as unique_dests by src_ip, _time
| where count > 100 AND unique_dests < 5
```

### 9.2 DNS 터널링
```spl
# Splunk: 긴 DNS 쿼리
index=dns
| eval query_len=len(query)
| where query_len > 50
| stats count by src_ip, query
| sort -count
```

## 10. 유출 (Exfiltration)

### 10.1 대용량 데이터 전송
```spl
# Splunk: 업무 시간 외 대용량 전송
index=ndr direction="outbound"
| where date_hour < 6 OR date_hour > 22
| stats sum(bytes_out) as total_bytes by src_ip
| where total_bytes > 1073741824
```

## 크로스 레이어 헌팅 쿼리

### 피싱 → 실행 → C2 체인
```spl
# 이메일 수신 후 의심스러운 프로세스 실행 및 외부 통신
index=email
| join type=inner recipient
    [search index=edr event_type="process_creation"
     | where match(process_name, "(?i)(powershell|cmd|wscript)")]
| join type=inner host
    [search index=ndr direction="outbound" dest_port IN (443, 80, 4444)]
| table _time, recipient, subject, host, process_name, dest_ip, dest_port
```
