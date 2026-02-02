##! XDR Platform Zeek Configuration
##! 로컬 사이트 설정 파일

# 기본 스크립트 로드
@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/intel
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp

# 정책 스크립트 로드
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/dns/detect-external-names
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-webapps
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssh/detect-bruteforcing
@load policy/protocols/ssh/geo-data
@load policy/misc/detect-traceroute
@load policy/misc/loaded-scripts

# 파일 분석
@load frameworks/files/hash-all-files
@load frameworks/files/extract-all-files

# JA3/JA3S TLS 핑거프린팅
@load ja3

##! 사이트 설정
redef Site::local_nets += {
    10.0.0.0/8,
    172.16.0.0/12,
    192.168.0.0/16
};

##! 로깅 설정 - JSON 형식
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

##! 로그 경로 설정
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_dir = "/var/log/zeek/current";

##! Connection 로그 설정
redef Conn::default_capture_filters = {
    ["all"] = "ip"
};

##! DNS 설정
redef DNS::max_queries = 25;

##! HTTP 설정
redef HTTP::default_capture_password = F;

##! SSL/TLS 설정
redef SSL::disable_analyzer_after_detection = F;

##! Notice 설정 - 알림 임계값
redef Notice::mail_dest = "soc@company.com";

##! 파일 추출 설정
redef FileExtract::prefix = "/var/log/zeek/extract_files/";

# 악성 파일 확장자 추출
event file_sniff(f: fa_file, meta: fa_metadata) {
    if (meta?$mime_type) {
        local dominated_mimes = set(
            "application/x-dosexec",
            "application/x-executable",
            "application/java-archive",
            "application/x-rar",
            "application/zip",
            "application/x-msdos-program",
            "application/vnd.ms-office",
            "application/msword",
            "application/pdf"
        );

        if (meta$mime_type in dominated_mimes) {
            Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
        }
    }
}

##! 커스텀 Notice 정의
module XDR;

export {
    redef enum Notice::Type += {
        ## C2 비콘 패턴 탐지
        C2_Beacon_Detected,
        ## DNS 터널링 의심
        DNS_Tunneling_Suspected,
        ## 대용량 데이터 유출 의심
        Data_Exfiltration_Suspected,
        ## 내부 스캔 활동
        Internal_Scan_Detected,
        ## 비정상적인 SSL 인증서
        Suspicious_SSL_Certificate
    };
}

# C2 비콘 탐지 (주기적 통신)
global conn_history: table[addr] of vector of time &create_expire=1hr;

event connection_state_remove(c: connection) {
    if (c$id$resp_h !in Site::local_nets) {
        local src = c$id$orig_h;
        local dst = c$id$resp_h;

        if (src !in conn_history) {
            conn_history[src] = vector();
        }

        conn_history[src] += network_time();

        # 5분 내 10회 이상 동일 간격 연결 시 알림
        if (|conn_history[src]| >= 10) {
            NOTICE([
                $note=C2_Beacon_Detected,
                $msg=fmt("Potential C2 beacon detected from %s", src),
                $src=src,
                $dst=dst,
                $identifier=cat(src, dst)
            ]);
        }
    }
}

# DNS 터널링 탐지 (긴 쿼리)
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    if (|query| > 50) {
        NOTICE([
            $note=DNS_Tunneling_Suspected,
            $msg=fmt("Unusually long DNS query: %s", query),
            $src=c$id$orig_h,
            $identifier=query
        ]);
    }
}
