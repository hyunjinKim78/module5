#!/usr/bin/env python3
"""
알림 통합 서비스
XDR 플랫폼을 위한 다채널 알림 통합 (Slack, Email, Teams)
"""

import json
import logging
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from abc import ABC, abstractmethod
from enum import Enum
import requests
from jinja2 import Template

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# 설정
CONFIG = {
    "slack": {
        "enabled": True,
        "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
        "bot_token": "xoxb-your-bot-token",
        "default_channel": "#security-alerts"
    },
    "email": {
        "enabled": True,
        "smtp_server": "smtp.example.com",
        "smtp_port": 587,
        "use_tls": True,
        "username": "security-alerts@example.com",
        "password": "YOUR_EMAIL_PASSWORD",
        "from_address": "security-alerts@example.com",
        "from_name": "XDR Security Alerts"
    },
    "teams": {
        "enabled": True,
        "webhook_url": "https://outlook.office.com/webhook/YOUR/WEBHOOK/URL"
    },
    "pagerduty": {
        "enabled": True,
        "api_key": "YOUR_PAGERDUTY_API_KEY",
        "service_id": "YOUR_SERVICE_ID",
        "escalation_policy_id": "YOUR_ESCALATION_POLICY_ID"
    }
}


class Severity(Enum):
    """알림 심각도"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Alert:
    """알림 데이터 클래스"""
    id: str
    title: str
    description: str
    severity: Severity
    source: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    host: Optional[str] = None
    user: Optional[str] = None
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    iocs: Dict[str, Any] = field(default_factory=dict)
    actions_taken: List[str] = field(default_factory=list)
    case_id: Optional[str] = None
    case_url: Optional[str] = None
    additional_data: Dict[str, Any] = field(default_factory=dict)


class NotificationChannel(ABC):
    """알림 채널 추상 클래스"""

    @abstractmethod
    def send(self, alert: Alert, recipients: List[str] = None) -> bool:
        pass

    @abstractmethod
    def get_name(self) -> str:
        pass


class SlackNotification(NotificationChannel):
    """Slack 알림"""

    def __init__(self, config: Dict):
        self.webhook_url = config.get("webhook_url")
        self.bot_token = config.get("bot_token")
        self.default_channel = config.get("default_channel", "#security-alerts")
        self.session = requests.Session()

    def get_name(self) -> str:
        return "Slack"

    def send(self, alert: Alert, recipients: List[str] = None) -> bool:
        try:
            # 채널 결정 (recipients가 Slack 채널 목록)
            channels = recipients if recipients else [self.default_channel]

            # 심각도별 색상
            color_map = {
                Severity.LOW: "#36a64f",      # 녹색
                Severity.MEDIUM: "#ffcc00",   # 노란색
                Severity.HIGH: "#ff9900",     # 주황색
                Severity.CRITICAL: "#ff0000"  # 빨간색
            }

            # 심각도별 이모지
            emoji_map = {
                Severity.LOW: ":information_source:",
                Severity.MEDIUM: ":warning:",
                Severity.HIGH: ":rotating_light:",
                Severity.CRITICAL: ":fire:"
            }

            # 메시지 구성
            blocks = self._build_slack_blocks(alert, emoji_map[alert.severity])
            attachments = [{
                "color": color_map[alert.severity],
                "blocks": blocks
            }]

            success = True
            for channel in channels:
                payload = {
                    "channel": channel,
                    "attachments": attachments,
                    "unfurl_links": False
                }

                if self.bot_token:
                    # Bot API 사용
                    response = self.session.post(
                        "https://slack.com/api/chat.postMessage",
                        headers={"Authorization": f"Bearer {self.bot_token}"},
                        json=payload,
                        timeout=10
                    )
                else:
                    # Webhook 사용
                    response = self.session.post(
                        self.webhook_url,
                        json=payload,
                        timeout=10
                    )

                if response.status_code != 200:
                    logger.error(f"Slack send failed: {response.text}")
                    success = False

            return success

        except Exception as e:
            logger.error(f"Slack notification error: {e}")
            return False

    def _build_slack_blocks(self, alert: Alert, emoji: str) -> List[Dict]:
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} {alert.title}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Severity:*\n{alert.severity.value.upper()}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source:*\n{alert.source}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Time:*\n{alert.timestamp}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Alert ID:*\n{alert.id}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{alert.description}"
                }
            }
        ]

        # 호스트/사용자 정보
        if alert.host or alert.user:
            fields = []
            if alert.host:
                fields.append({"type": "mrkdwn", "text": f"*Host:*\n{alert.host}"})
            if alert.user:
                fields.append({"type": "mrkdwn", "text": f"*User:*\n{alert.user}"})
            blocks.append({"type": "section", "fields": fields})

        # MITRE ATT&CK
        if alert.mitre_tactics or alert.mitre_techniques:
            mitre_text = ""
            if alert.mitre_tactics:
                mitre_text += f"*Tactics:* {', '.join(alert.mitre_tactics)}\n"
            if alert.mitre_techniques:
                mitre_text += f"*Techniques:* {', '.join(alert.mitre_techniques)}"
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": mitre_text}
            })

        # 수행된 조치
        if alert.actions_taken:
            actions_text = "\n".join([f"• {action}" for action in alert.actions_taken])
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Actions Taken:*\n{actions_text}"
                }
            })

        # 케이스 링크
        if alert.case_url:
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View Case"},
                    "url": alert.case_url,
                    "style": "primary"
                }]
            })

        return blocks


class EmailNotification(NotificationChannel):
    """이메일 알림"""

    def __init__(self, config: Dict):
        self.smtp_server = config["smtp_server"]
        self.smtp_port = config["smtp_port"]
        self.use_tls = config.get("use_tls", True)
        self.username = config["username"]
        self.password = config["password"]
        self.from_address = config["from_address"]
        self.from_name = config.get("from_name", "Security Alerts")

    def get_name(self) -> str:
        return "Email"

    def send(self, alert: Alert, recipients: List[str] = None) -> bool:
        if not recipients:
            logger.warning("No email recipients specified")
            return False

        try:
            # 이메일 구성
            msg = MIMEMultipart("alternative")
            msg["Subject"] = self._get_subject(alert)
            msg["From"] = f"{self.from_name} <{self.from_address}>"
            msg["To"] = ", ".join(recipients)

            # 텍스트 버전
            text_content = self._build_text_content(alert)
            msg.attach(MIMEText(text_content, "plain"))

            # HTML 버전
            html_content = self._build_html_content(alert)
            msg.attach(MIMEText(html_content, "html"))

            # 이메일 전송
            context = ssl.create_default_context()

            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                if self.use_tls:
                    server.starttls(context=context)
                server.login(self.username, self.password)
                server.sendmail(self.from_address, recipients, msg.as_string())

            logger.info(f"Email sent to {len(recipients)} recipients")
            return True

        except Exception as e:
            logger.error(f"Email notification error: {e}")
            return False

    def _get_subject(self, alert: Alert) -> str:
        severity_prefix = {
            Severity.LOW: "[INFO]",
            Severity.MEDIUM: "[WARNING]",
            Severity.HIGH: "[ALERT]",
            Severity.CRITICAL: "[CRITICAL]"
        }
        return f"{severity_prefix[alert.severity]} {alert.title}"

    def _build_text_content(self, alert: Alert) -> str:
        return f"""
Security Alert: {alert.title}
{'=' * 50}

Severity: {alert.severity.value.upper()}
Source: {alert.source}
Time: {alert.timestamp}
Alert ID: {alert.id}

Description:
{alert.description}

Host: {alert.host or 'N/A'}
User: {alert.user or 'N/A'}

MITRE ATT&CK:
- Tactics: {', '.join(alert.mitre_tactics) if alert.mitre_tactics else 'N/A'}
- Techniques: {', '.join(alert.mitre_techniques) if alert.mitre_techniques else 'N/A'}

Actions Taken:
{chr(10).join(['- ' + action for action in alert.actions_taken]) if alert.actions_taken else 'None'}

Case: {alert.case_url or 'N/A'}
        """

    def _build_html_content(self, alert: Alert) -> str:
        severity_colors = {
            Severity.LOW: "#36a64f",
            Severity.MEDIUM: "#ffcc00",
            Severity.HIGH: "#ff9900",
            Severity.CRITICAL: "#ff0000"
        }

        template = Template("""
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: {{ severity_color }}; color: white; padding: 15px; border-radius: 5px 5px 0 0; }
        .content { background-color: #f9f9f9; padding: 20px; border: 1px solid #ddd; border-radius: 0 0 5px 5px; }
        .field { margin-bottom: 15px; }
        .field-label { font-weight: bold; color: #555; }
        .field-value { margin-top: 5px; }
        .severity-badge { display: inline-block; padding: 3px 10px; border-radius: 3px; color: white; background-color: {{ severity_color }}; }
        .mitre-box { background-color: #e9ecef; padding: 10px; border-radius: 5px; margin-top: 10px; }
        .actions-list { list-style-type: none; padding-left: 0; }
        .actions-list li:before { content: "✓ "; color: green; }
        .button { display: inline-block; padding: 10px 20px; background-color: #007bff; color: white; text-decoration: none; border-radius: 5px; margin-top: 15px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>🔔 {{ alert.title }}</h2>
        </div>
        <div class="content">
            <div class="field">
                <span class="severity-badge">{{ alert.severity.value | upper }}</span>
                <span style="margin-left: 10px; color: #666;">{{ alert.timestamp }}</span>
            </div>

            <div class="field">
                <div class="field-label">Description</div>
                <div class="field-value">{{ alert.description }}</div>
            </div>

            <div class="field">
                <div class="field-label">Details</div>
                <table style="width: 100%;">
                    <tr><td><strong>Source:</strong></td><td>{{ alert.source }}</td></tr>
                    <tr><td><strong>Host:</strong></td><td>{{ alert.host or 'N/A' }}</td></tr>
                    <tr><td><strong>User:</strong></td><td>{{ alert.user or 'N/A' }}</td></tr>
                    <tr><td><strong>Alert ID:</strong></td><td>{{ alert.id }}</td></tr>
                </table>
            </div>

            {% if alert.mitre_tactics or alert.mitre_techniques %}
            <div class="field">
                <div class="field-label">MITRE ATT&CK</div>
                <div class="mitre-box">
                    {% if alert.mitre_tactics %}
                    <div><strong>Tactics:</strong> {{ alert.mitre_tactics | join(', ') }}</div>
                    {% endif %}
                    {% if alert.mitre_techniques %}
                    <div><strong>Techniques:</strong> {{ alert.mitre_techniques | join(', ') }}</div>
                    {% endif %}
                </div>
            </div>
            {% endif %}

            {% if alert.actions_taken %}
            <div class="field">
                <div class="field-label">Actions Taken</div>
                <ul class="actions-list">
                    {% for action in alert.actions_taken %}
                    <li>{{ action }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}

            {% if alert.case_url %}
            <a href="{{ alert.case_url }}" class="button">View Case</a>
            {% endif %}
        </div>
    </div>
</body>
</html>
        """)

        return template.render(alert=alert, severity_color=severity_colors[alert.severity])


class TeamsNotification(NotificationChannel):
    """Microsoft Teams 알림"""

    def __init__(self, config: Dict):
        self.webhook_url = config["webhook_url"]
        self.session = requests.Session()

    def get_name(self) -> str:
        return "Microsoft Teams"

    def send(self, alert: Alert, recipients: List[str] = None) -> bool:
        try:
            # Adaptive Card 형식 메시지
            card = self._build_adaptive_card(alert)

            payload = {
                "type": "message",
                "attachments": [{
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": card
                }]
            }

            response = self.session.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )

            if response.status_code == 200:
                logger.info("Teams notification sent")
                return True
            else:
                logger.error(f"Teams send failed: {response.text}")
                return False

        except Exception as e:
            logger.error(f"Teams notification error: {e}")
            return False

    def _build_adaptive_card(self, alert: Alert) -> Dict:
        severity_colors = {
            Severity.LOW: "good",
            Severity.MEDIUM: "warning",
            Severity.HIGH: "attention",
            Severity.CRITICAL: "attention"
        }

        card = {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.4",
            "body": [
                {
                    "type": "TextBlock",
                    "text": f"🔔 {alert.title}",
                    "weight": "bolder",
                    "size": "large",
                    "color": severity_colors[alert.severity]
                },
                {
                    "type": "ColumnSet",
                    "columns": [
                        {
                            "type": "Column",
                            "items": [
                                {"type": "TextBlock", "text": "Severity", "weight": "bolder"},
                                {"type": "TextBlock", "text": alert.severity.value.upper(), "color": severity_colors[alert.severity]}
                            ]
                        },
                        {
                            "type": "Column",
                            "items": [
                                {"type": "TextBlock", "text": "Source", "weight": "bolder"},
                                {"type": "TextBlock", "text": alert.source}
                            ]
                        },
                        {
                            "type": "Column",
                            "items": [
                                {"type": "TextBlock", "text": "Time", "weight": "bolder"},
                                {"type": "TextBlock", "text": alert.timestamp[:19]}
                            ]
                        }
                    ]
                },
                {
                    "type": "TextBlock",
                    "text": alert.description,
                    "wrap": True
                }
            ]
        }

        # 호스트/사용자 정보
        if alert.host or alert.user:
            facts = []
            if alert.host:
                facts.append({"title": "Host", "value": alert.host})
            if alert.user:
                facts.append({"title": "User", "value": alert.user})

            card["body"].append({
                "type": "FactSet",
                "facts": facts
            })

        # MITRE ATT&CK
        if alert.mitre_tactics or alert.mitre_techniques:
            mitre_facts = []
            if alert.mitre_tactics:
                mitre_facts.append({"title": "Tactics", "value": ", ".join(alert.mitre_tactics)})
            if alert.mitre_techniques:
                mitre_facts.append({"title": "Techniques", "value": ", ".join(alert.mitre_techniques)})

            card["body"].append({
                "type": "Container",
                "style": "emphasis",
                "items": [
                    {"type": "TextBlock", "text": "MITRE ATT&CK", "weight": "bolder"},
                    {"type": "FactSet", "facts": mitre_facts}
                ]
            })

        # 케이스 링크 버튼
        if alert.case_url:
            card["body"].append({
                "type": "ActionSet",
                "actions": [{
                    "type": "Action.OpenUrl",
                    "title": "View Case",
                    "url": alert.case_url
                }]
            })

        return card


class PagerDutyNotification(NotificationChannel):
    """PagerDuty 알림"""

    def __init__(self, config: Dict):
        self.api_key = config["api_key"]
        self.service_id = config["service_id"]
        self.escalation_policy_id = config.get("escalation_policy_id")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Token token={self.api_key}",
            "Content-Type": "application/json"
        })

    def get_name(self) -> str:
        return "PagerDuty"

    def send(self, alert: Alert, recipients: List[str] = None) -> bool:
        # PagerDuty는 high/critical만 전송
        if alert.severity not in (Severity.HIGH, Severity.CRITICAL):
            logger.info(f"Skipping PagerDuty for {alert.severity.value} severity")
            return True

        try:
            # Events API v2 사용
            payload = {
                "routing_key": self.api_key,
                "event_action": "trigger",
                "dedup_key": alert.id,
                "payload": {
                    "summary": alert.title,
                    "severity": "critical" if alert.severity == Severity.CRITICAL else "error",
                    "source": alert.source,
                    "timestamp": alert.timestamp,
                    "custom_details": {
                        "description": alert.description,
                        "host": alert.host,
                        "user": alert.user,
                        "mitre_tactics": alert.mitre_tactics,
                        "mitre_techniques": alert.mitre_techniques,
                        "actions_taken": alert.actions_taken,
                        "case_id": alert.case_id
                    }
                },
                "links": [],
                "images": []
            }

            if alert.case_url:
                payload["links"].append({
                    "href": alert.case_url,
                    "text": "View Case"
                })

            response = self.session.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=10
            )

            if response.status_code == 202:
                logger.info(f"PagerDuty incident created for alert {alert.id}")
                return True
            else:
                logger.error(f"PagerDuty send failed: {response.text}")
                return False

        except Exception as e:
            logger.error(f"PagerDuty notification error: {e}")
            return False


class NotificationService:
    """알림 통합 서비스"""

    def __init__(self, config: Dict):
        self.config = config
        self.channels: Dict[str, NotificationChannel] = {}
        self._init_channels()

    def _init_channels(self):
        if self.config.get("slack", {}).get("enabled"):
            self.channels["slack"] = SlackNotification(self.config["slack"])

        if self.config.get("email", {}).get("enabled"):
            self.channels["email"] = EmailNotification(self.config["email"])

        if self.config.get("teams", {}).get("enabled"):
            self.channels["teams"] = TeamsNotification(self.config["teams"])

        if self.config.get("pagerduty", {}).get("enabled"):
            self.channels["pagerduty"] = PagerDutyNotification(self.config["pagerduty"])

        logger.info(f"Initialized {len(self.channels)} notification channels")

    def send_alert(
        self,
        alert: Alert,
        channels: List[str] = None,
        recipients: Dict[str, List[str]] = None
    ) -> Dict[str, bool]:
        """
        알림 전송

        Args:
            alert: 알림 객체
            channels: 전송할 채널 목록 (None이면 모든 채널)
            recipients: 채널별 수신자 목록 {"email": ["a@b.com"], "slack": ["#channel"]}

        Returns:
            채널별 전송 결과
        """
        results = {}
        target_channels = channels if channels else list(self.channels.keys())

        for channel_name in target_channels:
            if channel_name not in self.channels:
                logger.warning(f"Unknown channel: {channel_name}")
                continue

            channel = self.channels[channel_name]
            channel_recipients = recipients.get(channel_name) if recipients else None

            try:
                success = channel.send(alert, channel_recipients)
                results[channel_name] = success
                logger.info(f"{channel.get_name()}: {'Success' if success else 'Failed'}")

            except Exception as e:
                logger.error(f"{channel.get_name()} error: {e}")
                results[channel_name] = False

        return results

    def send_by_severity(
        self,
        alert: Alert,
        recipients: Dict[str, List[str]] = None
    ) -> Dict[str, bool]:
        """
        심각도 기반 알림 전송

        - LOW: Slack만
        - MEDIUM: Slack + Email
        - HIGH: Slack + Email + Teams
        - CRITICAL: 모든 채널 + PagerDuty
        """
        severity_channels = {
            Severity.LOW: ["slack"],
            Severity.MEDIUM: ["slack", "email"],
            Severity.HIGH: ["slack", "email", "teams"],
            Severity.CRITICAL: ["slack", "email", "teams", "pagerduty"]
        }

        channels = severity_channels.get(alert.severity, ["slack"])
        return self.send_alert(alert, channels, recipients)


# 편의 함수
_service: Optional[NotificationService] = None


def get_notification_service() -> NotificationService:
    """싱글톤 알림 서비스 인스턴스 반환"""
    global _service
    if _service is None:
        _service = NotificationService(CONFIG)
    return _service


def send_security_alert(
    title: str,
    description: str,
    severity: str,
    source: str = "XDR",
    host: str = None,
    user: str = None,
    **kwargs
) -> Dict[str, bool]:
    """
    보안 알림 전송 헬퍼 함수

    Args:
        title: 알림 제목
        description: 알림 설명
        severity: 심각도 (low, medium, high, critical)
        source: 알림 소스
        host: 관련 호스트
        user: 관련 사용자
        **kwargs: 추가 알림 필드

    Returns:
        채널별 전송 결과
    """
    import uuid

    alert = Alert(
        id=kwargs.get("alert_id", str(uuid.uuid4())),
        title=title,
        description=description,
        severity=Severity(severity.lower()),
        source=source,
        host=host,
        user=user,
        mitre_tactics=kwargs.get("mitre_tactics", []),
        mitre_techniques=kwargs.get("mitre_techniques", []),
        iocs=kwargs.get("iocs", {}),
        actions_taken=kwargs.get("actions_taken", []),
        case_id=kwargs.get("case_id"),
        case_url=kwargs.get("case_url")
    )

    service = get_notification_service()
    return service.send_by_severity(alert, kwargs.get("recipients"))


def main():
    """테스트 함수"""
    # 테스트 알림 생성
    test_alert = Alert(
        id="TEST-001",
        title="Test Security Alert",
        description="This is a test alert from the XDR notification service.",
        severity=Severity.HIGH,
        source="XDR-Test",
        host="workstation-01",
        user="testuser",
        mitre_tactics=["Initial Access", "Execution"],
        mitre_techniques=["T1566.001", "T1059.001"],
        actions_taken=[
            "Host isolated from network",
            "User session terminated",
            "Forensic data collected"
        ],
        case_id="CASE-2024-001",
        case_url="https://thehive.example.com/cases/CASE-2024-001"
    )

    # 서비스 초기화 및 전송
    service = NotificationService(CONFIG)
    results = service.send_by_severity(test_alert)

    print("Notification Results:")
    for channel, success in results.items():
        print(f"  {channel}: {'✓' if success else '✗'}")


if __name__ == "__main__":
    main()
