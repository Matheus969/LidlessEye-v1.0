
#matheus.moura6@proton.me
#esse programa monitora logs em tempo real contra ataques de força bruta, SQLi,
#Path Traversal e scanners de vulnerabilidade com geolocalização IP.


import argparse
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

import requests
from rich.console import Console
from rich.panel import Panel

# Inicializa o console da biblioteca Rich para renderização limpa
console = Console()

# REGEX DE DETECÇÃO DE AMEAÇAS

PATTERNS = {
    "ssh_failed_login": re.compile(
        r"Failed password for (?:invalid user )?(\w+) from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ),
    "web_sqli": re.compile(
        r"(?:UNION|SELECT|INSERT|DELETE|DROP|' OR '1'='1)",
        re.IGNORECASE
    ),
    "web_path_traversal": re.compile(
        r"(?:\.\./\.\./|\.\.\\\.\.\\)",
        re.IGNORECASE
    ),
    "web_scanners": re.compile(
        r"(?:nikto|nmap|sqlmap|acunetix|gobuster|dirbuster)",
        re.IGNORECASE
    )
}

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SOURCE_IP_PATTERN = re.compile(r"\bIP:\s*((?:\d{1,3}\.){3}\d{1,3})\b", re.IGNORECASE)


def extract_source_ip(log_line: str) -> str:
    """Extrai o IP de origem do log, priorizando a tag 'IP:' se presente."""
    source_match = SOURCE_IP_PATTERN.search(log_line)
    if source_match:
        return source_match.group(1)

    ip_match = IP_PATTERN.search(log_line)
    return ip_match.group(0) if ip_match else "Desconhecido"


class ThreatDetector:
    """Mecanismo de análise e correlação de ameaças em tempo real."""

    def __init__(self, threshold: int = 5, time_window: int = 60, discord_webhook: Optional[str] = None):
        self.threshold = threshold
        self.time_window = time_window
        self.discord_webhook = discord_webhook
        
        # Estruturas de controle
        self.failed_attempts: Dict[str, list] = defaultdict(list)
        self.alerts_sent: set = set()
        
        # Sessão HTTP reutilizável para alta performance
        self.http_session = requests.Session()

    def check_brute_force(self, ip: str, user: str) -> None:
        """Detecta solicitações repetidas de autenticação em janela móvel."""
        now = datetime.now()
        self.failed_attempts[ip].append((now, user))

        # Filtra registros dentro da janela de tempo estipulada
        cutoff_time = now - timedelta(seconds=self.time_window)
        self.failed_attempts[ip] = [
            t for t in self.failed_attempts[ip] if t[0] >= cutoff_time
        ]

        # Limpeza defensiva de RAM se não houver registros
        if not self.failed_attempts[ip]:
            del self.failed_attempts[ip]
            return

        count = len(self.failed_attempts[ip])
        alert_key = f"brute_force_{ip}_{now.strftime('%Y%m%d%H%M')}"

        if count >= self.threshold and alert_key not in self.alerts_sent:
            self.alerts_sent.add(alert_key)
            geo_info = self.enrich_ip(ip)
            self.trigger_alert(
                threat_type="Ataque de Força Bruta (SSH)",
                ip=ip,
                details=f"{count} tentativas incorretas em menos de {self.time_window}s. Usuário-alvo: '{user}'.",
                geo_info=geo_info
            )

    def check_web_threat(self, threat_type: str, ip: str, log_line: str) -> None:
        """Processa assinaturas de ataques em requisições Web."""
        alert_key = f"{threat_type}_{ip}_{hash(log_line)}"
        if alert_key not in self.alerts_sent:
            self.alerts_sent.add(alert_key)
            geo_info = self.enrich_ip(ip)
            self.trigger_alert(
                threat_type=threat_type,
                ip=ip,
                details=f"Assinatura maliciosa identificada: {log_line.strip()}",
                geo_info=geo_info
            )

    def enrich_ip(self, ip: str) -> Dict[str, str]:
        """Consulta inteligência geográfica e dados de ISP do IP."""
        if ip in ("127.0.0.1", "localhost", "Desconhecido"):
            return {"country": "Rede Interna / Localhost", "city": "Local", "isp": "Loopback"}

        try:
            response = self.http_session.get(f"http://ip-api.com/json/{ip}", timeout=3)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "N/A"),
                        "city": data.get("city", "N/A"),
                        "isp": data.get("isp", "N/A")
                    }
        except requests.RequestException:
            # Falha de conexão/timeout silenciosa para não travar o loop principal
            pass

        return {"country": "Desconhecido", "city": "N/A", "isp": "N/A"}

    def trigger_alert(self, threat_type: str, ip: str, details: str, geo_info: Dict[str, str]) -> None:
        """Dispara notificações no terminal e via Webhook se configurado."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Formatação limpa no terminal via Rich Panel
        alert_content = (
            f"[bold red]🚨 ALERTA DE SEGURANÇA DETECTADO[/bold red]\n"
            f"[bold yellow]Tipo de Ameaça:[/bold yellow] {threat_type}\n"
            f"[bold cyan]IP Origem:[/bold cyan] {ip}\n"
            f"[bold orange3]Localização:[/bold orange3] {geo_info['city']}, {geo_info['country']} ({geo_info['isp']})\n"
            f"[bold white]Detalhes:[/bold white] {details}\n"
            f"[dim]Timestamp: {timestamp}[/dim]"
        )
        console.print(Panel(alert_content, border_style="red", expand=False))

        # Envio assíncrono simulado via Webhook
        if self.discord_webhook:
            self.send_discord_webhook(threat_type, ip, details, geo_info, timestamp)

    def send_discord_webhook(self, threat_type: str, ip: str, details: str, geo_info: Dict[str, str], timestamp: str) -> None:
        """Envia os detalhes do evento para um Webhook do Discord/Teams/Slack."""
        payload = {
            "embeds": [{
                "title": f"🚨 Alerta de Segurança: {threat_type}",
                "color": 15158332,  # Red Color Code
                "fields": [
                    {"name": "IP Origem", "value": ip, "inline": True},
                    {"name": "Localização", "value": f"{geo_info['city']}, {geo_info['country']}", "inline": True},
                    {"name": "Provedor / ISP", "value": geo_info['isp'], "inline": True},
                    {"name": "Detalhes", "value": details, "inline": False},
                    {"name": "Data/Hora", "value": timestamp, "inline": False}
                ],
                "footer": {"text": "LidlessEye Engine • SIEM Threat Detector"}
            }]
        }
        try:
            self.http_session.post(self.discord_webhook, json=payload, timeout=5)
        except requests.RequestException as err:
            console.print(f"[bold red][!] Erro ao transmitir Webhook:[/bold red] {err}")


def monitor_log(file_path: str, detector: ThreatDetector) -> None:
    """Monitora o arquivo de log continuamente (comportamento tail -f)."""
    target_file = Path(file_path)

    banner_text = (
        f"[bold cyan]🛡️ LidlessEye v1.1 - SIEM Threat Detector[/bold cyan]\n"
        f"[bold yellow]📂 Log Alvo:[/bold yellow] {target_file.resolve()}\n"
        f"[dim]Desenvolvido por: matheus.moura6@proton.me[/dim]"
    )
    console.print(Panel(banner_text, border_style="blue", expand=False))

    # Garante que o arquivo existe antes da leitura
    if not target_file.exists():
        target_file.touch()

    with target_file.open("r", encoding="utf-8", errors="ignore") as file:
        file.seek(0, os.SEEK_END)  # Inicia leitura a partir do final do arquivo

        while True:
            line = file.readline()
            if not line:
                time.sleep(0.3)
                continue

            # 1. Análise de Força Bruta SSH
            match_ssh = PATTERNS["ssh_failed_login"].search(line)
            if match_ssh:
                user, ip = match_ssh.group(1), match_ssh.group(2)
                detector.check_brute_force(ip, user)
                continue

            # 2. Análise de SQL Injection
            if PATTERNS["web_sqli"].search(line):
                ip = extract_source_ip(line)
                detector.check_web_threat("Tentativa de SQL Injection", ip, line)
                continue

            # 3. Análise de Path Traversal
            if PATTERNS["web_path_traversal"].search(line):
                ip = extract_source_ip(line)
                detector.check_web_threat("Ataque Path Traversal", ip, line)
                continue

            # 4. Análise de Vulnerability Scanners
            if PATTERNS["web_scanners"].search(line):
                ip = extract_source_ip(line)
                detector.check_web_threat("Scanner de Vulnerabilidades Detectado", ip, line)
                continue


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="LidlessEye - Monitor de Logs e Detector de Ameaças em Tempo Real"
    )
    parser.add_argument("--log", type=str, default="server.log", help="Caminho do arquivo de log a ser monitorado")
    parser.add_argument("--webhook", type=str, default=None, help="URL do Webhook (Discord / Slack / Teams)")
    parser.add_argument("--threshold", type=int, default=5, help="Limite de falhas para alertas de Força Bruta")
    
    args = parser.parse_args()

    engine = ThreatDetector(threshold=args.threshold, discord_webhook=args.webhook)

    try:
        monitor_log(args.log, engine)
    except KeyboardInterrupt:
        console.print("\n[bold red]🛑 Execução do LidlessEye interrompida pelo usuário.[/bold red]")