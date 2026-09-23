#Codigo criador por matheus moura, este programa simula 
#6 ataque de brute force no SSH
#registra vulnerabilidades web 
#registra uma tentativa de attack ao banco de dados

#importei a rich para deixa mais bonitinho a iterface kkkk

import time
from rich.console import Console
from rich.progress import Progress
from rich.align import Align

#esse server.log e o arquivo que e definido como destino dos log

LOG_FILE = "server.log"
console = Console()

#aqui eu fiz uma interface interativa com barra de carregamento

def print_header():
    print("👤 By: matheus.moura6@proton.me")
    console.rule("[bold blue]SIMULADOR DE ATTACK[/bold blue]", style="blue")

def wait_for_start():
    console.print(Align.center("[bold]APERTE ENTER PARA INICIAR_[/bold]"))
    input()


def write_log(line: str):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    console.log(f"[Simulador] Log gerado: {line.strip()}")


def simulate_progress(message: str, steps=10, delay=0.3):
    with Progress(transient=True) as progress:
        task = progress.add_task(f"[green]{message}", total=steps * 10)
        for _ in range(steps):
            progress.update(task, advance=10)
            time.sleep(delay)

#Gera 6 tentativas registradas de invasão por senha no SSH

def simulate_brute_force(ip: str):
    console.print(f"\n[cyan]--- [1] Simulando Ataque Brute Force SSH de {ip} ---[/cyan]")
    for i in range(6):
        timestamp = f"Oct 24 14:02:{10 + i}"
        log_line = (
            f"{timestamp} server sshd[1234]: Failed password for invalid user admin from {ip} port 54321 ssh2"
        )
        write_log(log_line)
        time.sleep(0.8)

#Regista uma varredura de vulnerabilidades web

def simulate_nikto_scan(ip: str):
    console.print(f"\n[cyan]--- [2] Simulando Web Scanner (Nikto) de {ip} ---[/cyan]")
    log_line = (
        f'192.168.1.1 - - [24/Oct/2026:14:02:20 +0000] '
        f'"GET /admin HTTP/1.1" 404 123 "-" "Mozilla/5.0 (Nikto/2.1.6)" IP:{ip}'
    )
    write_log(log_line)

#Registra uma tentativa de invasão a banco de dados via URL

def simulate_sql_injection(ip: str):
    console.print(f"\n[cyan]--- [3] Simulando SQL Injection de {ip} ---[/cyan]")
    log_line = (
        f'192.168.1.1 - - [24/Oct/2026:14:02:25 +0000] '
        f'"GET /login?user=admin\' OR \'1\'=\'1 HTTP/1.1" 200 450 "-" "Mozilla/5.0" IP:{ip}'
    )
    write_log(log_line)


def run_simulation():
    print_header()
    wait_for_start()
    simulate_progress("Carregando...", steps=10, delay=0.3)

    simulate_brute_force("185.220.101.5")
    time.sleep(3)

    simulate_nikto_scan("45.154.255.88")
    time.sleep(3)

    simulate_sql_injection("89.248.165.72")

    console.print("\n[bold green]✔ Simulação concluída com sucesso![/bold green]")


if __name__ == "__main__":
    run_simulation()

#se for usar meu codigo da meus creditos ae man:
#https://github.com/Matheus969