# 🛡️ LidlessEye - SIEM Threat Detector & Log Analyzer

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Domain-Cybersecurity%20%2F%20SOC-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

O **LidlessEye** é um detetor de ameaças em tempo real (*SIEM Engine*) desenvolvido em Python. O sistema monitoriza ficheiros de log continuamente, correlaciona eventos maliciosos via Expressões Regulares (Regex) e dispara alertas visuais no terminal acompanhados de enriquecimento de **GeoIP**, além de suportar notificações via **Webhook (Discord/Slack/Teams)**.

<img width="1557" height="908" alt="Captura de Tela (7)" src="https://github.com/user-attachments/assets/75c169e1-1f0d-4307-b40c-4787ce7b6329" />

---
Acompanha também um **Simulador de Ataques** capaz de gerar cenários reais para testes de validação das regras de deteção.

<img width="1590" height="876" alt="Captura de Tela (6)" src="https://github.com/user-attachments/assets/78ca866d-dab4-47dd-9d09-3fe4dfc1ad98" />






---

## 📑 Funcionalidades Principais

- 🔍 **Monitorização em Tempo Real:** Leitura contínua estilo `tail -f` em ficheiros de log HTTP e SSH.
- 🚨 **Deteção de Ameaças:**
  - **Ataques de Força Bruta (SSH):** Agrupamento por IP numa janela móvel de tempo configurável.
  - **SQL Injection (SQLi):** Identificação de assinaturas maliciosas em rotas da aplicação web.
  - **Path Traversal:** Deteção de tentativas de exploração de diretórios (`../`).
  - **Web Scanners:** Mapeamento de User-Agents de ferramentas automatizadas (Nikto, Nmap, Sqlmap, Gobuster, etc.).
- 🌐 **Enriquecimento GeoIP:** Integração com API de geolocalização para extrair Cidade, País e ISP do atacante.
- 🔔 **Notificações Flexíveis:** Painel formatado via `Rich` e suporte a Webhooks para integração com canais de SIEM/SOC no Discord ou Slack.

---

## 🛠️ Tecnologias Utilizadas

- **Linguagem:** Python 3
- **Interface e Formatação:** [Rich](https://github.com/Textualize/rich)
- **Requisições HTTP & APIs:** Requests
- **Análise de Padrões:** Expressões Regulares (`re`)

---

## 🚀 Como Executar o Projeto

### 1. Clonar o Repositório e Instalar Dependências

```bash
git clone [https://github.com/teu-usuario/lidlesseye-siem.git](https://github.com/teu-usuario/lidlesseye-siem.git)
cd lidlesseye-siem
pip install -r requirements.txt
