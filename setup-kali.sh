#!/usr/bin/env bash
#
# RAPTOR - Automated Setup Script for Kali Linux / Debian
# Configures system packages, uv, OpenCode, and security tools.
#

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BOLD}${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║       RAPTOR - Setup Automatizado para Kali Linux (OpenCode)   ║${NC}"
echo -e "${BOLD}${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}\n"

# 1. Root / Sudo check
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo -e "${RED}[!] Execute como root ou instale o sudo para continuar.${NC}" >&2
        exit 1
    fi
fi

# 2. Update and install Debian/Kali packages
echo -e "${GREEN}[+] 1/6 Atualizando repositórios e instalando dependências de sistema...${NC}"
$SUDO apt-get update -y
$SUDO apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    build-essential \
    curl \
    git \
    jq \
    rizin \
    radare2 \
    aflplusplus \
    gdb \
    libseccomp-dev

# 3. Install uv (Astral) if not present
echo -e "\n${GREEN}[+] 2/6 Verificando/Instalando uv (Fast Python Package Manager)...${NC}"
if ! command -v uv >/dev/null 2>&1; then
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
fi
echo -e "uv version: $(uv --version)"

# 4. Sync Python virtualenv
echo -e "\n${GREEN}[+] 3/6 Sincronizando dependências Python via uv...${NC}"
uv sync --locked
if [ -d ".venv" ]; then
    echo -e "Ambiente virtual pronto em .venv"
fi

# 5. Install OpenCode CLI
echo -e "\n${GREEN}[+] 4/6 Verificando/Instalando OpenCode CLI...${NC}"
if ! command -v opencode >/dev/null 2>&1; then
    echo -e "Instalando OpenCode via script oficial..."
    curl -fsSL https://opencode.ai/install | bash
    export PATH="$HOME/.local/bin:$PATH"
fi
if command -v opencode >/dev/null 2>&1; then
    echo -e "OpenCode disponível em: $(command -v opencode)"
else
    echo -e "${YELLOW}[!] OpenCode foi instalado mas pode exigir reabrir o terminal ou recarregar o PATH.${NC}"
fi

# 6. Install Semgrep
echo -e "\n${GREEN}[+] 5/6 Instalando Semgrep para análise estática...${NC}"
if ! command -v semgrep >/dev/null 2>&1; then
    uv tool install semgrep
    export PATH="$HOME/.local/bin:$PATH"
fi
echo -e "Semgrep: $(command -v semgrep 2>/dev/null || echo 'instalado no uv tools')"

# 7. Set file permissions
echo -e "\n${GREEN}[+] 6/6 Configurando permissões de execução dos scripts...${NC}"
chmod +x bin/raptor
chmod +x libexec/*

echo -e "\n${BOLD}${GREEN}================================================================${NC}"
echo -e "${BOLD}${GREEN}✔ Instalação e configuração do RAPTOR concluídas com sucesso!   ${NC}"
echo -e "${BOLD}${GREEN}================================================================${NC}\n"
echo -e "Para utilizar o comando 'raptor' de qualquer diretório:"
echo -e "  ${YELLOW}export PATH=\"\$PATH:$(pwd)/bin\"${NC}"
echo -e "Adicione a linha acima ao seu ~/.bashrc ou ~/.zshrc.\n"
echo -e "Para iniciar o RAPTOR no OpenCode, execute:"
echo -e "  ${BOLD}raptor${NC}\n"
