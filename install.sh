#!/usr/bin/env bash
#
# ╔═══════════════════════════════════════════════════════════════════════╗
# ║  OpenRaptor - Zero-Config One-Command Installer                       ║
# ║  Kali Linux & OpenCode Native Edition                                 ║
# ╚═══════════════════════════════════════════════════════════════════════╝
#
# Uso:
#   1) Diretamente via curl (sem precisar clonar antes):
#      curl -fsSL https://raw.githubusercontent.com/ViniciusCostaGrillo/OpenRaptor/main/install.sh | sudo bash
#
#   2) Ou após clonar o repositório:
#      git clone https://github.com/ViniciusCostaGrillo/OpenRaptor.git
#      cd OpenRaptor
#      sudo ./install.sh
#

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║           OpenRaptor - Instalador Automático de 1 Comando             ║${NC}"
echo -e "${BOLD}${BLUE}║           Pronto para Uso • Kali Linux & OpenCode                     ║${NC}"
echo -e "${BOLD}${BLUE}╚═══════════════════════════════════════════════════════════════════════╝${NC}\n"

# 1. Privilégios de Administrador
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo -e "${RED}[!] Execute como root ou garanta acesso ao comando sudo.${NC}" >&2
        exit 1
    fi
fi

# 2. Determinar o diretório da instalação (suporte a execução local ou via curl|bash)
REPO_URL="https://github.com/ViniciusCostaGrillo/OpenRaptor.git"
INSTALL_DIR=""

if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
    CANDIDATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$CANDIDATE_DIR/bin/raptor" ] && [ -f "$CANDIDATE_DIR/pyproject.toml" ]; then
        INSTALL_DIR="$CANDIDATE_DIR"
    fi
fi

if [ -z "$INSTALL_DIR" ]; then
    # Executado via curl/stdin: instalar em /opt/openraptor
    INSTALL_DIR="/opt/openraptor"
    echo -e "${GREEN}[*] Instalando OpenRaptor em: ${BOLD}$INSTALL_DIR${NC}"
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo -e "Repositório existente detectado. Atualizando..."
        git -C "$INSTALL_DIR" pull --ff-only || true
    else
        $SUDO rm -rf "$INSTALL_DIR"
        $SUDO git clone "$REPO_URL" "$INSTALL_DIR"
    fi
fi

cd "$INSTALL_DIR"

# 3. Pacotes do Sistema Operacional (Apt)
echo -e "\n${GREEN}[1/6] Instalando dependências de sistema e ferramentas de segurança...${NC}"
if command -v apt-get >/dev/null 2>&1; then
    $SUDO apt-get update -y
    $SUDO apt-get install -y \
        python3 python3-pip python3-venv build-essential \
        curl git jq rizin radare2 aflplusplus gdb libseccomp-dev \
        nodejs npm
else
    echo -e "${YELLOW}[!] Gerenciador apt-get não encontrado. Certifique-se de que python3, git e curl estão instalados.${NC}"
fi

# 4. Instalador do uv (Python Package Manager ultra rápido)
echo -e "\n${GREEN}[2/6] Configurando uv e ambiente Python hermético...${NC}"
if ! command -v uv >/dev/null 2>&1; then
    echo -e "Instalando uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
fi

# 5. Sincronizar o ambiente virtual hermético
echo -e "\n${GREEN}[3/6] Sincronizando dependências do OpenRaptor em .venv...${NC}"
uv sync --locked
echo -e "✔ Ambiente Python pronto com todas as dependências isoladas."

# 6. Instalar OpenCode CLI
echo -e "\n${GREEN}[4/6] Verificando / Instalando OpenCode CLI...${NC}"
if ! command -v opencode >/dev/null 2>&1; then
    echo -e "Instalando OpenCode via script oficial..."
    curl -fsSL https://opencode.ai/install | bash
    export PATH="$HOME/.local/bin:$PATH"
fi
if command -v opencode >/dev/null 2>&1; then
    echo -e "✔ OpenCode pronto em: $(command -v opencode)"
fi

# 7. Instalar Semgrep
echo -e "\n${GREEN}[5/6] Instalando Semgrep...${NC}"
if ! command -v semgrep >/dev/null 2>&1; then
    uv tool install semgrep || true
    export PATH="$HOME/.local/bin:$PATH"
fi

# 8. Permissões e Link Global no Sistema (/usr/local/bin/raptor)
echo -e "\n${GREEN}[6/6] Configurando permissões e registrando comando global 'raptor'...${NC}"
chmod +x "$INSTALL_DIR/install.sh" || true
chmod +x "$INSTALL_DIR/setup-kali.sh" || true
chmod +x "$INSTALL_DIR/bin/raptor"
chmod +x "$INSTALL_DIR/libexec/"* || true

# Criar link simbólico global para uso sem precisar mexer em PATH
if [ -d "/usr/local/bin" ]; then
    $SUDO ln -sf "$INSTALL_DIR/bin/raptor" /usr/local/bin/raptor
    echo -e "✔ Link global criado em: ${BOLD}/usr/local/bin/raptor${NC}"
fi

echo -e "\n${BOLD}${GREEN}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║               ✔ TUDO PRONTO PARA USO IMEDIATO!                        ║${NC}"
echo -e "${BOLD}${GREEN}╚═══════════════════════════════════════════════════════════════════════╝${NC}\n"
echo -e "Você não precisa configurar variáveis nem ativar ambientes virtuais.\n"
echo -e "Para começar a usar agora mesmo em qualquer terminal, basta digitar:"
echo -e "  ${BOLD}${YELLOW}raptor${NC}\n"
echo -e "Exemplos de uso rápido:"
echo -e "  ${BLUE}raptor /caminho/do/alvo${NC}          # Inicia análise no alvo"
echo -e "  ${BLUE}raptor --help${NC}                   # Mostra todas as opções e comandos"
echo -e "  ${BLUE}/agentic${NC}                        # Dentro do raptor, roda o pipeline autônomo completo\n"
