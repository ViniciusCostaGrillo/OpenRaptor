#!/usr/bin/env bash
#
# ╔═══════════════════════════════════════════════════════════════════════╗
# ║  RAPTOR - Zero-Config One-Command Installer (OpenCode & Kali Linux)   ║
# ╚═══════════════════════════════════════════════════════════════════════╝
#
# Uso:
#   ./install.sh
#

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}╔═══════════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║             RAPTOR - Instalador Automático de 1 Comando               ║${NC}"
echo -e "${BOLD}${BLUE}║             Pronto para Uso • Kali Linux & OpenCode                   ║${NC}"
echo -e "${BOLD}${BLUE}╚═══════════════════════════════════════════════════════════════════════╝${NC}\n"

# 1. Determinar o diretório da instalação
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 2. Privilégios de Administrador
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo -e "${RED}[!] Execute como root ou garanta acesso ao sudo.${NC}" >&2
        exit 1
    fi
fi

# 3. Pacotes do Sistema Operacional (Apt)
echo -e "${GREEN}[1/6] Instalando dependências de sistema e ferramentas de segurança...${NC}"
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
echo -e "\n${GREEN}[3/6] Sincronizando dependências do RAPTOR em .venv...${NC}"
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
chmod +x "$SCRIPT_DIR/bin/raptor"
chmod +x "$SCRIPT_DIR/libexec/"* || true

# Criar link simbólico global para uso sem precisar mexer em PATH
if [ -d "/usr/local/bin" ]; then
    $SUDO ln -sf "$SCRIPT_DIR/bin/raptor" /usr/local/bin/raptor
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
