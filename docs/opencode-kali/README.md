# RAPTOR — Fork Nativo OpenCode para Kali Linux

## 📌 Visão Geral

Este projeto é um fork do **RAPTOR** (Recursive Autonomous Penetration Testing and Observation Robot), adaptado para substituir o **Claude Code** pelo **OpenCode** (`opencode.ai`) e otimizado para execução nativa no **Kali Linux**.

### O que muda neste Fork?
1. **Desacoplamento do Claude Code:** Remoção da dependência do binário proprietário `claude` e da subscrição Anthropic como único meio interativo.
2. **Orquestração com OpenCode:** Uso nativo de `AGENTS.md`, `.opencode/commands/*.md`, `.opencode/agents/*.md`, e `opencode.json`.
3. **Multi-Model Flexibility:** Suporte a mais de 75 provedores de LLM suportados pelo OpenCode, incluindo modelos locais via Ollama/vLLM (DeepSeek R1, Llama 3, Qwen) e APIs em nuvem (Claude, GPT, Gemini).
4. **Foco no Kali Linux:** Script unificado `setup-kali.sh` automatizando a instalação de scanners, fuzzer AFL++, ferramentas de engenharia reversa (Rizin/Radare2), GDB e dependências via `apt` e `uv`.
5. **Preservação de Segurança:** Manutenção dos mecanismos de sandbox Linux (Landlock, seccomp BPF, namespaces) e trust-markers (`_RAPTOR_TRUSTED`, session tokens).

---

## 📂 Estrutura da Documentação do Fork

- [Arquitetura & Stack Tecnológica](ARCHITECTURE.md)
- [Plano de Implementação em 8 Tarefas](IMPLEMENTATION_PLAN.md)
- [Mapeamento de Comandos e Subagentes](COMMANDS_AND_AGENTS_MAP.md)

---

## 🚀 Como Executar no Kali Linux (Planejado)

```bash
# 1. Clonar o fork
git clone https://github.com/seu-fork/raptor.git
cd raptor

# 2. Executar setup automatizado para Kali Linux
chmod +x setup-kali.sh
./setup-kali.sh

# 3. Iniciar o RAPTOR interativo com OpenCode
raptor
```


---

## 🛡️ Bundle Integrado: "AAS Security Engineer"

O fork vem equipado por padrão com todas as skills do bundle **AAS Security Engineer** (do repositório [agentic-awesome-skills](https://github.com/sickn33/agentic-awesome-skills)):
1. `ethical-hacking-methodology`: Metodologia de pentest autorizada e ciclo de vida completo.
2. `burp-suite-testing`: Testes de aplicações web com fluxos integrados do Burp Suite.
3. `top-web-vulnerabilities`: Cobertura de classes de vulnerabilidades alinhadas ao OWASP Top 10.
4. `api-security-testing`: Auditoria e testes de segurança em APIs REST e GraphQL.
5. `linux-privilege-escalation`: Identificação de vetores de escalação de privilégios em Linux/Kali.
6. `cloud-penetration-testing`: Avaliação de ambientes de nuvem (AWS, Azure, GCP).
7. `security-auditor`: Auditoria holística de segurança em código e infraestrutura.
8. `vulnerability-scanner`: Triagem e validação prática de vulnerabilidades.
9. `sast-configuration`: Ajuste e parametrização de scanners estáticos.
10. `web-security-testing`: Testes defensivos e validação de segurança web.
11. `threat-modeling-expert`: Mapeamento de ameaças e fronteiras de confiança.
12. `skill-security-audit`: Auditoria de segurança de instruções e fluxos de dados de agentes.
