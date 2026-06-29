# LOLBins Blue Team Guide

> Referência consolidada para detecção de técnicas **Living Off The Land** no Wazuh — Linux (GTFOBins) e Windows (LOLBAS).

---

## O que é este projeto?

Binários legítimos do sistema operacional são rotineiramente abusados por atacantes para executar código, fazer download de payloads, escalar privilégios e exfiltrar dados — sem instalar nenhum software malicioso. Essa técnica é conhecida como **Living Off The Land (LotL)**.

Este repositório cruza:

- **[GTFOBins](https://gtfobins.org/)** — binários Unix/Linux abusáveis
- **[LOLBAS](https://lolbas-project.github.io/)** — binários/scripts/libs Windows abusáveis

…com **detecção prática no [Wazuh](https://wazuh.com/)**, incluindo regras XML prontas, mapeamento MITRE ATT&CK e orientação sobre falsos positivos.

---

## Estrutura

```
lolbins-blue-team/
├── docs/
│   ├── methodology.md       # Como funcionam LOLBins e os contextos de abuso
│   ├── wazuh-setup.md       # Configurar auditd + Sysmon + Wazuh
│   └── mitre-mapping.md     # Tabela cruzada MITRE ATT&CK
├── linux/
│   ├── execution/           # Interpretadores e executores de código
│   ├── file-operations/     # Leitura, escrita e manipulação de arquivos
│   ├── network/             # Download, upload, shells reversos
│   ├── privesc/             # Escalada de privilégios (sudo, SUID, capabilities)
│   └── data-exfil/          # Exfiltração de dados
├── windows/
│   ├── execution/           # Execução de código via binários nativos
│   ├── download/            # Transferência de arquivos
│   ├── awl-bypass/          # Bypass de Application Whitelist
│   ├── dump/                # Dump de credenciais e memória
│   └── uac-bypass/          # Bypass de UAC
├── wazuh-rules/
│   ├── linux/               # Regras XML para auditd/syslog
│   └── windows/             # Regras XML para Sysmon/WEL
└── sigma/                   # Regras Sigma (multi-SIEM)
```

---

## Formato de cada entrada

Cada binário tem seu próprio `.md` com:

1. **Descrição** — o que o binário faz legitimamente
2. **Como o atacante usa** — técnicas documentadas com exemplos reais
3. **Sinais de detecção** — o que procurar (processo, args, parent, rede)
4. **Regra Wazuh** — XML pronto para importar
5. **Falsos positivos** — como reduzir ruído
6. **Referências** — links GTFOBins/LOLBAS + MITRE ATT&CK

---

## Instalando as regras no Wazuh

```bash
# Copie as regras para o manager
cp wazuh-rules/linux/*.xml /var/ossec/etc/rules/
cp wazuh-rules/windows/*.xml /var/ossec/etc/rules/

# Teste a sintaxe
/var/ossec/bin/wazuh-logtest

# Recarregue
systemctl restart wazuh-manager
```

Veja [docs/wazuh-setup.md](docs/wazuh-setup.md) para configuração completa de auditd e Sysmon.

---

## Cobertura atual

### Linux (GTFOBins)

| Binário | Shell | Cmd | Rev Shell | File R/W | Download | Upload | Privesc |
|---------|:-----:|:---:|:---------:|:--------:|:--------:|:------:|:-------:|
| bash    | ✅ | ✅ | ✅ | — | — | — | — |
| curl    | — | — | ✅ | ✅ | ✅ | ✅ | — |
| wget    | — | — | ✅ | — | ✅ | — | — |
| python3 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| find    | ✅ | ✅ | — | ✅ | — | — | ✅ |
| vim     | ✅ | ✅ | — | ✅ | — | — | ✅ |
| tar     | ✅ | ✅ | — | — | — | — | ✅ |
| nc/ncat | — | — | ✅ | ✅ | ✅ | ✅ | — |
| socat   | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| docker  | ✅ | ✅ | — | ✅ | — | — | ✅ |

### Windows (LOLBAS)

| Binário | Execute | Download | AWL Bypass | Dump | UAC Bypass |
|---------|:-------:|:--------:|:----------:|:----:|:----------:|
| certutil.exe     | — | ✅ | — | — | — |
| rundll32.exe     | ✅ | — | ✅ | — | — |
| mshta.exe        | ✅ | ✅ | ✅ | — | — |
| regsvr32.exe     | ✅ | — | ✅ | — | — |
| msbuild.exe      | ✅ | — | ✅ | — | — |
| bitsadmin.exe    | — | ✅ | — | — | — |
| wmic.exe         | ✅ | — | — | — | — |
| powershell.exe   | ✅ | ✅ | ✅ | ✅ | — |
| installutil.exe  | ✅ | — | ✅ | — | — |
| ntdsutil.exe     | — | — | — | ✅ | — |

---

## Contribuindo

Veja [CONTRIBUTING.md](CONTRIBUTING.md). O template para novas entradas está em [docs/template.md](docs/template.md).

---

## Referências

- [GTFOBins](https://gtfobins.org/) — @GTFOBins
- [LOLBAS Project](https://lolbas-project.github.io/) — @lolbas_project
- [MITRE ATT&CK](https://attack.mitre.org/)
- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Sigma Rules](https://github.com/SigmaHQ/sigma)
- [InternalAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/) — AD/Internal pentest

---

> **Aviso legal:** Este material destina-se exclusivamente a equipes de segurança defensiva. Os exemplos de ataque são reproduzidos para fins de detecção.
