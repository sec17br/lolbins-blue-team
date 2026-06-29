# LOLBins Blue Team Guide

Documentação de referência para equipes de segurança defensiva sobre técnicas de Living Off The Land (LotL) em ambientes Linux e Windows, com foco em detecção via Wazuh.

---

## Contexto

Atacantes experientes evitam instalar ferramentas externas nos sistemas comprometidos. Em vez disso, abusam de binários legítimos já presentes no sistema operacional para executar código, transferir arquivos, escalar privilégios e exfiltrar dados. Essa abordagem, conhecida como Living Off The Land, dificulta a detecção por antivírus e soluções baseadas em hash, já que os binários utilizados são assinados digitalmente e considerados confiáveis pelo sistema.

Este projeto cruza dois repositórios de referência ofensiva:

- GTFOBins (https://gtfobins.org) — binários Unix/Linux abusáveis
- LOLBAS (https://lolbas-project.github.io) — binários, scripts e bibliotecas Windows abusáveis

O resultado é uma documentação orientada ao blue team: para cada binário, explicamos como o ataque funciona na prática, quais sinais procurar, como configurar regras no Wazuh e como reduzir falsos positivos.

---

## Princípio orientador

Entender o ataque é pré-requisito para detectá-lo bem. Uma regra criada sem compreensão da técnica tende a gerar ruído alto ou cobertura insuficiente. Por isso, cada entrada deste projeto descreve o comportamento ofensivo com exemplos reais antes de propor qualquer controle de detecção.

---

## Estrutura

```
lolbins-blue-team/
├── docs/
│   ├── methodology.md       # Como funcionam LOLBins, contextos de abuso e modelo de detecção
│   ├── wazuh-setup.md       # Configuração de auditd, Sysmon e importação de regras
│   └── mitre-mapping.md     # Tabela cruzada com MITRE ATT&CK
├── linux/
│   ├── execution/           # Interpretadores e executores de código arbitrário
│   ├── file-operations/     # Leitura, escrita e manipulação de arquivos
│   ├── network/             # Download, upload, shells reversos, tunelamento
│   ├── privesc/             # Escalada de privilégios via sudo, SUID e capabilities
│   └── data-exfil/          # Exfiltração de dados por canais alternativos
├── windows/
│   ├── execution/           # Execução de código via binários nativos do Windows
│   ├── download/            # Transferência de arquivos de entrada
│   ├── awl-bypass/          # Bypass de Application Whitelist (AppLocker, WDAC)
│   ├── dump/                # Extração de credenciais e memória de processos
│   └── uac-bypass/          # Elevação de privilégios sem prompt de UAC
├── wazuh-rules/
│   ├── linux/               # Regras XML para eventos auditd e syslog
│   └── windows/             # Regras XML para Sysmon e Windows Event Log
└── sigma/                   # Regras Sigma para portabilidade entre SIEMs
```

---

## Como usar as regras Wazuh

Copie os arquivos XML para o diretório de regras do Wazuh Manager e recarregue:

```bash
cp wazuh-rules/linux/*.xml /var/ossec/etc/rules/
cp wazuh-rules/windows/*.xml /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

Consulte docs/wazuh-setup.md para a configuração completa de auditd (Linux) e Sysmon (Windows).

---

## Cobertura atual

### Linux

| Binário | Categorias cobertas |
|---------|---------------------|
| curl | Download, upload, exfiltração, shell reverso |
| wget | Em breve |
| python3 | Em breve |
| bash | Em breve |
| nc/ncat | Em breve |

### Windows

| Binário | Categorias cobertas |
|---------|---------------------|
| certutil.exe | Download, encode/decode, Alternate Data Streams |
| rundll32.exe | Em breve |
| mshta.exe | Em breve |
| msbuild.exe | Em breve |
| powershell.exe | Em breve |

---

## Referências principais

- GTFOBins: https://gtfobins.org
- LOLBAS Project: https://lolbas-project.github.io
- MITRE ATT&CK: https://attack.mitre.org
- Wazuh Documentation: https://documentation.wazuh.com
- Sigma Rules: https://github.com/SigmaHQ/sigma
- InternalAllTheThings: https://swisskyrepo.github.io/InternalAllTheThings

---

Este material destina-se exclusivamente a equipes de segurança defensiva. Os exemplos de ataque são reproduzidos para fins didáticos e de detecção.
