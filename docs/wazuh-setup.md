# Configuração do Wazuh para Detecção de LOLBins

## 1. Linux — Configurar auditd

### Instalar auditd
```bash
# Debian/Ubuntu
apt install auditd audispd-plugins -y

# RHEL/CentOS
yum install audit audit-libs -y
```

### Regras de auditoria para LOLBins (`/etc/audit/rules.d/lolbins.rules`)
```bash
# Monitorar execuções de processos suspeitos
-a always,exit -F arch=b64 -S execve -k lolbins_exec
-a always,exit -F arch=b32 -S execve -k lolbins_exec

# Monitorar acesso a arquivos sensíveis
-w /etc/passwd -p wa -k sensitive_files
-w /etc/shadow -p wa -k sensitive_files
-w /etc/sudoers -p wa -k sensitive_files
-w /root/.ssh -p wa -k sensitive_files
-w /home -p wa -k sensitive_files

# Monitorar cron
-w /etc/cron.d/ -p wa -k cron_changes
-w /etc/crontab -p wa -k cron_changes
-w /var/spool/cron/ -p wa -k cron_changes

# Monitorar setuid/setgid
-a always,exit -F arch=b64 -S setuid -S setgid -k privesc
-a always,exit -F arch=b32 -S setuid -S setgid -k privesc

# Aplicar
augenrules --load
auditctl -l  # verificar regras ativas
```

### Integrar auditd com Wazuh (`/var/ossec/etc/ossec.conf`)
```xml
<ossec_config>
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>
</ossec_config>
```

### Verificar que o Wazuh está recebendo eventos
```bash
tail -f /var/ossec/logs/archives/archives.log | grep audit
```

---

## 2. Windows — Configurar Sysmon

### Instalar Sysmon
```powershell
# Baixar Sysmon (Microsoft Sysinternals)
# https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon

# Instalar com configuração recomendada (SwiftOnSecurity)
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

### Configuração Sysmon para LOLBins (`sysmonconfig-lolbins.xml`)
```xml
<Sysmon schemaversion="4.90">
  <EventFiltering>

    <!-- Event ID 1: Process Creation -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="include">
        <!-- LOLBins Windows de alta prioridade -->
        <Image condition="end with">certutil.exe</Image>
        <Image condition="end with">rundll32.exe</Image>
        <Image condition="end with">mshta.exe</Image>
        <Image condition="end with">regsvr32.exe</Image>
        <Image condition="end with">msbuild.exe</Image>
        <Image condition="end with">bitsadmin.exe</Image>
        <Image condition="end with">wmic.exe</Image>
        <Image condition="end with">installutil.exe</Image>
        <Image condition="end with">ntdsutil.exe</Image>
        <Image condition="end with">cscript.exe</Image>
        <Image condition="end with">wscript.exe</Image>
        <Image condition="end with">regasm.exe</Image>
        <Image condition="end with">regsvcs.exe</Image>
        <Image condition="end with">odbcconf.exe</Image>
        <Image condition="end with">msiexec.exe</Image>
        <Image condition="end with">forfiles.exe</Image>
        <Image condition="end with">esentutl.exe</Image>
        <Image condition="end with">expand.exe</Image>
        <Image condition="end with">extrac32.exe</Image>
        <Image condition="end with">mavinject.exe</Image>
        <Image condition="end with">procdump.exe</Image>
        <!-- PowerShell com argumentos suspeitos -->
        <CommandLine condition="contains">-enc </CommandLine>
        <CommandLine condition="contains">-EncodedCommand</CommandLine>
        <CommandLine condition="contains">IEX</CommandLine>
        <CommandLine condition="contains">Invoke-Expression</CommandLine>
        <CommandLine condition="contains">DownloadString</CommandLine>
        <CommandLine condition="contains">WebClient</CommandLine>
      </ProcessCreate>
    </RuleGroup>

    <!-- Event ID 3: Network Connection -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="include">
        <Image condition="end with">certutil.exe</Image>
        <Image condition="end with">bitsadmin.exe</Image>
        <Image condition="end with">mshta.exe</Image>
        <Image condition="end with">regsvr32.exe</Image>
        <Image condition="end with">wmic.exe</Image>
        <Image condition="end with">msiexec.exe</Image>
        <Image condition="end with">cscript.exe</Image>
        <Image condition="end with">wscript.exe</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 7: Image Load (DLL) -->
    <RuleGroup name="ImageLoad" groupRelation="or">
      <ImageLoad onmatch="include">
        <!-- DLLs usadas em ataques via rundll32 -->
        <ImageLoaded condition="contains">scrobj.dll</ImageLoaded>
        <ImageLoaded condition="contains">comsvcs.dll</ImageLoaded>
      </ImageLoad>
    </RuleGroup>

  </EventFiltering>
</Sysmon>
```

### Integrar Sysmon com Wazuh (agent `ossec.conf`)
```xml
<ossec_config>
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</ossec_config>
```

---

## 3. Importar Regras de Detecção

### Copiar regras para o Wazuh Manager
```bash
# Regras Linux
cp /path/to/lolbins-blue-team/wazuh-rules/linux/*.xml \
   /var/ossec/etc/rules/

# Regras Windows
cp /path/to/lolbins-blue-team/wazuh-rules/windows/*.xml \
   /var/ossec/etc/rules/
```

### Testar sintaxe
```bash
/var/ossec/bin/wazuh-logtest
# Cole um log de exemplo e veja qual regra dispara
```

### Recarregar rules sem restart
```bash
kill -HUP $(cat /var/ossec/var/run/wazuh-analysisd.pid)
```

---

## 4. Grupos de Alertas e Níveis

| Level | Significado | Ação recomendada |
|-------|-------------|------------------|
| 7–8 | Suspeito — contexto incomum | Investigar se repetido |
| 9–11 | Alta suspeita — raramente legítimo | Alert + ticket automático |
| 12–15 | Crítico — quase certamente malicioso | Alert imediato + bloqueio opcional |

---

## 5. Integração com Alertas (Slack/PagerDuty)

```xml
<!-- /var/ossec/etc/ossec.conf -->
<integration>
  <name>slack</name>
  <hook_url>https://hooks.slack.com/services/XXX/YYY/ZZZ</hook_url>
  <level>10</level>
  <group>lolbins,gtfobins,lolbas</group>
  <alert_format>json</alert_format>
</integration>
```

---

## 6. Dashboard Wazuh — Filtros úteis

```
# Kibana/OpenSearch Query para LOLBins
rule.groups: "lolbins" AND rule.level: [10 TO 15]

# Filtrar por binário específico
data.win.eventdata.image: "*certutil*" AND rule.level: [9 TO 15]

# Filtrar Linux por comando
data.audit.command: "curl" AND rule.level: [9 TO 15]
```
