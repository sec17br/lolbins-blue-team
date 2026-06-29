# [NOME DO BINÁRIO] — [Categoria Principal]

> **Plataforma:** Linux | Windows  
> **Fonte:** [GTFOBins](URL) | [LOLBAS](URL)  
> **MITRE ATT&CK:** T1XXX.XXX — Nome da Técnica  
> **Risco:** Alto | Médio | Baixo  

---

## Descrição

O que o binário faz legitimamente e por que é abusável.

---

## Como o Atacante Usa

### Técnica 1 — Nome
```bash
# Descrição do que faz
comando --arg1 valor
```

**Contexto:** Quando/como essa técnica é usada em ataques reais.

### Técnica 2 — Nome
```bash
comando --arg2 valor
```

---

## Sinais de Detecção

| Indicador | Valor | Relevância |
|-----------|-------|------------|
| Processo | `nome_do_binario` | Sempre presente |
| Argumento | `--flag-suspeita` | Alta |
| Parent process | `www-data`, `apache2` | Crítico |
| Conexão de rede | Porta X para IP externo | Alta |
| Arquivo criado | `/tmp/[a-z]{8}` | Média |

---

## Regra Wazuh

```xml
<!-- Arquivo: wazuh-rules/linux/XXXX-gtfobins_categoria.xml -->
<!-- OU:      wazuh-rules/windows/XXXX-lolbas_categoria.xml -->

<group name="lolbins,gtfobins,linux">  <!-- ou lolbas,windows -->

  <rule id="1XXXXX" level="X">
    <!-- condições -->
    <description>Descrição do alerta</description>
    <mitre>
      <id>TXXXX.XXX</id>
    </mitre>
  </rule>

</group>
```

---

## Falsos Positivos

- **Cenário legítimo 1:** Descrição → Mitigação (ex: filtrar por usuário `jenkins`)
- **Cenário legítimo 2:** Descrição → Mitigação

---

## Referências

- [GTFOBins — nome](https://gtfobins.org/gtfobins/nome/)  
  OU  
  [LOLBAS — Nome.exe](https://lolbas-project.github.io/lolbas/Binaries/Nome/)
- MITRE ATT&CK: [T1XXX](https://attack.mitre.org/techniques/T1XXX/)
