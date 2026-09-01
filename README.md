# Home Lab SOC com Wazuh

## Objetivo

Projeto de laboratório caseiro para praticar montagem, configuração e operação de um SOC (Security Operations Center) usando o Wazuh como SIEM. O foco é entender coleta de logs, detecção de eventos e resposta a incidentes em um ambiente controlado — **não é um ambiente de produção**.

Este projeto faz parte de um portfólio prático voltado para atuação em equipes Blue Team.

## Arquitetura

<!-- Insira aqui o diagrama (PNG/SVG) feito no draw.io ou Excalidraw -->

| Máquina | Especificação | Função |
|---|---|---|
| Desktop | 16GB RAM, i5 11ª geração | Wazuh Server (manager + indexer + dashboard, via Docker) |
| Notebook | 8GB RAM, i5 | VM Windows (endpoint) |

Todas as VMs foram configuradas em modo **Bridged**, para que ficassem na mesma rede física (LAN) e se enxergassem entre o desktop e o notebook.

**Troubleshooting de rede:** inicialmente houve problemas de conectividade entre as VMs. A causa foi identificada no firewall das máquinas host, que bloqueava **ICMPv4-In (Echo Request)**. Após habilitar essa regra, os testes de conectividade (ping) passaram a funcionar normalmente.

## Setup

### 1. Wazuh Server

Deploy feito seguindo o docker-compose oficial do repositório do Wazuh (single-node stack), versão v4.14.7.

**Clonagem do repositório:**
```bash
git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.7
cd wazuh-docker/single-node/
```

**Geração dos certificados self-signed** (necessário para cada nó da stack, via imagem `wazuh-certs-generator`):
```bash
docker compose -f generate-indexer-certs.yml run --rm generator
```

**Subida da stack** (manager + indexer + dashboard):
```bash
docker compose up -d
```

> Nota: caso o ambiente esteja atrás de proxy, é possível configurar a variável `HTTP_PROXY` no serviço `generator` dentro do `generate-indexer-certs.yml` antes de gerar os certificados.

### 2. Registro dos agentes

O registro foi feito através do assistente **"Deploy new agent"** do próprio dashboard do Wazuh, que gera o comando de instalação já configurado com o endereço do manager. Não houve problemas durante esse processo.

**Endpoint Windows:**
- Server address: `10.0.0.198`
- Agent name: `Windows`
- Grupo: `default`

Comando de instalação gerado e executado no PowerShell (com privilégios de administrador):
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi -OutFile ${env:tmp}\wazuh-agent; msiexec.exe /i ${env:tmp}\wazuh-agent /q WAZUH_MANAGER='10.0.0.198' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Windows'
```

Inicialização do serviço:
```powershell
NET START WazuhSvc
```

### 3. Instalação do Sysmon (endpoint Windows)

Instalado utilizando a configuração da **SwiftOnSecurity**, por ser um conjunto de regras balanceado e amplamente adotado como ponto de partida para logging de eventos do sistema.

```powershell
sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

> Observação: o comando deve ser executado com o CMD/PowerShell aberto no mesmo diretório onde estão o executável do Sysmon e o arquivo de configuração (`sysmonconfig-export.xml`), caso contrário é necessário informar o caminho completo dos arquivos.

### 4. Integração Sysmon → Wazuh

Configurado o bloco `<localfile>` no `ossec.conf` do agente Windows para coletar o canal de eventos do Sysmon:

```xml
<localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
</localfile>
```

Após a alteração, o serviço do agente foi reiniciado para aplicar a configuração:
```powershell
NET STOP WazuhSvc
NET START WazuhSvc
```

> **Troubleshooting:** na primeira tentativa, o valor do `<location>` foi digitado como `Operacional` em vez de `Operational` — o nome do canal de eventos do Windows não é traduzido, mesmo em sistemas operacionais em português. Após a correção, os eventos do Sysmon passaram a ser coletados corretamente e confirmados no dashboard do Wazuh.

## Testes de detecção

Eventos gerados no endpoint Windows para validar a coleta e o parsing no Wazuh, mapeados às técnicas MITRE ATT&CK correspondentes.

| Técnica simulada | Comando/Ação | MITRE ATT&CK | Event ID (Sysmon) | Resultado |
|---|---|---|---|---|
| Execução codificada em base64 | `powershell.exe -enc ...` | T1027 - Obfuscated Files or Information | 1 | ✅ Detectado |
| Cópia de executável suspeito | `Copy-Item calc.exe ...` | — | 11 | ✅ Detectado |
| Encadeamento de processo | `cmd.exe /c powershell.exe ...` | T1059 - Command and Scripting Interpreter | 1 | ✅ Detectado |

<!-- Para cada linha da tabela, adicione abaixo o print do evento no dashboard do Wazuh -->

### Evidências

**Event ID 1 (Process Create)** — comando com base64 capturado corretamente, incluindo `CommandLine`, `ParentImage` e hashes do processo:
<!-- ![Evento base64 - Event ID 1](./docs/evento-1-processcreate.png) -->

**Event ID 11 (File Created)** — criação de arquivo pelo processo PowerShell capturada corretamente:
<!-- ![Evento cópia de arquivo - Event ID 11](./docs/evento-11-filecreate.png) -->


## Regras customizadas

### Detecção de PowerShell com comando codificado em Base64 (T1027)

Regra criada em `/var/ossec/etc/rules/local_rules.xml`, herdando do grupo nativo `sysmon_event1` (Process Create) e adicionando uma condição extra sobre o campo `commandLine`:

```xml
<group name="local,">
  <rule id="100002" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}</field>
    <options>no_full_log</options>
    <description>Possível execução de comando PowerShell codificado em Base64 (T1027)</description>
    <mitre>
      <id>T1027</id>
    </mitre>
  </rule>
</group>
```

Testada com sucesso reexecutando o comando `powershell.exe -enc ...` — o evento passou a ser classificado com nível 12 e a descrição customizada, em vez da classificação genérica de "Process Create".

## Aprendizados

Todo o processo de montagem serviu como um primeiro contato aprofundado com o Wazuh: entendimento prático de como o manager, indexer e dashboard se relacionam, como o parsing de eventos funciona via decoders, e como a hierarquia de regras (`if_group`/`if_sid`) permite criar detecções específicas a partir de regras nativas mais genéricas.

## Próximos passos

- [ ] Aprofundar com os próximos projetos do portfólio, com destaque para o de **Purple Team** (simulação de ataque + ajuste de detecção), que reaproveita esse mesmo ambiente
- [ ] Explorar threat hunting manual sobre os logs coletados
