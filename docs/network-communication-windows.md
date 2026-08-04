# Comunicação entre máquinas no Windows

## Portas oficiais

As duas máquinas precisam usar a mesma build/configuração do InputLeap Modernized.

| Porta | Transporte | Uso | Deve aceitar conexões de outra máquina? |
|---:|---|---|---|
| `24800` | TCP | Controle principal do InputLeap: mouse, teclado e conexão entre `input-leapc`/`input-leaps` | Sim |
| `24810` | TCP | Transferência moderna de arquivos, pastas, texto e imagens, com TLS-PSK quando a sessão estiver pareada | Sim |
| `24801` | TCP | IPC local entre a GUI e o daemon Windows | **Não** |
| `24802` | TCP | Porta usada somente por testes/integrações locais ou fluxos específicos; não é a porta de controle padrão | Não abrir por padrão |

A porta `24801` não deve ser usada para comunicação entre computadores. Se ela aparecer como `127.0.0.1:24801`, isso é esperado para o IPC local e não prova que a rede esteja configurada.

## Requisitos no computador destino

1. A GUI/daemon da **mesma versão** deve estar instalado e em execução.
2. O processo que recebe arquivos deve escutar `24810` em uma interface de rede, não apenas em `127.0.0.1`.
3. O serviço instalado e a GUI não podem ser de versões diferentes. Verifique o caminho do serviço:

```text
C:\Program Files\InputLeap\input-leapd.exe
```

4. O firewall de entrada deve permitir TCP `24800` e TCP `24810` no perfil de rede usado. Não abra `24801` para a LAN.
5. Para transferências autenticadas, os computadores devem estar pareados na sessão atual e possuir a chave TLS-PSK válida em memória. Não copie chaves ou códigos para este arquivo.

## Teste a partir da outra máquina

No PowerShell do computador cliente:

```powershell
Test-NetConnection <IP-DO-DESTINO> -Port 24800
Test-NetConnection <IP-DO-DESTINO> -Port 24810
```

Os dois testes devem retornar `TcpTestSucceeded : True` para controle e transferência. Um teste positivo em `24801` não é suficiente e normalmente indica apenas que o teste foi feito contra o próprio computador.

Para verificar listeners no computador destino:

```powershell
Get-NetTCPConnection -State Listen |
  Where-Object { $_.LocalPort -in 24800,24810 } |
  Format-Table LocalAddress,LocalPort,OwningProcess
```

Se não houver listener em `24800`, o núcleo de controle (`input-leaps`/`input-leapc`, conforme o papel) não está ativo. Se não houver listener em `24810`, mantenha a GUI aberta e confirme se a inicialização do serviço de transferência não registrou erro.

## Diagnóstico de versões misturadas

Este cenário impede a comunicação mesmo quando o firewall parece correto:

- serviço instalado antigo escutando `24801` ou somente localhost;
- GUI nova anunciando `24810`;
- regra de firewall permitindo uma porta diferente da porta anunciada;
- uma máquina usando `24800` e a outra tentando usar `24801` para controle.

Nessa situação, pare somente as instâncias de teste, reinstale/atualize o daemon e a GUI para a mesma build e confirme novamente os listeners. Não altere o serviço do usuário nem regras reais do firewall sem autorização administrativa explícita.

## Resumo rápido

```text
LAN controle:       TCP 24800
LAN transferência:  TCP 24810
IPC local:          TCP 24801 (não abrir na LAN)
```
