# Inventário de contratos da reescrita Rust/Tauri

**Estado:** baseline R0 refeito e regateado para a fonte corrente; R2.9/DMMV permanece aberta até dois reviews independentes aprovarem o mesmo snapshot  
**Fonte do contrato:** C++ atual do working tree, antes da implementação Rust  
**Regra:** a implementação Rust deve reproduzir bytes, limites e falhas observáveis antes de substituir qualquer consumidor C++.

## 1. Convenções de serialização

`ProtocolUtil` define o codec binário comum (`src/lib/inputleap/ProtocolUtil.h`):

| Formato | Wire |
|---|---|
| `%1i` | inteiro de 1 byte |
| `%2i` | inteiro de 2 bytes em network byte order |
| `%4i` | inteiro de 4 bytes em network byte order |
| `%1I` | lista de `u8` |
| `%2I` | lista de `u16` em network byte order |
| `%4I` | lista de `u32` em network byte order |
| `%s` | `u32` big-endian de comprimento seguido pelos bytes da string |
| `%S` | somente escrita: `u32` big-endian de comprimento seguido por bytes crus; `vreadf()` não implementa `%S` |
| `%%` | byte literal `%` |

Limites atuais em `src/lib/inputleap/protocol_types.h`:

- payload remoto: até `4.194.304` bytes, inclusive; wire máximo `4.194.308` bytes com o prefixo externo;
- lista: teto nominal de contagem `1.048.576`; o limite efetivo também depende da largura e do payload total. `%4I` isolado aceita no máximo `1.048.575` elementos e `DSOP%4I`, por incluir o código de quatro bytes, no máximo `1.048.574`;
- string: até `1.048.576` bytes, inclusive;
- resposta hello: `1024` bytes;
- protocolo remoto atual: `1.6`;
- porta de controle padrão: `24800`.

Strings são sequências de bytes: NUL é preservado e o core não valida UTF-8. Signedness é interpretação do consumidor, não propriedade do wire. Clipboard e arquivo usam chunks de 32 KiB por política do emissor; esse valor não substitui os limites do parser.

## 2. Wire remoto — TCP/TLS 24800

### Framing externo

`PacketStreamFilter` escreve `u32` big-endian com o tamanho do payload, seguido pelo payload. No recebimento, tamanho superior a `PROTOCOL_MAX_MESSAGE_LENGTH` gera `STREAM_INPUT_FORMAT_ERROR`; o parser não espera o corpo inteiro de um tamanho já inválido.

### Greeting

O greeting usa o prefixo textual `Barrier` por compatibilidade histórica:

| Fluxo | Formato |
|---|---|
| servidor → cliente | `Barrier%2i%2i` |
| cliente → servidor | `Barrier%2i%2i%s` |

O limite de `1024` bytes cobre o hello-back inteiro; o nome máximo efetivamente aceito é `1009` bytes. A versão não é simétrica: o servidor cria proxy somente para `1.6`, enquanto o cliente rejeita servidor menor que `1.6`, mas atualmente aceita versão maior e responde como `1.6`. `UnsupportedVersion` precisa, portanto, considerar direção e estado.

### Comandos e dados

| Código | Formato de payload | Direção/uso |
|---|---|---|
| `CNOP` | `CNOP` | emissão produtiva observada: cliente → servidor em sessão ativa; decode aceito: servidor → cliente em handshake/ativo e cliente → servidor após hello-back aguardando `DINF`/ativo; rejeitado antes do hello-back |
| `CBYE` | `CBYE` | decode servidor → cliente em handshake/ativo; terminal; sem encode produtivo observado porque `ClientProxy::close(msg)` ignora `msg` |
| `CINN` | `CINN%2i%2i%4i%2i` | entrar em tela |
| `COUT` | `COUT` | servidor → cliente; emissão/decode: cliente receptor ativo; sair da tela |
| `CCLP` | `CCLP%1i%4i` | clipboard grab |
| `CSEC` | `CSEC%1i` | servidor → cliente ativo; writer produtivo emite apenas `0`/`1`; decode estrutural preserva qualquer `u8`, com efeito C++ `0 = false` e qualquer valor não zero `= true`; não terminal |
| `CROP` | `CROP` | servidor → cliente; emissão/decode: cliente receptor em handshake/ativo; resetar opções |
| `CIAK` | `CIAK` | servidor → cliente; emissão/decode: cliente receptor em handshake/ativo; ack de info |
| `CALV` | `CALV` | decode: servidor → cliente em handshake/ativo e cliente → servidor ativo; encode observado: servidor → cliente ativo e cliente → servidor aguardando `DINF`/ativo; servidor → cliente em handshake permanece `UNKNOWN`/não autorizado; efeitos stateful descritos abaixo |
| `DKDN` | `DKDN%2i%2i%2i` | key down 1.1+ |
| `DKDN` | `DKDN%2i%2i` | key down 1.0 |
| `DKRP` | `DKRP%2i%2i%2i%2i` | key repeat 1.1+ |
| `DKRP` | `DKRP%2i%2i%2i` | key repeat 1.0 |
| `DKUP` | `DKUP%2i%2i%2i` | key up 1.1+ |
| `DKUP` | `DKUP%2i%2i` | key up 1.0 |
| `DMDN` | `DMDN%1i` | servidor → cliente ativo; `ButtonID` produtivo é `u8`, decode preserva todos os bit patterns após o cast legado `int8_t → ButtonID`; botão down; não terminal |
| `DMUP` | `DMUP%1i` | servidor → cliente ativo; mesmo domínio `u8` de `DMDN`; botão up; não terminal |
| `DMMV` | `DMMV%2i%2i` | servidor → cliente ativo; coordenadas `i16`, boundary de 8 bytes, mensagem não terminal; truncamento falha fechado com `EBAD`, disconnect e nenhum callback; movimento absoluto |
| `DMRM` | `DMRM%2i%2i` | movimento relativo |
| `DMWM` | `DMWM%2i%2i` | scroll horizontal/vertical |
| `DMWM` | `DMWM%2i` | scroll 1.0 |
| `DCLP` | `DCLP%1i%4i%1i%s` | dados de clipboard |
| `DINF` | `DINF%2i%2i%2i%2i%2i%2i%2i` | geometria/posição do cliente |
| `DSOP` | `DSOP%4I` | pares opção/valor |
| `DFTR` | `DFTR%1i%s` | transferência de arquivo legada |
| `DDRG` | `DDRG%2i%s` | drag info |
| `QINF` | `QINF` | servidor → cliente; emissão produtiva observada: cliente receptor em handshake; decode: handshake/ativo (ativo é decode-only); consulta de tela |
| `EICV` | `EICV%2i%2i` | servidor → cliente durante handshake; emissão produtiva observada somente para `1.6`; decode estrutural aceita quaisquer dois bit patterns `i16`; boundary de 8 bytes; terminal |
| `EBSY` | `EBSY` | decode servidor → cliente em handshake; terminal; sem encode produtivo observado porque `ClientProxy::close(msg)` ignora `msg` |
| `EUNK` | `EUNK` | decode servidor → cliente em handshake; terminal; sem encode produtivo observado porque `ClientProxy::close(msg)` ignora `msg` |
| `EBAD` | `EBAD` | decode servidor → cliente em handshake/ativo; encode produtivo comprovado servidor → cliente em handshake; send-site cliente → servidor existe, mas o estado do receptor permanece `UNKNOWN` e não autoriza encode; terminal |

> Os formatos legados 1.0 compartilham o mesmo ID de quatro bytes, mas não são alcançáveis pelo proxy 1.6 atual, que espera sempre o layout moderno.

### Alcance operacional

- servidor recebendo cliente em sessão 1.6: `DFTR`, `DDRG`, `CALV`, `DINF`, `CNOP`, `CCLP` e `DCLP`;
- cliente recebendo servidor em sessão: input, clipboard, info/opções, file/drag, keepalive/no-op, enter/leave e erros documentados;
- `EBSY`, `EUNK` e `CBYE` são definidos e parseáveis, mas o caminho atual `ClientProxy::close(const char*)` ignora o código recebido e apenas faz flush. Fixtures devem marcá-los como definidos/intencionados, não como comprovadamente emitidos por esse caminho;
- a classificação terminal de `CBYE`, `EBSY`, `EUNK` e `EBAD` no codec Rust é metadata para policy do caller: preserva `consumed=4`, mas não executa nem comprova disconnect ou transição da state machine C++;
- `EICV` é emitido por `ClientProxyUnknown` com a versão produtiva `1.6` e aceito pelo `ServerProxy` somente no handshake do cliente. O parser Rust preserva os dois campos como `i16`, aceita estruturalmente qualquer bit pattern e marca `consumed=8`; encode Rust é autorizado somente para `1.6` nesse contexto. A metadata terminal do parser continua sem efeitos stateful. Separadamente, um harness C++ conduz `ServerProxy` pelo evento público `STREAM_INPUT_READY` e observa `CLIENT_CONNECTION_FAILED` sem reprocessar o comando seguinte. Os números logados pelo consumidor C++ não são oracle: `ServerProxy.cpp` passa ponteiros `int32_t*` para `%2i`, enquanto `ProtocolUtil::vreadf()` grava por `uint16_t*`; somente bytes do writer, framing real e efeito terminal são comparados;
- `CALV` recebido pelo cliente em handshake produz eco `CALV`; no cliente ativo produz `CALV` seguido de `CNOP`, nessa ordem. O servidor em handshake rejeita e desconecta; ativo aceita sem resposta e faz dois resets estruturais do alarme no processamento do lote. Um frame de entrada no cliente ativo gera dois frames de saída (amplificação limitada de `2×`); periodicidade e expiração de timer não estão cobertas sem relógio virtual;
- frame externo de tamanho zero não se torna pronto em `PacketStreamFilter` e exige caso próprio no corpus.

### Estados que o oracle deve classificar

- `Accepted`: frame completo e canônico;
- `NeedMore`: prefixo/campo/corpo parcial que ainda pode se tornar válido;
- `Malformed`: rejeição específica do consumidor e do estado; não presumir que todo enum inválido ou trailing data seja terminal. O oracle deve registrar separadamente o resultado do parser de framing, do parser da mensagem e da state machine;
- `Oversized`: prefixo de frame, string ou lista acima do limite;
- `UnsupportedVersion`: greeting/negociação de versão não suportada.

O frame externo não é fronteira atômica de comando para os consumidores atuais: comandos completos adicionais dentro do mesmo payload podem ser processados. O corpus deve cobrir `CNOPCNOP` em um único frame, resíduos de 1–3 bytes, próximo código válido e próximo código desconhecido.

## 3. IPC local — loopback 24801

### Transporte e identidade

- endereço atual: `127.0.0.1:24801`;
- não há prefixo global de frame; o código de quatro bytes e os comprimentos de `%s` delimitam cada mensagem;
- o parser incremental mantém buffer e retorna `NeedMore` até haver campos suficientes;
- qualquer código/enum/tamanho inválido coloca `IpcFrameReader` em estado terminal inválido e limpa o buffer;
- string acima de `1 MiB` é inválida;
- Core/daemon (`IpcFrameReader`): buffer agregado máximo `2.097.167` bytes, calculado como código + três enums + duas strings máximas; um append coalescido acima desse total invalida o reader mesmo quando contém frames individualmente válidos;
- GUI (`IpcReader`): strings limitadas a `1.048.576` bytes, porém sem teto agregado equivalente; frames válidos coalescidos são drenados em sequência;
- o IPC não possui versão; código desconhecido é `Malformed`, e `UnsupportedVersion` não se aplica a 24801;
- GUI e core mantêm cópias independentes das constantes IPC; testes diferenciais devem detectar divergência entre elas;
- loopback não é autenticação: no Windows a identidade real precisa continuar ligada a PID, caminho confiável e papel; no Unix o substituto deverá usar UDS e credenciais do peer.

Autorização operacional por papel no daemon atual:

- GUI → daemon: `IHEL`, depois `ICMD`, `ISTR`, `IRLD`, `ISTP` ou `IGST`;
- node → daemon: `IHEL`, depois `ISTS`;
- daemon → GUI: `ILOG`, `IACK`, `IRTS` e `ISTS`;
- daemon → node: `ISDN`.

O proxy C++ da GUI serializa `IGST` e entrega `IRTS` como evento tipado. `IACK` e `IRTS` correlacionados são enviados com `sendToConnection` somente à conexão GUI que originou o pedido; não são broadcast para outras GUIs conectadas.

### Mensagens cliente → daemon

| Código | Formato | Restrições |
|---|---|---|
| `IHEL` | `IHEL%1i` | papel somente GUI ou node |
| `ICMD` | `ICMD%s%1i` | elevate somente `0` ou `1` |
| `ISTR` | `ISTR%s%s%1i` | nonce exatamente 16 bytes; elevate `0/1` |
| `IRLD` | `IRLD%s%s` | `request_nonce` e `expected_applied_nonce` exatamente 16 bytes e distintos; somente GUI autenticada; exige que a geração esperada seja a última operação duravelmente aplicada e reaplica exatamente o mesmo comando/elevate antes de `IACK(request_nonce)` |
| `ISTP` | `ISTP%s%s` | `request_nonce` e `expected_applied_nonce` exatamente 16 bytes e distintos; somente GUI autenticada; para somente a geração autoritativa esperada e responde `IACK(request_nonce)` apenas após parada confirmada e conclusão persistida |
| `IGST` | `IGST%s` | `query_nonce` exatamente 16 bytes; somente GUI autenticada; consulta autoritativa antes de operação mutável |
| `ISTS` | `ISTS%1i%1i%1i%s%s` | enums limitados; identidade conhecida exige nome; degradação legada exige nome vazio |

`IRLD` não aceita command line no payload e não pode adicionar, remover ou substituir argumentos de transporte. Sem uma geração duravelmente aplicada, com `expected_applied_nonce` obsoleto, com colisão entre os dois nonces ou depois de um stop confirmado, o daemon rejeita o pedido sem aplicar processo e sem emitir `IACK`. O commit marker `authenticated-ipc-v4` vincula comando, elevação, nonce do reload e geração esperada; um replay idêntico é ACKado sem reaplicar, inclusive após reconstrução do daemon, enquanto um novo `ISTR` ou `ISTP` invalida o replay anterior. Como o IPC 24801 não possui negociação de versão, cliente e daemon precisam ser atualizados juntos antes de o cliente enviar esse código.

Se a aplicação do processo novo foi tentada e seu resultado é aplicado ou incerto, mas a chamada, a persistência final de `CommandAppliedNonce` ou a configuração de runtime falha, a transação não emite `IACK`: o daemon solicita parada compensatória e revoga em memória as autoridades START/RELOAD/STOP, impedindo que a geração anterior autorize um comando stale sobre o processo novo. Falhas de persistência anteriores à tentativa não disparam compensação.

Se a parada foi confirmada, mas a conclusão de `CommandStopAppliedNonce` falha, o daemon não emite `IACK`, revoga as autoridades START/RELOAD e mantém uma receipt STOP pending em memória. Retry idêntico persiste apenas a conclusão e ACKa sem repetir a parada. Após reconstrução, a receipt pending não presume que o efeito ocorreu: o daemon primeiro confirma/garante o estado parado via watchdog, depois persiste a conclusão e somente então ACKa. Falha nessa confirmação mantém a receipt incompleta e não produz ACK.

`ISTP` rejeita geração obsoleta, nonces iguais ou de tamanho inválido sem persistir, parar ou ACKar. A receipt `authenticated-ipc-stop-v1` vincula domínio STOP, nonce do pedido, geração esperada e marcador de conclusão em chaves dedicadas. Um replay idêntico concluído é ACKado sem repetir persistência ou parada, inclusive após reconstrução; colisão do mesmo nonce com outra geração permanece rejeitada. START também rejeita um nonce já vinculado à receipt STOP atual/restaurada, evitando ACK ambíguo entre domínios.

### Mensagens daemon → cliente

| Código | Formato | Restrições |
|---|---|---|
| `ISDN` | `ISDN` | sem campos |
| `ILOG` | `ILOG%s` | linha limitada pelo máximo de string |
| `IACK` | `IACK%s` | nonce exatamente 16 bytes |
| `IRTS` | `IRTS%s%1i%1i%s` | ecoa `query_nonce` de 16 bytes; schema exatamente `1`; estado `stopped=0`, `running=1` ou `unknown=2`; `applied_nonce` vazio ou com 16 bytes |
| `ISTS` | `ISTS%1i%1i%1i%s%s` | mesmo contrato simétrico de estado |

Enums atuais:

- client type: unknown `0`, GUI `1`, node `2`; hello rejeita unknown;
- connection state: available `0`, connected `1`, disconnected `2`;
- role: client peer `0`, server peer `1`;
- identity presence: known `0`, legacy unavailable `1`.

## 4. Portas e canais que não podem ser confundidos

| Canal | Porta/endpoint | Contrato |
|---|---:|---|
| controle de input | TCP/TLS `24800` | protocolo remoto 1.6 acima |
| daemon IPC atual | loopback TCP `24801` | IPC binário acima |
| pareamento | endpoint dedicado e efêmero | SRP/HKDF com M1/M2/M3; não reutilizar controle sem contrato explícito |
| transferência moderna | TLS-PSK `24810` | chave por dispositivo derivada do pareamento |
| futuro Unix IPC | UDS privado | permissões de arquivo + peer credentials |
| futuro Windows IPC | Named Pipe ACL privado | SID/session/process policy explícita |

## 5. Contratos criptográficos a congelar

O oracle/KAT de R0 deve registrar entradas e saídas determinísticas, sem incluir segredo real de usuário:

- UUID local e remoto de teste;
- relógio fixo;
- RNG determinístico de teste;
- salt/verifier e public values A/B;
- transcript canônico;
- provas M1, M2 e M3;
- chave de pareamento derivada por HKDF;
- chave TLS-PSK derivada por dispositivo/canal;
- adulteração de cada flight, replay entre sessões, expiração, rotação e revogação como falhas fechadas.

O KAT `src/gui/test/fixtures/pairing-srp6a-hkdf-v1.json` congela UUIDs/tempo/RNG sintéticos, salt, A/B, M1/M2/M3 e pair key exatos. O teste valida tipo/tamanho/hex canônico, hashes LF-canônicos dos oráculos, ordem das chamadas RNG e commit antes/depois de M3. Hoje `MainWindow.cpp:1509-1512` passa essa pair key diretamente ao `FileTransferService` como TLS-PSK efetiva; isso congela o comportamento C++ atual, não satisfaz a separação futura de subchaves exigida pelo threat model.

## 6. Matriz de fixtures do oracle C++

Cada fixture versionada deve carregar:

- `schema` do manifesto;
- nome e categoria normalizados;
- oracle e símbolo de origem;
- revisão/manifesto de source;
- plataforma, arquitetura, compilador e endianness;
- bytes exatos e SHA-256;
- entrada sem segredo e resultado esperado;
- indicação se é payload puro ou frame completo.

Cobertura mínima antes de iniciar R2:

1. todos os formatos primitivos de `ProtocolUtil`;
2. greeting 1.6 e versões incompatíveis;
3. cada ID remoto alcançável em pelo menos um frame aceito;
4. cada ID IPC em ambas as direções aplicáveis, executado tanto no `IpcFrameReader` core quanto no `IpcReader` GUI;
5. fragmentação em cada fronteira de comprimento/campo;
6. trailing data conforme direção, estado e consumidor, incluindo múltiplos comandos dentro do mesmo frame externo; enum inválido; string/lista/frame oversized;
7. KAT SRP/HKDF e testes negativos de transcript/replay;
8. round trip C++ e posterior comparação byte a byte Rust ↔ C++.

Primeiro conjunto determinístico mínimo:

1. hello 1.6 aceito;
2. hello-back 1.7 classificado conforme a direção;
3. prefixo remoto truncado;
4. comprimento remoto `4.194.305` oversized;
5. código remoto desconhecido;
6. `IHEL` GUI aceito;
7. `IHEL` sem tipo como need-more;
8. código IPC desconhecido;
9. `ILOG` com comprimento `1.048.577` oversized.

O emissor deve ser executado duas vezes e produzir diretórios, manifestos e hashes byte a byte idênticos.

O primeiro conjunto está versionado em `src/test/fixtures/rust-r0-wire`. O CTest compara duas emissões do ambiente corrente, valida semanticamente o manifesto frozen, compara os dez binários byte a byte, rejeita entradas extras e executa `r0-source-manifest.json --check`. Metadados de plataforma/compilador/revisão da execução não são confundidos com os bytes invariáveis do corpus.

## 7. Arquivos-oráculo

- `src/lib/inputleap/ProtocolUtil.{h,cpp}`
- `src/lib/inputleap/protocol_types.{h,cpp}`
- `src/lib/inputleap/PacketStreamFilter.{h,cpp}`
- `src/lib/ipc/Ipc.{h,cpp}`
- `src/lib/ipc/IpcMessage.{h,cpp}`
- `src/lib/ipc/IpcFrameReader.{h,cpp}`
- `src/lib/ipc/IpcClientProxy.cpp`
- `src/lib/ipc/IpcServerProxy.cpp`
- `src/lib/client/Client.cpp`
- `src/lib/client/ServerProxy.cpp`
- `src/lib/server/ClientProxy.cpp`
- `src/lib/server/ClientProxyUnknown.cpp`
- `src/lib/server/ClientProxy1_6.cpp`
- `src/lib/server/ClientConnectionByStream.cpp`
- `src/lib/inputleap/ClipboardChunk.cpp`
- `src/lib/inputleap/FileChunk.cpp`
- `src/gui/src/Ipc.{h,cpp}`
- `src/gui/src/IpcReader.{h,cpp}`
- `src/gui/src/IpcClient.{h,cpp}`
- `src/gui/src/PairingService.{h,cpp}`
- `src/gui/src/PairingProtocolCodec.{h,cpp}`
- `src/gui/src/FileTransferService.{h,cpp}`

Qualquer alteração posterior nesses arquivos invalida fixtures que não forem regeneradas e regated contra um novo source manifest.
