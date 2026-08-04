# Threat model da reescrita Rust/Tauri

**Estado:** Fase R0 em andamento  
**Regra principal:** compatibilidade de wire nunca autoriza downgrade silencioso de segurança.

## Escopo e ativos

Ativos protegidos:

- autoridade para capturar ou injetar mouse e teclado;
- identidade durável por dispositivo;
- pair root keys, PSKs, PINs, credenciais e material de assinatura;
- clipboard, arquivos transferidos, perfis e configurações;
- integridade do daemon, agente, nodes e helpers elevados;
- integridade, autenticidade e rollback de updates;
- disponibilidade sem loops, OOM, deadlock ou teclado preso.

## Fronteiras de confiança

1. **WebView Tauri → backend Rust:** apresentação não confiável para segredos ou comandos arbitrários.
2. **GUI → agente residente:** IPC local autenticado, schema limitado e papel derivado do SO.
3. **Agente → daemon/nodes/helpers:** identidade, sessão, caminho/hash e argumentos fixos.
4. **Host local → LAN:** rede é hostil mesmo em LAN privada.
5. **Descoberta → autorização:** Zeroconf/DNS-SD é consultivo e não autenticado.
6. **Pairing → canais reais:** a chave derivada só cria proteção quando um consumidor de tráfego a usa.
7. **Updater → helper elevado/instalador:** assinatura, origem, versão, hash, identidade e transação precisam permanecer ligados.
8. **Estado persistido → runtime:** arquivos/configurações podem estar truncados, corrompidos, repetidos ou substituídos por reparse points.

## Adversários considerados

- atacante LAN/MITM;
- peer pareado malicioso ou comprometido;
- processo local impostor com nome semelhante;
- processo da sessão/usuário errado;
- WebView comprometido/XSS;
- servidor de update comprometido;
- perda ou comprometimento de um signatário;
- replay de pairing, capability, transferência, update ou resultado de helper;
- interrupção de energia/crash entre validação e publicação;
- symlink, junction, reparse point e troca TOCTOU;
- estado local corrompido ou schema futuro;
- input flood para causar OOM, atraso, teclas presas ou eventos após revogação.

## Controles C++ atuais localizados

### Pairing

`src/gui/src/PairingService.cpp` implementa SRP-6a com grupo RFC 5054 de 2048 bits, SHA-256, limites de sessões/tentativas, M1/M2/M3, transcript canônico, HKDF e limpeza explícita.

`PairingController.cpp` é assimétrico: o convidado emite `paired` ao receber `success` e enviar `confirmed`, sem confirmação de entrega; o convidador emite `paired` ao receber `confirmed`. `success` e `confirmed` carregam somente `sessionId`, sem MAC próprio. Metadata posterior é autenticada com a pair key. Isso pode causar estado unilateral/desincronizado sob MITM, ainda que não permita derivar a chave SRP. A reescrita deve autenticar toda confirmação de estado com a chave/transcript.

O KAT R0 versionado congela salt, A/B, M1/M2/M3 e pair key sintéticos, com hashes canônicos dos oráculos e validação fail-closed. No consumidor C++ atual, `MainWindow.cpp:1509-1512` entrega a pair key diretamente ao `FileTransferService` como PSK por dispositivo. A compatibilidade Rust deverá reproduzir esse oracle para testes, mas o desenho final deve derivar subchave de transferência distinta antes do cutover.

### Transferência

`src/gui/src/MainWindow.cpp:1509-1512` entrega a chave por dispositivo ao `FileTransferService`. `src/gui/src/FileTransferService.cpp` usa TLS-PSK, identidade por UUID, chaves de contexto e exige versão autenticada nos fluxos modernos.

### Canal principal de controle — lacuna crítica

A pair key não é consumida por `input-leaps`/`input-leapc` no canal 24800. `src/lib/net/SecureSocket.cpp:357-405` solicita certificado em modo autenticado, mas usa callback que aceita a cadeia; a confiança efetiva continua dependente do mecanismo legado de certificado/fingerprint.

Consequência: a UI não pode afirmar que o pareamento protege mouse/teclado. O cutover Rust exige `control-channel-auth-v1`, derivado da pair root key, vinculado ao TLS exporter, UUIDs, papéis, nonces e capabilities. Nenhum frame de aplicação pode ser processado antes da confirmação mútua. Peer sem capability segura deve receber “Atualização necessária”, sem fallback.

Os bancos `TrustedServers.txt`/`TrustedClients.txt` são plaintext e o código não comprova MAC nem ACL da raiz. Um processo malicioso do mesmo usuário pode adulterar confiança TOFU. A persistência Rust deve ser autenticada, atômica e ancorada em storage protegido.

### IPC local

`src/lib/ipc/IpcPeerProcessAuth.cpp` no Windows valida loopback, PID, processo ainda vivo, creation time, caminho canônico ao lado do daemon, nome permitido, SID e sessão ativa. Fora do Windows, `peerProcessId()` retorna `nullopt`; o desenho final não pode depender desse caminho para Unix.

O controle atual classifica localização e nome do binário, mas não comprova assinatura/hash imutável nem verifica que a raiz de instalação possui ACL segura. Instalação em diretório gravável pelo usuário reduz essa fronteira a same-user trust.

Destino:

- Windows named pipe com DACL, token, SID, sessão, PID, creation time e handle vivo;
- Linux/macOS Unix socket privado em runtime dir, modo `0600`, peer credentials do kernel e sessão/seat;
- papel calculado pelo servidor, nunca aceito do payload;
- autorização revalidada antes de efeitos privilegiados.

### Segredos persistentes

`src/gui/src/SecureCredentialStore.cpp` usa Windows Credential Manager e falha fechado quando o backend/seam está incompleto. A migração deve usar Credential Manager/Keychain/Secret Service sem fallback plaintext. O WebView nunca recebe PSK, PIN, chave de pairing ou chave de update.

Credential Manager protege contra exposição simples em disco/outro usuário, não contra processo comprometido no mesmo logon que conheça os nomes dos alvos. Chaves de maior autoridade devem ser separadas por contexto e o modelo deve declarar explicitamente esse limite.

### Atualização

`src/gui/src/UpdateTrustConfig.cpp` contém três âncoras e `minimumValidSignatures = 2`. A migração preserva o helper elevado e exige validação em ordem: manifesto 2-de-3 → anti-replay/high-water mark → download temporário → hash → assinatura do pacote → identidade do helper → instalação transacional → resultado autenticado → promoção do high-water mark. Falha preserva estado para diagnóstico/rollback e nunca autoriza limpeza destrutiva por timeout.

Lacunas atuais que não podem ser herdadas:

- o helper reavalia assinatura, mas não aplica independentemente o high-water mark/replay store; um pacote antigo ainda assinado pode chegar ao helper por instrução substituída;
- em falha parcial de MSI, o fluxo relança o executável anterior se o hash conferir, mas não prova restauração de arquivos, Registry e serviço alterados;
- staging ainda possui operações check-then-path em `.part`, metadata e rename; a reescrita deve manter diretório/arquivo por handles validados até commit.

O caminho legado de transferência deriva PSK por SHA-256 direto do código aparado. Ele não é equivalente à chave SRP e não pode ser promovido nem usado como fallback silencioso.

## Matriz de ameaças e requisitos

| Ameaça | Caminho | Controle atual | Requisito Rust / estado |
|---|---|---|---|
| MITM no controle | LAN 24800 | TLS + fingerprint legado | pairing-derived mutual confirmation; **bloqueante** |
| MITM na transferência | LAN 24810 | TLS-PSK por UUID nos fluxos modernos | differential interop e sem downgrade |
| anúncio falso | DNS-SD | metadata consultiva | nunca autorizar por TXT/nome/IP |
| peer pareado malicioso | protocolo remoto | limites e permissões por UUID em serviços modernos | quotas, schemas, revalidação e revogação por canal |
| replay de pairing | pairing TCP | sessões, M1/M2/M3, expiração | KATs e testes de consumo único |
| processo local impostor | 24801 | identidade Windows forte | named pipe/UDS e identidade do kernel |
| sessão errada | serviço Windows | SID + sessão ativa | preservar e testar troca de sessão/PID reuse |
| WebView comprometido | commands Tauri | inexistente hoje | capabilities mínimas; sem shell/fs/network genéricos |
| input flood | 24800/hook | limites parciais | canais limitados; coalescer só movimento; teclas/botões nunca descartados silenciosamente |
| evento após revogação | callbacks assíncronos | controles por serviço | epoch/cancellation token e revalidação no consumidor |
| update server comprometido | feed/download | assinaturas e hash | 2-de-3, anti-rollback e pacote assinado |
| downgrade no helper | instrução GUI→helper | assinatura repetida sem HWM independente | helper valida replay/freshness antes de instalar |
| rollback MSI incompleto | instalação elevada | relançamento do binário anterior | restauração transacional de arquivos/Registry/serviço |
| TOFU adulterado same-user | banco de fingerprints | arquivos plaintext | storage autenticado + ACL verificada |
| confirmação pairing forjada | success/confirmed | sessionId sem MAC | confirmação ligada ao transcript e pair key |
| staging por junction race | `.part`/metadata/rename | checagens por pathname | operações handle-relative até publicação |
| um signatário perdido | assinatura | limiar 2-de-3 | custódia independente e rotação testada |
| helper falso | IPC/update | validações C++ existentes | parent/child identity, path/hash/signature e schema mínimo |
| power loss | config/update/transfer | transações em áreas modernas | journal autenticado, fsync/atomic replace e recuperação testada |
| symlink/junction/reparse | arquivos/update | guards existentes em áreas críticas | revalidar no sink por handle, não só pathname |
| corrupção/schema futuro | persistência | stores estritos em áreas modernas | fail-closed/read-only e bytes preservados |
| segredo no log/JS | UI/diagnóstico | sanitização parcial | tipos secretos não serializáveis; testes com sentinelas |
| rollback para legado | capability negotiation | varia por protocolo | capability autenticada; falha moderna é terminal |

## Invariantes obrigatórios

1. Descoberta nunca concede permissão.
2. Nome, IP e texto visível nunca substituem UUID autenticado.
3. Pairing só conta como proteção quando a chave autentica o canal consumidor.
4. A chave raiz gera subchaves independentes por contexto via HKDF.
5. Falha de capability moderna não tenta caminho legado.
6. Revogação invalida novas operações e callbacks já enfileirados.
7. Daemon/serviço nunca captura input na Session 0.
8. Hot path não passa por JavaScript ou filesystem.
9. Nenhum processo inicia comando arbitrário vindo do WebView.
10. Validação antes de prompt/fila é repetida imediatamente antes do efeito.
11. Resultado `Installing` é não terminal e nunca autoriza limpeza destrutiva.
12. C++ só é removido após soak atual, manifests congelados e paridade real por plataforma.

## Gates de aprovação do threat model

- revisão independente sem achado HIGH/MEDIUM aberto;
- KATs SRP/HKDF e controle-channel auth versionados;
- differential tests C++↔Rust para válidos e inválidos;
- fuzzing de codecs/state machines com budgets;
- IPC adversarial por SO, incluindo PID reuse, sessão errada e papel forjado;
- revogação durante input/transfer/update sem efeito posterior;
- updater com replay, power loss, helper falso e rollback real;
- nenhuma alegação de proteção na UI sem consumidor real comprovado.
