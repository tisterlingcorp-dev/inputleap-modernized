# R5 — contrato de segurança Rust

Status: TLS/mTLS, autenticação de controle, anti-replay e persistência da associação certificado ↔ `DeviceId` validados localmente; a integração produtiva do peer Rust e a validação E2E ficam registradas como trabalho posterior, pois esta entrega será transferida para validação em Linux e não dispõe de duas máquinas Windows.

## Objetivos

- Não aceitar controle, transferência ou atualização de um peer sem identidade autenticada.
- Falhar fechado em erro de certificado, replay, timeout, versão ou associação de identidade.
- Não transportar segredo de pareamento em texto claro.

## Transporte

- TCP é apenas transporte; toda sessão produtiva usa TLS 1.3.
- O cliente valida a cadeia do certificado do servidor contra uma CA/âncora configurada localmente.
- O servidor exige certificado de cliente (mTLS) para operações autenticadas.
- TLS 1.2 e versões inferiores são recusados.
- O socket é fechado após qualquer falha de handshake, certificado, framing ou autenticação.

## Identidade e pareamento

- `DeviceId` é a identidade lógica já persistida por `inputleap-types`.
- O pareamento associa `DeviceId` à chave pública/certificado do peer; a associação é persistida atomicamente.
- `PeerBindingStore` grava atomicamente linhas versionadas `v1` com `DeviceId` e SHA-256 do certificado apresentado.
- `receive_authenticated_control_with_bindings` exige que a identidade assinada e o fingerprint do certificado mTLS correspondam ao mesmo pareamento persistido.
- Certificado válido sem associação local não autoriza comandos.
- Revogação local tem precedência sobre qualquer certificado anteriormente pareado.
- A chave privada nunca é enviada ao peer nem registrada em logs.

## Handshake de controle

Após TLS, os peers trocam uma mensagem de controle versionada contendo:

- versão do contrato;
- `DeviceId`;
- nonce aleatório de 32 bytes;
- capacidades/protocolo suportados;
- assinatura da mensagem com a chave privada vinculada ao certificado.

Cada lado verifica a assinatura, a validade do certificado, a associação `DeviceId`/chave pública e a unicidade do nonce da sessão. Nonces usados não podem ser aceitos novamente na mesma janela de vida do processo.

## Autorização por operação

- Entrada/clipboard/transferência exigem sessão autenticada e dispositivo pareado não revogado.
- Update exige também versão monotônica, hash íntegro e autorização criptográfica do pacote por uma chave de assinatura de release confiável.
- Falha em qualquer política retorna erro local e não executa efeito parcial.

## Testes obrigatórios

1. certificado expirado, emitido por CA errada e hostname/SAN inválido;
2. peer sem certificado de cliente;
3. `DeviceId` não pareado, revogado ou associado a outra chave;
4. assinatura inválida e nonce repetido;
5. downgrade de TLS/contrato;
6. timeout e desconexão durante handshake, framing e commit;
7. replay de update e adulteração após persistência.

A implementação deve atualizar este documento somente quando os testes acima tiverem evidência executada; a existência deste contrato não é evidência de TLS implementado.
