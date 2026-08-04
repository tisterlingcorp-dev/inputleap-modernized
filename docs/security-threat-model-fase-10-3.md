# Fase 10.3 — ameaça e controles (PT-BR)

## Limites

Zeroconf/DNS-SD é somente descoberta. TXT, nome, UUID, portas e capacidades são
**não autenticados** e podem ser falsificados, repetidos ou usados para enumerar
máquinas. Nenhuma conexão, permissão ou transferência deve ser autorizada por TXT.
A autorização exige UUID autenticado e a chave de sessão do pareamento.

## Controles implementados

- `ProtocolSecurityPolicy` emite uma autorização HMAC-SHA-256 ligada ao UUID,
  endpoint resolvido e conjunto exato de capacidades negociadas.
- O token possui nonce aleatório de 128 bits, validade curta (máximo de 5 minutos)
  e é consumido uma única vez; replay, expiração, UUID/endereço incorretos e
  downgrade de capability são rejeitados.
- UUID nulo, chave diferente de 32 bytes e anúncios sem identidade continuam
  fail-closed. Nenhum segredo é publicado no Zeroconf.
- A negociação existente continua separando versões por capability; uma versão
  anunciada sem autenticação não autoriza recurso sensível.

## Riscos residuais

A confirmação do token precisa ser chamada no ponto final de cada operação de
rede (após o handshake autenticado e antes de efeitos). TXT pode continuar
causando ruído/enumeração de serviços, mas não concede acesso. A política não
substitui TLS-PSK nem o registro de dispositivos.

## English summary

Zeroconf is discovery-only and untrusted. Authorization is bound to the
authenticated UUID, resolved endpoint, exact capability set, a random nonce,
short expiry, and a 32-byte session key. Tokens are single-use, preventing
replay. Legacy/null identities and unauthenticated capability claims fail closed.
