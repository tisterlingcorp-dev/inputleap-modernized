# Checklist de validação de release

Este checklist separa o que pode ser verificado localmente do que exige custódia de produção, assinatura e feed externo. Um artefato não deve ser anunciado como release enquanto qualquer gate obrigatório estiver pendente.

## 1. Congelamento e build

- [ ] Confirmar branch e revisão exatas.
- [ ] Confirmar que não existem processos InputLeap antigos usando os artefatos.
- [ ] Reconfigurar o preset Release em diretório limpo:

```bat
$env:B_BUILD_TYPE = 'Release'
.\clean_build.ps1
```

O artefato Inno Setup deve estar em `build\installer-inno\bin\InputLeapSetup-*.exe`. O CI de push usa Debug; para compilar o instalador no Actions, executar manualmente `Build tests` com `build_release=true` e `include_legacy_platforms=false`.

- [ ] Verificar `git diff --check`.
- [ ] Verificar versão embutida e notas de release.
- [ ] Verificar que `qtDeploy` contém as DLLs/plugins necessários.

## 2. Testes

- [ ] Confirmar que o gate Build tests no SHA candidato concluiu com sucesso no job Windows Qt6.
- [ ] Executar CTest Release com o PATH do Qt configurado.
- [ ] Executar os testes funcionais de transferência, IPC, descoberta e atualização.
- [ ] Validar o canal TLS legado 24800: certificado ausente, ASN.1/data inválida, ainda não válido, expirado, fingerprint não confiável e revogado devem falhar antes de qualquer evento de input; certificado vigente e explicitamente confiável deve conectar. Confirmar log acionável e que rotação de identidade exige novo pareamento explícito (nunca regenerar silenciosamente e invalidar peers existentes).
- [ ] Em VM Windows 10 e Windows 11 limpas, validar instalação, reinstalação/upgrade, reparo, desinstalação e rollback da versão anterior; confirmar serviço, firewall e preservação de `%ProgramData%\InputLeap` e `%LOCALAPPDATA%\InputLeap`. O candidato atual inclui runtime DNS-SD compilado da revisão mDNSResponder pinada (DLL e serviço `mDNSResponder.exe`); validar discovery com esse pacote e a rota manual sem DNS-SD. Não incluir o instalador proprietário Apple Bonjour. A distribuição pública do runtime compilado continua bloqueada até revisão/aprovação legal e de redistribuição dos arquivos e do nome de serviço.
- [ ] Registrar logs fora de `out/` quando o script de limpeza puder remover os artefatos.
- [ ] Reexecutar os gates depois de qualquer alteração no código-fonte congelado.

## 3. Pacote e hash

- [ ] Gerar o instalador Inno em ambiente de release.
- [ ] Gerar e arquivar os cinco SBOMs CycloneDX do workflow Release: pacote Windows instalado, workspace Rust, Tauri, agente e servidor. O Syft deve analisar diretórios contendo manifests/lockfiles; confirmar PURLs e relações transitivas nos quatro inventários Rust e revisar manualmente componentes redistribuídos que não sejam descobertos por manifests (incluindo Qt, OpenSSL, Bonjour/DNS-SD e DLLs do pacote).
- [ ] Confirmar que cada DLL/plugin Qt do `licenses/Qt/DEPLOYED-PAYLOAD.json` aparece como componente `file` no SBOM Windows, com SHA-256 igual ao manifesto. Este é um gate de cobertura/integridade do inventário, não uma atribuição automática de licença nem aprovação legal.
- [ ] Calcular SHA-256 a partir do pacote final, depois de todas as cópias.
- [ ] Confirmar tamanho, caminho e identidade do arquivo por descriptor/handle.
- [ ] Comparar versão, URL, tamanho e hash por canal independente.

## 4. Assinatura Authenticode

- [ ] Assinar executáveis e instalador com o certificado de produção autorizado.
- [ ] Verificar cada assinatura com o `signtool.exe` do Windows SDK:

```bat
signtool verify /pa /v <artefato-final>
```

- [ ] Confirmar cadeia, timestamp e política de confiança.
- [ ] Não substituir assinatura ausente por hash: hash e assinatura são gates diferentes.

## 5. Manifesto/feed seguro

- [ ] Cada um dos três custodiantes produzir sua contribuição independente.
- [ ] Montar o manifesto somente com pelo menos duas assinaturas de chaves distintas.
- [ ] Executar os testes do verificador C++ e do signer Python.
- [ ] Publicar somente após o pacote, hash, assinatura e manifesto estarem congelados.
- [ ] Validar URL HTTPS final, status 200, MIME, conteúdo, hashes e assinaturas a partir de uma build limpa sem credenciais de desenvolvimento.

Os comandos detalhados de custódia e montagem estão em `doc/secure-update-signing.md`. Chaves privadas, tokens, senhas e perfis de custódia nunca devem ser armazenados neste repositório.

## 6. Estado atual conhecido

O workflow Windows inclui um smoke de instalação, reinstalação/repair, início do serviço, desinstalação e preservação de um marcador em `%ProgramData%`. O candidato atual instala o runtime DNS-SD compilado de mDNSResponder; o smoke confirma DLL, serviço e avisos/proveniência e rejeita os instaladores proprietários `Bonjour.msi`/`Bonjour64.msi`. Isso é apenas um gate de conteúdo e ciclo de vida, não valida discovery real nem a rota manual sem DNS-SD, e tampouco aprova legalmente a redistribuição do runtime compilado. Quando `upgrade_from_run_id` é informado, valida também instalação do baseline, upgrade para o candidato (incluindo mudança do hash do daemon), reinstalação do candidato, desinstalação e rollback reinstalando o baseline. Esses testes automatizados não simulam interrupção/falha no meio da atualização e não substituem validação em VM limpa Windows 10/11, reparo via interface do Windows Installer, piloto em duas máquinas, nem revisão manual de licenças e cobertura do SBOM. Em particular, a geração do SBOM do diretório instalado não resolve a proveniência/licença dos binários DNS-SD nem prova que todas as DLLs redistribuídas foram catalogadas. Também não substitui assinatura Authenticode. Sem evidência desses gates, o resultado correto é **pendente**, não um PASS parcial apresentado como release.
