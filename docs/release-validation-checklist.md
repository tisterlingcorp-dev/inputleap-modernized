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
- [ ] Em VM Windows 10 e Windows 11 limpas, validar instalação, reinstalação/upgrade, reparo, desinstalação e rollback da versão anterior; confirmar serviço, firewall e preservação de `%ProgramData%\InputLeap` e `%LOCALAPPDATA%\InputLeap`.
- [ ] Registrar logs fora de `out/` quando o script de limpeza puder remover os artefatos.
- [ ] Reexecutar os gates depois de qualquer alteração no código-fonte congelado.

## 3. Pacote e hash

- [ ] Gerar o instalador Inno em ambiente de release.
- [ ] Gerar SBOM CycloneDX do diretório instalado e dos quatro lockfiles Rust; confirmar PURLs e relações transitivas nos inventários de dependências.
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

O workflow Windows inclui um smoke de instalação, reinstalação/repair, início do serviço, desinstalação e preservação de um marcador em `%ProgramData%`. Quando `upgrade_from_run_id` é informado, valida também instalação do baseline, upgrade para o candidato (incluindo mudança do hash do daemon), reinstalação do candidato, desinstalação e rollback reinstalando o baseline. Isso ainda não simula interrupção/falha no meio da atualização e não substitui validação em VM limpa Windows 10/11, reparo via interface do Windows Installer, piloto em duas máquinas, nem revisão de licenças/SBOM/hash/assinatura. Sem evidência desses gates, o resultado correto é **pendente**, não um PASS parcial apresentado como release.
