# Checklist de validação de release

Este checklist separa o que pode ser verificado localmente do que exige custódia de produção, assinatura e feed externo. Um artefato não deve ser anunciado como release enquanto qualquer gate obrigatório estiver pendente.

## 1. Congelamento e build

- [ ] Confirmar branch e revisão exatas.
- [ ] Confirmar que não existem processos InputLeap antigos usando os artefatos.
- [ ] Reconfigurar o preset Release em diretório limpo:

```bat
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cmake --fresh --preset windows-msvc-main
cmake --build out\build\windows-msvc-main --target input-leap input-leapc input-leaps input-leapd --parallel 2
```

- [ ] Verificar `git diff --check`.
- [ ] Verificar versão embutida e notas de release.
- [ ] Verificar que `qtDeploy` contém as DLLs/plugins necessários.

## 2. Testes

- [ ] Executar CTest Release com o PATH do Qt configurado.
- [ ] Executar os testes funcionais de transferência, IPC, descoberta e atualização.
- [ ] Registrar logs fora de `out/` quando o script de limpeza puder remover os artefatos.
- [ ] Reexecutar os gates depois de qualquer alteração no código-fonte congelado.

## 3. Pacote e hash

- [ ] Gerar o instalador com WiX/Inno em ambiente de release.
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

O ambiente de desenvolvimento pode verificar build, versão, deployment Qt, testes e hashes. Certificado Authenticode de produção, ferramentas de empacotamento instaladas, custódia 2-de-3 e feed HTTPS de produção são dependências externas; na ausência deles, o resultado correto é **bloqueado**, não um PASS parcial apresentado como release.
