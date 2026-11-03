# input-leap-agent

> Agente experimental legado X11; não é o worker Windows do piloto Rust.

Escopo desta fase:

- criar processo `input-leap-agent` rastreável;
- expor status básico para o shell Tauri;
- manter estado em memória e sem efeitos de entrada/saída do SO ainda.

Estado verificado em 2026-11-03:

- O caminho Unix implementa conexão TLS e eventos X11; exige argumentos de conexão e identidade.
- O caminho Windows retorna erro de plataforma não suportada.
- `--status` descreve disponibilidade experimental, não uma conexão de controle pronta.

Observações:

- não controla entrada/saída Windows em produção;
- não substitui daemon C++.
- depende das decisões de IPC da Task 9 do plano Rust/Tauri.
