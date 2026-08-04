# input-leap-agent

> Bootstrap inicial do agente Rust (R3 — shell read-only)

Escopo desta fase:

- criar processo `input-leap-agent` rastreável;
- expor status básico para o shell Tauri;
- manter estado em memória e sem efeitos de entrada/saída do SO ainda.

Implementação atual (placeholder de bootstrap):

- CLI sem argumentos: entra em loop de heartbeat e loga snapshots de status.
- `--status`: imprime snapshot atual e sai.

Observações:

- não controla entrada/saída real de teclado/mouse ainda;
- não substitui daemon C++.
- depende das decisões de IPC da Task 9 do plano Rust/Tauri.
