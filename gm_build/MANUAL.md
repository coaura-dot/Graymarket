# Manual de Operação — Gray Market Inject System

---

## Visão Geral

O servidor **GrayMarket** funciona como uma loja de itens Minecraft. Por dentro, carrega um sistema de injeção escondido acessível apenas via URL secreta. O Firefox no PC do jogador age como agente — faz polling silencioso, recebe o comando, baixa a DLL encriptada, mapeia direto na RAM do processo-alvo (sem tocar o disco), e reporta o resultado.

**Sem arquivo temporário. Sem entrada no USN Journal. Sem artefato NTFS.**

---

## Estrutura do Pacote

```
gm_build/
├── app.rb                        — Servidor principal (GrayMarket + inject)
├── config.ru / Gemfile / Rakefile — boilerplate Ruby
├── config/environment.rb
├── app/models/                   — modelos do GrayMarket
├── views/                        — templates HTML do GrayMarket
├── db/                           — schema e seeds do banco
├── dll/
│   └── Extreme_patched.dll       ← COLOQUE A DLL AQUI (não incluída)
├── firefox_autoconfig/
│   ├── autoconfig.js             — ativa o autoconfig no Firefox
│   └── firefox.cfg               — agente de injeção (privilegiado)
└── MANUAL.md                     — este arquivo
```

---

## PARTE 1 — Configurar o Servidor

### Opção A: Render.com (recomendado para internet, HTTPS automático)

1. **Criar conta** em render.com
2. **Novo Web Service** → conectar repositório GitHub privado com estes arquivos
3. **Configurações do serviço:**
   - Language: `Ruby`
   - Build Command: `bundle install`
   - Start Command: `bundle exec rackup config.ru -p $PORT -o 0.0.0.0`
4. **Variáveis de ambiente** (aba Environment):
   ```
   SESSION_SECRET   = (gerar string aleatória longa)
   OP_TOKEN         = (sua senha do painel — ex: Xk9mP3vQ7wL2nR5z)
   SINATRA_ENV      = production
   ```
5. Aguardar o deploy. A URL ficará no formato `https://seu-app.onrender.com`

> **Free tier**: servidor hiberna após 15 min sem requests. Use o UptimeRobot
> (uptimerobot.com, grátis) para pingar o servidor a cada 5 min e mantê-lo ativo.
> Paid tier ($7/mês): sempre on, sem hibernação.

### Opção B: Termux no celular (rede local — só se KellerGuard NÃO for ring-0)

```bash
pkg install ruby
gem install bundler
cd ~/gm_build
bundle install
OP_TOKEN="SuaSenhaAqui" bundle exec rackup config.ru -p 4567 -o 0.0.0.0
```

Acesse o painel em: `http://<ip-do-celular>:4567/__sys__/SuaSenhaAqui`

> **Atenção:** IP local (192.168.x.x) é detectável por KellerGuard via Sysmon
> Event ID 3. Para torneios, use sempre a Opção A (internet).

---

## PARTE 2 — Colocar a DLL no Servidor

1. Copie `Extreme_patched.dll` para a pasta `dll/` do projeto
2. Se usar Render: inclua o arquivo no repositório **privado** e redeploy
3. O servidor só serve a DLL encriptada — nunca em plaintext

---

## PARTE 3 — Configurar o Firefox no PC

### 3.1 — Editar `firefox.cfg`

Abrir `firefox_autoconfig/firefox.cfg` e alterar as primeiras linhas:

```javascript
var SERVER   = "https://seu-app.onrender.com"; // URL do servidor SEM barra final
var TARGET   = "HD-Player.exe";               // processo do BlueStacks
                                               // LDPlayer: "dnplayer.exe"
var POLL_MS  = 3500;                          // intervalo de polling (ms)
```

### 3.2 — Instalar os arquivos no Firefox

Localizar a pasta de instalação do Firefox:
- Padrão: `C:\Program Files\Mozilla Firefox\`

Copiar os arquivos:

| Arquivo fonte                    | Destino                                              |
|----------------------------------|------------------------------------------------------|
| `firefox_autoconfig/autoconfig.js` | `C:\Program Files\Mozilla Firefox\defaults\pref\autoconfig.js` |
| `firefox_autoconfig/firefox.cfg`   | `C:\Program Files\Mozilla Firefox\firefox.cfg`       |

> Se a pasta `defaults\pref\` não existir, criá-la.

### 3.3 — Verificar instalação

Abrir o Firefox. Não há mensagem de confirmação — o agente inicia silenciosamente
com o browser e começa a fazer polling.

Para confirmar que está funcionando: abrir o painel no celular e verificar se
"Agente (PC)" aparece como **● online** em até 10 segundos.

---

## PARTE 4 — Operação

### Painel de controle

Acessar no celular (ou qualquer browser):
```
https://seu-app.onrender.com/__sys__/SuaSenhaAqui
```

O painel mostra:
- **Agente (PC):** se o Firefox está conectado e respondendo heartbeat
- **DLL no servidor:** se `Extreme_patched.dll` está presente
- **Último evento:** timestamp e resultado da última injeção

### Fluxo de uso

```
1. Abrir o BlueStacks com Free Fire no lobby
2. Abrir o Firefox (agente inicia automaticamente)
3. Aguardar "Agente (PC): ● online" no painel (até 10s)
4. Pressionar ATIVAR no painel
5. Aguardar ~5-15 segundos — painel mostra "✓" no último evento
6. Entrar na partida
```

### Protocolo pré-telagem

**Antes de iniciar a sessão de telagem:**

1. Pressionar **PARAR AGENTE** no painel — Firefox recebe o sinal e para o polling
2. Fechar o Firefox
3. O Firefox NÃO aparece mais fazendo requests periódicos
4. Iniciar a telagem normalmente

> Se o Firefox estiver fechado antes do inject, o agente não estará presente
> para o telador. Os requests anteriores aparecem no histórico como acesso ao
> catálogo do GrayMarket (máscara configurada em `FAKE_URL`).

---

## PARTE 5 — Técnica de Injeção

### Por que não deixa rastro no USN Journal

O método anterior (LoadLibraryW) escrevia um arquivo `.tmp` em `%TEMP%` —
isso gerava entradas de `FILE_CREATE`, `DATA_EXTEND` e `FILE_DELETE` visíveis
no KellerTrace.

O sistema atual usa **manual PE mapping**:

1. DLL baixada como bytes na RAM do Firefox (sem tocar o disco)
2. Bytes decriptados via ChaCha20 (chave única por sessão)
3. PE parser lê headers, sections, imports e relocations do buffer
4. `VirtualAllocEx` aloca espaço no processo-alvo
5. `WriteProcessMemory` copia headers e cada section para o VA correto
6. Imports resolvidos: `GetProcAddress` no Firefox → endereço escrito no IAT do alvo
7. Relocations aplicadas (delta = base real − base preferida)
8. Permissões de memória ajustadas por section (`.text` → RX, `.data` → RW)
9. Shellcode trampoline (40 bytes) chama `DllMain(base, DLL_PROCESS_ATTACH, 0)`
10. Handle do processo fechado imediatamente

**Zero I/O de filesystem = zero entrada no USN Journal.**

### Module stomping

Quando uma DLL do sistema grande o suficiente está carregada no processo-alvo,
o sistema usa a região de memória dessa DLL (já marcada como `MEM_IMAGE`) em vez
de alocar memória privada. Isso elimina a assinatura de `MEM_PRIVATE + PAGE_EXECUTE_READ`
que scanners de memória procuram.

Se nenhuma DLL vítima adequada for encontrada, o sistema faz fallback para
alocação privada (ainda sem rastro no USN Journal).

### Encriptação ChaCha20

A DLL nunca trafega em plaintext. Para cada inject:
1. Servidor gera chave de 32 bytes + nonce de 12 bytes aleatórios
2. Encripta a DLL com ChaCha20
3. Envia bytes encriptados + chave/nonce em header HTTP (`X-Cache-Tag`)
4. Firefox decripta em memória antes do map

Bytes na rede e em disco são ruído estatístico — sem assinatura do cheat.

---

## PARTE 6 — Troubleshoot

### "Agente (PC): ○ offline"
- Firefox está fechado, ou `firefox.cfg` não está instalado corretamente
- Verificar se `autoconfig.js` está em `defaults/pref/` e `firefox.cfg` na raiz
- Reabrir o Firefox

### "DLL: ausente"
- `Extreme_patched.dll` não está em `dll/` ou o deploy não incluiu o arquivo
- Redeploy com a DLL no repositório

### Painel retorna 404
- URL ou token errado. O painel está em `/__sys__/<OP_TOKEN>` exatamente

### Inject retorna "✗ processo não encontrado"
- BlueStacks não está aberto, ou o nome do processo está diferente
- Verificar o nome correto em Task Manager e ajustar `TARGET` no `firefox.cfg`

### Inject retorna "✗ OpenProcess falhou"
- Firefox sem privilégios suficientes. Executar Firefox como Administrador uma vez
  para o inject (clic direito → Executar como administrador)

### "LoadLibrary returned NULL" (DLL antiga via loader.exe)
- Ver MANUAL original do Extreme para troubleshoot de dependências e bitness

---

## PARTE 7 — Render: configurar domínio custom (opcional)

Para que o Firefox apareça acessando `catalog.graymarket.gg` em vez de
`algo.onrender.com`:

1. Registrar domínio (Registro.br para .com.br, Namecheap para outros)
2. Render → Settings → Custom Domain → adicionar o domínio
3. Seguir instruções do Render para apontar o CNAME no DNS
4. Atualizar `SERVER` no `firefox.cfg` para o domínio custom

---

## Notas de Segurança Operacional

- O painel (`/__sys__/TOKEN`) não tem autenticação adicional além da URL secreta.
  Manter o `OP_TOKEN` confidencial e não usar um token previsível.
- O repositório GitHub **deve ser privado** (contém a DLL).
- Não deixar o Firefox aberto durante a telagem. Usar PARAR AGENTE antes.
- Após o inject, o handle do processo é fechado em < 1 segundo — janela
  mínima para detecção via scan de handles.

---

*Gray Market Inject System — build interno*
