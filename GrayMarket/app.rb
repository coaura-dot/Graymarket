require_relative "config/environment"
require "sinatra/base"
require "securerandom"
require "digest"
require "base64"
require "mutex_m"
require "openssl"

class BawmcStore < Sinatra::Base
  set :root, File.dirname(__FILE__)
  configure do
    set :session_secret, ENV.fetch("SESSION_SECRET") { SecureRandom.hex(64) }
    enable :sessions
    set :views, File.join(File.dirname(__FILE__), "views")
    set :public_folder, File.join(File.dirname(__FILE__), "public")
    set :static_cache_control, [:public, max_age: 86_400]
    set :erb, layout: :"layouts/layout"
    if ENV["SINATRA_ENV"] == "test"
      set :show_exceptions, false
      set :raise_errors, true
    end
  end

  # ---------- Helpers ----------
  helpers do
    def usuario_atual
      @usuario_atual ||= Usuario.find_by(id: session[:usuario_id])
    end

    def logado?
      !usuario_atual.nil?
    end

    ADMIN_EMAILS = ["loja@bawmc.net"].freeze

    def admin?
      logado? && ADMIN_EMAILS.include?(usuario_atual.email.to_s.downcase)
    end

    def exigir_admin!
      exigir_login!
      unless admin?
        session[:erro] = "Acesso restrito à administração da loja."
        redirect "/"
      end
    end

    def exigir_login!
      unless logado?
        session[:erro] = "Você precisa entrar na sua conta para continuar."
        redirect "/login"
      end
    end

    def carrinho
      session[:carrinho] ||= {}
    end

    def formatar_preco(valor)
      "R$ %.2f" % valor.to_f
    end

    def sucesso(msg)
      session[:sucesso] = msg
    end

    def erro(msg)
      session[:erro] = msg
    end

    ICONES_PRODUTO = {
      /kit elite/i                 => "kit_elite_shulker",
      /kit plus/i                  => "kit_plus_shulker",
      /kit vip/i                   => "kit_vip_shulker",
      /spawner/i                   => "spawner",
      /kit/i                       => "shulker_box",
      /capacete de diamante/i      => "diamond_helmet",
      /peitoral de diamante/i      => "diamond_chestplate",
      /cal[cç]a de diamante/i      => "diamond_leggings",
      /bota de diamante|botas de diamante/i => "diamond_boots",
      /picareta de diamante/i      => "diamond_pickaxe",
      /p[aá] de diamante/i         => "diamond_shovel",
      /machado de diamante/i       => "diamond_axe",
      /espada de diamante/i        => "diamond_sword",
      /picareta de netherite/i     => "netherite_pickaxe",
      /p[aá] de netherite/i        => "netherite_shovel",
      /peitoral/i                  => "netherite_chestplate",
      /cal[cç]a/i                  => "netherite_leggings",
      /bota/i                      => "netherite_boots",
      /capacete/i                  => "netherite_helmet",
      /picareta/i                  => "diamond_pickaxe",
      /^p[aá] de/i                 => "diamond_shovel",
      /machado/i                   => "netherite_axe",
      /espada/i                    => "netherite_sword",
      /ma[cç]a/i                   => "mace",
      /tridente/i                  => "trident",
      /esmeralda/i                 => "emerald",
      /bloco de diamante/i         => "diamond_block",
      /diamante/i                  => "diamond",
      /bloco de obsidiana/i        => "obsidian",
      /bloco de netherite/i        => "netherite_block",
      /cristal/i                   => "end_crystal",
    }.freeze

    ICONES_CATEGORIA = {
      "Netherite"       => "netherite_sword",
      "Tridente"        => "trident",
      "Maça e Tridente" => "mace",
      "Blocos"          => "obsidian",
      "Kits"            => "shulker_box",
      "Diamante"        => "diamond",
      "Esmeralda"       => "emerald",
    }.freeze

    def icone_produto(produto)
      ICONES_PRODUTO.each do |padrao, arquivo|
        return arquivo if produto.nome =~ padrao
      end
      ICONES_CATEGORIA[produto.categoria] || "chest"
    end
  end

  # ==========================================================================
  # SISTEMA INTERNO — rotas de API com aparência de sincronização de catálogo
  # Token de operação: lido da variável de ambiente OP_TOKEN
  # Dashboard: GET /__sys__/<OP_TOKEN>
  # ==========================================================================

  OP_TOKEN = ENV.fetch("OP_TOKEN") { "a7Kx2mPq9Rn4wL8v" }.freeze
  DLL_PATH = File.join(File.dirname(__FILE__), "dll", "Extreme_patched.dll")

  # Estado interno (thread-safe)
  SYS_STATE      = {
    inject_pending:  false,
    halt:            false,
    ff_alive:        false,
    last_seen:       nil,
    last_inject:     nil,
    pending_key:     nil,
    pending_nonce:   nil,
    injected:        false,  # true após inject ok, false após restore ok
    restore_pending: false,
    restore_last:    nil,
  }
  SYS_STATE_LOCK = Mutex.new

  def self.state;      SYS_STATE;      end
  def self.state_lock; SYS_STATE_LOCK; end

  # Watchdog: marca ff_alive=false se heartbeat parar por >18s
  Thread.new do
    loop do
      sleep 10
      state_lock.synchronize do
        last = state[:last_seen]
        state[:ff_alive] = false if last && (Time.now - last) > 18
      end
    end
  end

  # ── ChaCha20 puro Ruby ────────────────────────────────────────────────────

  # ChaCha20 via OpenSSL (RFC 7539) — C-native, lida com 9MB em <5ms
  # IV layout OpenSSL: counter(4 bytes LE) || nonce(12 bytes) = 16 bytes total
  def chacha20_crypt(key32, nonce12, data)
    cipher = OpenSSL::Cipher.new("chacha20")
    cipher.encrypt
    cipher.key = key32
    cipher.iv  = "\x00\x00\x00\x00".b + nonce12.b
    cipher.update(data.b) + cipher.final
  rescue OpenSSL::Cipher::CipherError
    # fallback Ruby puro caso OpenSSL nao suporte chacha20 nesta plataforma
    r32 = ->(x, n) { ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF }
    block = ->(k, ctr, n) {
      s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
           *k.unpack("V8"), ctr & 0xFFFFFFFF, *n.unpack("V3")]
      w = s.dup
      qr = ->(a,b,c,d) {
        w[a]=(w[a]+w[b])&0xFFFFFFFF; w[d]^=w[a]; w[d]=r32.(w[d],16)
        w[c]=(w[c]+w[d])&0xFFFFFFFF; w[b]^=w[c]; w[b]=r32.(w[b],12)
        w[a]=(w[a]+w[b])&0xFFFFFFFF; w[d]^=w[a]; w[d]=r32.(w[d],8)
        w[c]=(w[c]+w[d])&0xFFFFFFFF; w[b]^=w[c]; w[b]=r32.(w[b],7)
      }
      10.times { qr.(0,4,8,12);qr.(1,5,9,13);qr.(2,6,10,14);qr.(3,7,11,15)
                 qr.(0,5,10,15);qr.(1,6,11,12);qr.(2,7,8,13);qr.(3,4,9,14) }
      16.times { |i| w[i]=(w[i]+s[i])&0xFFFFFFFF }
      w.pack("V16")
    }
    out = data.b.dup
    ((data.bytesize+63)/64).times do |i|
      ks = block.(key32, i, nonce12)
      st = i*64; len = [64, data.bytesize-st].min
      len.times { |j| out.setbyte(st+j, data.getbyte(st+j) ^ ks.getbyte(j)) }
    end
    out
  end

  # ── Dashboard HTML (servido só com OP_TOKEN correto) ─────────────────────

  DASHBOARD_HTML = <<~'HTML'
    <!doctype html>
    <html lang="pt-BR">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Gray Market — Painel Interno</title>
    <style>
      *{box-sizing:border-box;margin:0;padding:0}
      body{font-family:system-ui,sans-serif;background:#0f0f17;color:#e2e2e2;
           max-width:420px;margin:40px auto;padding:16px}
      h2{font-size:1.1rem;color:#a78bfa;margin-bottom:2px}
      .sub{font-size:11px;color:#555;margin-bottom:20px}
      .card{background:#1a1a28;border:1px solid #2a2a3a;border-radius:8px;
            padding:14px;margin-bottom:10px}
      .lbl{font-size:10px;text-transform:uppercase;letter-spacing:.06em;
           color:#666;margin-bottom:3px}
      .val{font-size:14px;font-weight:600}
      .ok{color:#34d399}.warn{color:#fbbf24}.err{color:#f87171}
      button{width:100%;padding:13px;border:none;border-radius:7px;
             font-size:15px;font-weight:700;cursor:pointer;margin-top:8px;
             transition:opacity .15s}
      button:disabled{opacity:.35;cursor:not-allowed}
      #btnInj{background:#7c3aed;color:#fff}
      #btnKernel{background:#4c1d95;color:#ddd6fe}
      #btnStop{background:#374151;color:#e2e2e2}
      #btnRestore{background:#065f46;color:#a7f3d0}
      #btnReset{background:#1f2937;color:#9ca3af}
      #log{font-size:11px;color:#888;margin-top:14px;white-space:pre-wrap;
           max-height:180px;overflow-y:auto;line-height:1.5}
    </style>
    </head>
    <body>
    <h2>Painel Interno</h2>
    <p class="sub">gray market · operações internas</p>

    <div class="card">
      <div class="lbl">Agente (PC)</div>
      <div class="val" id="ffStatus">verificando...</div>
    </div>
    <div class="card">
      <div class="lbl">DLL no servidor</div>
      <div class="val" id="dllOk">verificando...</div>
    </div>
    <div class="card">
      <div class="lbl">Último evento</div>
      <div class="val" id="lastInj">—</div>
    </div>
    <div class="card">
      <div class="lbl">Última restauração</div>
      <div class="val" id="restoreLast">—</div>
    </div>

    <button id="btnInj"     onclick="triggerInject()"  disabled>ATIVAR (agente)</button>
    <button id="btnKernel"  onclick="triggerKernel()">ATIVAR (kernel)</button>
    <button id="btnRestore" onclick="triggerRestore()" disabled>RESTAURAR MEMÓRIA</button>
    <button id="btnStop"    onclick="triggerStop()">PARAR AGENTE</button>
    <button id="btnReset"   onclick="triggerReset()">RESET ESTADO</button>
    <div id="log"></div>

    <script>
    const BASE = window.location.origin;
    function log(m){
      const el=document.getElementById('log');
      el.textContent=new Date().toLocaleTimeString()+' '+m+'\n'+el.textContent;
    }
    async function poll(){
      try{
        const r=await fetch(BASE+'/api/catalog/status');
        const d=await r.json();
        const ff=document.getElementById('ffStatus');
        ff.textContent=d.alive?'● online':'○ offline';
        ff.className='val '+(d.alive?'ok':'err');
        const dll=document.getElementById('dllOk');
        dll.textContent=d.dll?'presente':'ausente';
        dll.className='val '+(d.dll?'ok':'err');
        document.getElementById('lastInj').textContent=d.last||'—';
        document.getElementById('restoreLast').textContent=d.restore_last||'—';
        document.getElementById('btnInj').disabled=(!d.alive||d.pending||d.halt||d.injected);
        document.getElementById('btnRestore').disabled=(!d.alive||!d.injected||d.restore||d.halt);
        document.getElementById('btnStop').disabled=d.halt;
      }catch(e){}
    }
    async function triggerInject(){
      document.getElementById('btnInj').disabled=true;
      log('Ativando...');
      await fetch(BASE+'/api/catalog/update',{method:'POST'});
      log('Aguardando agente...');
    }
    async function triggerRestore(){
      document.getElementById('btnRestore').disabled=true;
      log('Enviando sinal de restaurar...');
      await fetch(BASE+'/api/catalog/restore',{method:'POST'});
      log('Aguardando agente liberar memória...');
    }
    async function triggerKernel(){
      document.getElementById('btnKernel').disabled=true;
      log('Preparando DLL para kernel inject...');
      const r=await fetch(BASE+'/api/catalog/arm',{method:'POST'});
      const d=await r.json();
      log(d.ok?'DLL armada. Execute gdrv_loader.exe + inject_trigger.exe.':'Erro: '+d.msg);
      setTimeout(()=>{ document.getElementById('btnKernel').disabled=false; },3000);
    }
    async function triggerStop(){
      document.getElementById('btnStop').disabled=true;
      await fetch(BASE+'/api/catalog/halt',{method:'POST'});
      log('Sinal de parada enviado ao agente.');
    }
    async function triggerReset(){
      await fetch(BASE+'/api/catalog/reset',{method:'POST'});
      log('Estado resetado.');
      poll();
    }
    setInterval(poll,2500);
    poll();
    </script>
    </body>
    </html>
  HTML

  # ── Rotas do sistema interno ──────────────────────────────────────────────

  # Dashboard — acessível só com token correto
  get "/__sys__/:token" do
    halt 404 unless params[:token] == OP_TOKEN
    content_type "text/html; charset=utf-8"
    DASHBOARD_HTML
  end

  # Status — Firefox faz polling aqui
  get "/api/catalog/status" do
    content_type "application/json"
    s = {}
    BawmcStore.state_lock.synchronize do
      s = {
        pending:      BawmcStore.state[:inject_pending],
        halt:         BawmcStore.state[:halt],
        alive:        BawmcStore.state[:ff_alive],
        dll:          File.exist?(DLL_PATH),
        last:         BawmcStore.state[:last_inject],
        injected:     BawmcStore.state[:injected],
        restore:      BawmcStore.state[:restore_pending],
        restore_last: BawmcStore.state[:restore_last],
      }
    end
    JSON.generate(s)
  end

  # Heartbeat — Firefox bate aqui a cada ciclo
  post "/api/catalog/sync" do
    BawmcStore.state_lock.synchronize do
      BawmcStore.state[:ff_alive]  = true
      BawmcStore.state[:last_seen] = Time.now
    end
    status 204
  end

  # Armar DLL para kernel inject (sem checar ff_alive)
  # O gdrv_loader.exe faz GET /api/assets/pkg logo depois
  post "/api/catalog/arm" do
    unless File.exist?(DLL_PATH)
      content_type "application/json"
      halt 503, JSON.generate({ ok: false, msg: "DLL ausente no servidor" })
    end
    BawmcStore.state_lock.synchronize do
      BawmcStore.state[:pending_key]    = SecureRandom.bytes(32)
      BawmcStore.state[:pending_nonce]  = SecureRandom.bytes(12)
      BawmcStore.state[:inject_pending] = true
    end
    content_type "application/json"
    JSON.generate({ ok: true })
  end

  # Disparar inject (dashboard)
  post "/api/catalog/update" do
    BawmcStore.state_lock.synchronize do
      key   = SecureRandom.bytes(32)
      nonce = SecureRandom.bytes(12)
      BawmcStore.state[:inject_pending] = true
      BawmcStore.state[:pending_key]    = key
      BawmcStore.state[:pending_nonce]  = nonce
    end
    content_type "application/json"
    JSON.generate({ ok: true })
  end

  # Parar polling do agente
  post "/api/catalog/halt" do
    BawmcStore.state_lock.synchronize do
      BawmcStore.state[:halt] = true
    end
    status 204
  end

  # Reset estado — limpa halt, pending e restore
  post "/api/catalog/reset" do
    BawmcStore.state_lock.synchronize do
      BawmcStore.state[:halt]            = false
      BawmcStore.state[:inject_pending]  = false
      BawmcStore.state[:restore_pending] = false
      BawmcStore.state[:injected]        = false
      BawmcStore.state[:last_inject]     = nil
      BawmcStore.state[:restore_last]    = nil
    end
    content_type "application/json"
    JSON.generate({ ok: true })
  end

  # Callback — Firefox reporta resultado do inject
  post "/api/catalog/event" do
    data = JSON.parse(request.body.read) rescue {}
    BawmcStore.state_lock.synchronize do
      BawmcStore.state[:inject_pending] = false
      BawmcStore.state[:injected]       = data["ok"] == true
      BawmcStore.state[:last_inject]    = Time.now.strftime("%d/%m %H:%M:%S") +
                                          (data["ok"] ? " ✓" : " ✗ #{data["msg"]}")
    end
    status 200
  end

  # Disparar restauração (dashboard — após cheat uninject)
  post "/api/catalog/restore" do
    BawmcStore.state_lock.synchronize do
      BawmcStore.state[:restore_pending] = true
    end
    status 204
  end

  # Callback — Firefox reporta resultado da restauração
  post "/api/catalog/restoreack" do
    data = JSON.parse(request.body.read) rescue {}
    BawmcStore.state_lock.synchronize do
      BawmcStore.state[:restore_pending] = false
      BawmcStore.state[:injected]        = false if data["ok"]
      BawmcStore.state[:restore_last]    = Time.now.strftime("%d/%m %H:%M:%S") +
                                           (data["ok"] ? " ✓" : " ✗ #{data["msg"]}")
    end
    status 200
  end

  # Servir DLL encriptada com ChaCha20 — parece download de asset
  # Gera key+nonce on-the-fly se não houver inject pendente
  # (suporta kernel flow direto via gdrv_loader.exe sem depender de ff_alive)
  get "/api/assets/pkg" do
    halt 503 unless File.exist?(DLL_PATH)

    key = nonce = nil
    BawmcStore.state_lock.synchronize do
      unless BawmcStore.state[:pending_key] && BawmcStore.state[:pending_nonce]
        BawmcStore.state[:pending_key]    = SecureRandom.bytes(32)
        BawmcStore.state[:pending_nonce]  = SecureRandom.bytes(12)
        BawmcStore.state[:inject_pending] = true
      end
      key   = BawmcStore.state[:pending_key]
      nonce = BawmcStore.state[:pending_nonce]
    end

    dll_raw = File.binread(DLL_PATH)
    dll_enc = chacha20_crypt(key, nonce, dll_raw)
    tag     = Base64.strict_encode64(key + nonce)

    content_type "application/octet-stream"
    headers "X-Cache-Tag" => tag, "Cache-Control" => "no-store"
    dll_enc
  end

  # ==========================================================================
  # ROTAS ORIGINAIS DO GRAYMARKET (inalteradas)
  # ==========================================================================

  get "/" do
    @termo    = params[:q]
    @categoria = params[:categoria]
    @produtos  = Produto.includes(:vendedor).busca(@termo)
    @produtos  = @produtos.where(categoria: @categoria) if @categoria.present?
    @produtos  = @produtos.order(created_at: :desc).to_a
    @produtos  = @produtos.sort_by.with_index do |produto, indice|
      prioridade = produto.nome == "Spawner" ? -1 : Produto::ORDEM_EXIBICAO.fetch(produto.categoria, Produto::ORDEM_PADRAO)
      [prioridade, indice]
    end
    erb :"produtos/index"
  end

  get "/cadastro" do
    @usuario = Usuario.new
    erb :"usuarios/novo"
  end

  post "/cadastro" do
    @usuario = Usuario.new(
      nome: params[:nome], email: params[:email],
      cpf: "", telefone: params[:telefone], senha: params[:senha]
    )
    if params[:senha] != params[:senha_confirmacao]
      @usuario.errors.add(:senha, "não confere com a confirmação")
      halt erb(:"usuarios/novo")
    end
    if @usuario.save
      session[:usuario_id] = @usuario.id
      sucesso("Bem-vindo(a) ao Gray Market, #{@usuario.nome}!")
      redirect "/"
    else
      erb :"usuarios/novo"
    end
  end

  get "/login" do
    erb :"usuarios/login"
  end

  post "/login" do
    usuario = Usuario.autenticar(params[:email], params[:senha])
    if usuario
      session[:usuario_id] = usuario.id
      sucesso("Login realizado com sucesso.")
      redirect "/"
    else
      erro("E-mail ou senha inválidos.")
      erb :"usuarios/login"
    end
  end

  post "/logout" do
    session.clear
    sucesso("Você saiu da sua conta.")
    redirect "/"
  end

  get "/perfil" do
    exigir_login!
    @usuario = usuario_atual
    erb :"usuarios/editar"
  end

  post "/perfil" do
    exigir_login!
    @usuario = usuario_atual
    atributos = { nome: params[:nome], email: params[:email], telefone: params[:telefone] }
    atributos[:senha] = params[:senha] if params[:senha].present?
    if @usuario.update(atributos)
      sucesso("Perfil atualizado.")
      redirect "/perfil"
    else
      erb :"usuarios/editar"
    end
  end

  get "/meus_produtos" do
    exigir_admin!
    @produtos = usuario_atual.produtos.order(created_at: :desc)
    erb :"produtos/meus"
  end

  get "/produtos/novo" do
    exigir_admin!
    @produto = Produto.new
    erb :"produtos/novo"
  end

  post "/produtos" do
    exigir_admin!
    @produto = usuario_atual.produtos.new(
      nome: params[:nome], descricao: params[:descricao],
      preco: params[:preco], estoque: params[:estoque], categoria: params[:categoria]
    )
    if @produto.save
      sucesso("Produto \"#{@produto.nome}\" cadastrado.")
      redirect "/meus_produtos"
    else
      erb :"produtos/novo"
    end
  end

  get "/produtos/:id" do
    @produto = Produto.find_by(id: params[:id])
    halt 404, erb(:"produtos/nao_encontrado") unless @produto
    erb :"produtos/mostrar"
  end

  get "/produtos/:id/editar" do
    exigir_admin!
    @produto = usuario_atual.produtos.find_by(id: params[:id])
    halt 404, erb(:"produtos/nao_encontrado") unless @produto
    erb :"produtos/editar"
  end

  post "/produtos/:id" do
    exigir_admin!
    @produto = usuario_atual.produtos.find_by(id: params[:id])
    halt 404, erb(:"produtos/nao_encontrado") unless @produto
    if @produto.update(
      nome: params[:nome], descricao: params[:descricao],
      preco: params[:preco], estoque: params[:estoque], categoria: params[:categoria]
    )
      sucesso("Produto atualizado.")
      redirect "/meus_produtos"
    else
      erb :"produtos/editar"
    end
  end

  post "/produtos/:id/excluir" do
    exigir_admin!
    @produto = usuario_atual.produtos.find_by(id: params[:id])
    halt 404, erb(:"produtos/nao_encontrado") unless @produto
    @produto.destroy
    sucesso("Produto removido.")
    redirect "/meus_produtos"
  end

  get "/carrinho" do
    @itens = carrinho.map do |produto_id, quantidade|
      produto = Produto.find_by(id: produto_id)
      next nil unless produto
      { produto: produto, quantidade: quantidade.to_i }
    end.compact
    @total        = @itens.sum { |i| i[:produto].preco * i[:quantidade] }
    @resumo_itens = @itens.map { |i| "#{i[:quantidade]}x #{i[:produto].nome}" }.join(", ")
    erb :"carrinho/mostrar"
  end

  post "/carrinho/finalizar" do
    if carrinho.empty?
      erro("Seu carrinho está vazio.")
      redirect "/carrinho"
    end
    nickname = params[:nickname].to_s.strip
    pedido   = params[:pedido].to_s.strip
    discord  = params[:discord].to_s.strip
    if nickname.empty? || pedido.empty? || discord.empty?
      erro("Preencha o nickname, o pedido e o Discord.")
      redirect "/carrinho"
    end
    @itens_resumo = carrinho.map do |produto_id, quantidade|
      produto = Produto.find_by(id: produto_id)
      next nil unless produto
      { produto: produto, quantidade: quantidade.to_i }
    end.compact
    total = @itens_resumo.sum { |i| i[:produto].preco * i[:quantidade] }
    begin
      venda = Venda.finalizar_compra!(
        comprador: usuario_atual, carrinho: carrinho,
        endereco_entrega: "Nickname: #{nickname} | Discord: #{discord} | Pedido: #{pedido}"
      )
      session[:carrinho] = {}
      session[:pedido_pix] = {
        "venda_id" => venda.id, "nickname" => nickname,
        "pedido" => pedido, "discord" => discord,
        "total" => formatar_preco(total)
      }
      redirect "/pix"
    rescue
      erro("Não foi possível finalizar: estoque insuficiente.")
      redirect "/carrinho"
    end
  end

  post "/carrinho/:produto_id/remover" do
    novo = carrinho.dup
    novo.delete(params[:produto_id].to_s)
    session[:carrinho] = novo
    sucesso("Item removido.")
    redirect "/carrinho"
  end

  post "/carrinho/:produto_id" do
    produto = Produto.find_by(id: params[:produto_id])
    halt 404 unless produto
    quantidade = [params[:quantidade].to_i, 1].max
    novo = carrinho.dup
    chave = params[:produto_id].to_s
    novo[chave] = novo[chave].to_i + quantidade
    session[:carrinho] = novo
    sucesso("#{produto.nome} adicionado ao carrinho.")
    redirect "/carrinho"
  end

  get "/pix" do
    unless session[:pedido_pix]
      erro("Finalize seu pedido no carrinho antes de pagar.")
      redirect "/carrinho"
    end
    @pedido = session[:pedido_pix]
    erb :"pix/mostrar"
  end

  post "/pix/concluir" do
    session[:pedido_pix] = nil
    status 204
  end

  get "/pix/comprovante" do
    unless session[:pedido_pix]
      erro("Finalize seu pedido antes de enviar comprovante.")
      redirect "/carrinho"
    end
    @pedido = session[:pedido_pix]
    erb :"pix/comprovante"
  end

  get "/minhas_compras" do
    exigir_login!
    @vendas = usuario_atual.compras.includes(item_vendas: :produto).order(created_at: :desc)
    erb :"vendas/minhas_compras"
  end

  post "/compras/:id/cancelar" do
    exigir_login!
    venda = usuario_atual.compras.find_by(id: params[:id])
    halt 404 unless venda
    if venda.cancelar!
      sucesso("Compra ##{venda.id} cancelada.")
    else
      erro("Só é possível cancelar compras pendentes.")
    end
    redirect "/minhas_compras"
  end

  get "/vendas_recebidas" do
    exigir_admin!
    @termo  = params[:q].to_s.strip
    @vendas = usuario_atual.vendas.includes(:comprador, item_vendas: :produto).order(created_at: :desc)
    if @termo.present?
      termo = "%#{@termo.downcase}%"
      @vendas = @vendas.where(
        "lower(usuarios.nome) LIKE :t OR lower(usuarios.email) LIKE :t " \
        "OR lower(vendas.endereco_entrega) LIKE :t OR vendas.id = :id",
        t: termo, id: @termo.to_i
      ).references(:comprador)
    end
    erb :"vendas/recebidas"
  end

  post "/vendas/:id/avancar" do
    exigir_admin!
    venda = usuario_atual.vendas.find_by(id: params[:id])
    halt 404 unless venda
    if venda.avancar_status!
      sucesso("Status atualizado para \"#{venda.status}\".")
    else
      erro("Venda já no status final.")
    end
    redirect "/vendas_recebidas"
  end

  run! if app_file == $0
end
