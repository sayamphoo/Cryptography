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

#define CHUNK_SIZE 2048

RSA *load_private_key(const char *filename)
{
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL)
    {
        perror("Unable to open file");
        return NULL;
    }

    RSA *rsa = PEM_read_RSAPrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);

    if (rsa == NULL)
    {
        ERR_print_errors_fp(stderr);
    }

    return rsa;
}

FILE *open_file(const char *file_path, const char *mode)
{
    FILE *file = fopen(file_path, mode);
    if (file == NULL)
    {
        // handle_errors("Failed to open file");
    }
    return file;
}

void remove_extension(char *filename)
{
    char *dot = strrchr(filename, '.');
    if (dot != NULL)
    {
        *dot = '\0'; // ตัดส่วนที่เหลือหลังจุดทิ้ง
    }
}

void decrypt(char *path_file)
{
    RSA *key_pub = load_private_key("./key/private.pem");
    FILE *file_encrypt = open_file(path_file, "rb");
    int rsa_size = RSA_size(key_pub);
    unsigned char *decrypt = malloc(rsa_size);
    char *output_traget = malloc(strlen(path_file) + 1);
    strcpy(output_traget, path_file);
    remove_extension(output_traget);
    FILE *output_file = open_file(output_traget, "wb");

    char *buffer = (char *)malloc(CHUNK_SIZE);
    size_t byte_read;
    printf("%s\n",path_file);
    while ((byte_read = fread(buffer, 1, rsa_size, file_encrypt)) > 0)
    {
        int result = RSA_private_decrypt(
            byte_read,
            (unsigned char *)buffer,
            (unsigned char *)decrypt,
            key_pub,
            RSA_PKCS1_OAEP_PADDING);

        // printf("%s\n", path_file);
        fwrite(decrypt, 1, result, output_file);
    }

    free(buffer);
    free(decrypt);
    RSA_free(key_pub);
    fclose(file_encrypt);
    fclose(output_file);
    remove(path_file);
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
            char fullpath[1000];
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

            //
            if (S_ISREG(filestat.st_mode))
            {
                decrypt(fullpath);
            }
            else if (S_ISDIR(filestat.st_mode))
            {
                traget_walk(fullpath);
            }
        }
    }

    if (closedir(dir) == -1)
    {
        perror("closedir");
    }
}

void main()
{
    // decrypt();
    traget_walk("./traget");
}