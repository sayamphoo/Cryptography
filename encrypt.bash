out=encrypt_file

gcc -o $out encrypt.c -lssl -lcrypto
./encrypt_file
rm -rf ./$out