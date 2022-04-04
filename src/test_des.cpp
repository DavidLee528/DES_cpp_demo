#include <iostream>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include "des.hpp"

int main(int argc, const char **argv) {
    /**
     * @brief show usage
     */
    if (argc < 2) {
        printf("Usage: %s [option]\n", argv[0]); 
        printf("  Options: \n"); 
        printf("  -k <filename>                         -- Generate key\n"); 
        printf("  -e <keyfile> <plaintext> <ciphertext> -- Encrypt a string message or a text file\n"); 
        printf("  -d <keyfile> <ciphertext> <plaintext> -- Decrypt a string message or a text file\n"); 
        return 1; 
    }

    /**
     * @brief Generate key
     */
    if (strcmp(argv[1], "-k") == 0 && argc == 3) {
        DES *des = new DES(argv[1], argv[2]); 
        return 0; 
    }

    /**
     * @brief Encrypt
     */
    if (strcmp(argv[1], "-e") == 0 && argc == 5) {
        DES *des = new DES(argv[1], argv[2], argv[3], argv[4]); 
        return 0; 
    }

    /**
     * @brief Decrypt
     */
    if (strcmp(argv[1], "-d") == 0 && argc == 5) {
        DES *des = new DES(argv[1], argv[2], argv[3], argv[4]); 
        return 0; 
    }

    printf("> Check parameter and try again. "); 

    return 0; 
}