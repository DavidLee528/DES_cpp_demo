/**
 * @file des.hpp
 * @author David Lee (13121515269@163.com)
 * @brief 
 * @version 0.1
 * @date 2022-03-31
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#ifndef _DES_HPP
#define _DES_HPP

/**
 * @brief Parameter actions 
 */
#define     ACTION_GENERATE_KEY     "-k"
#define     ACTION_ENCRYPT          "-e"
#define     ACTION_DECRYPT          "-d"

/**
 * @brief key set type define
 */
typedef struct {
	unsigned char k[8];
	unsigned char c[4];
	unsigned char d[4];
} key_set;


class DES {
public: 
    /**
     * @brief Construct a new DES object
     *        Invoke this version of constructer to generate
     *        key, expect a parameter of "-k". 
     * 
     * @param action expect "-k" only
     * @param filename the path of output file
     */
    DES(const char *action, const char *filename); 

    /**
     * @brief Construct a new DES object
     *        Invoke this version of constructer to encrypt or 
     *        decrypt message after generating the key. In the 
     *        other word, use parameter "-k" before "-e"/"-d" 
     *        in your command line. 
     * 
     * @param action expect "-e" or "-k"
     * @param key the path of key file
     * @param input the path of input file (in encrypt mode, it is plaintext)
     * @param output the path of output file (in encrypt mode, it is ciphertext)
     */
    DES(const char *action, const char *key, const char *input, const char *output); 

    /**
     * @brief We use singleton design pattern
     */
    DES(const DES &no_way_to_copy) = delete; 

    /**
     * @brief Destroy the DES object
     */
    ~DES() = default; 

private: 
    inline void print_char_as_binary(char ch); 
    void print_key_set(key_set ks); 

    void generate_key(unsigned char *key); 
    void generate_sub_keys(unsigned char* main_key, key_set* key_sets);
    void process_message(unsigned char* message_piece, unsigned char* processed_piece, key_set* key_sets, int mode);

    void error_log(const std::string &err_msg); 
}; 

#endif /* _DES_HPP */