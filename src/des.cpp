/**
 * @file des.cpp
 * @author David Lee (13121515269@163.com)
 * @brief 
 * @version 0.1
 * @date 2022-03-31
 * 
 * @copyright Copyright (c) 2022
 * 
 */

#include <iostream>
#include <fstream>
#include <string>
#include <cstring>

#include "des.hpp"

/**
 * @brief DES key is 8 bytes long
 */
#define     DES_KEY_SIZE            8

/**
 * @brief Operation mode
 */
#define     ENCRYPTION_MODE         1
#define     DECRYPTION_MODE         0


/**
 * @brief tables
 */

static const int initial_key_permutaion[] = {57, 49,  41, 33,  25,  17,  9,
								              1, 58,  50, 42,  34,  26, 18,
								             10,  2,  59, 51,  43,  35, 27,
								             19, 11,   3, 60,  52,  44, 36,
								             63, 55,  47, 39,  31,  23, 15,
								              7, 62,  54, 46,  38,  30, 22,
								             14,  6,  61, 53,  45,  37, 29,
								             21, 13,   5, 28,  20,  12,  4};

static const int initial_message_permutation[] = {58, 50, 42, 34, 26, 18, 10, 2,
                                                  60, 52, 44, 36, 28, 20, 12, 4,
                                                  62, 54, 46, 38, 30, 22, 14, 6,
                                                  64, 56, 48, 40, 32, 24, 16, 8,
                                                  57, 49, 41, 33, 25, 17,  9, 1,
                                                  59, 51, 43, 35, 27, 19, 11, 3,
                                                  61, 53, 45, 37, 29, 21, 13, 5,
                                                  63, 55, 47, 39, 31, 23, 15, 7};

static const int key_shift_sizes[] = {-1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

static const int sub_key_permutation[] = {14, 17, 11, 24,  1,  5,
                                           3, 28, 15,  6, 21, 10,
                                          23, 19, 12,  4, 26,  8,
                                          16,  7, 27, 20, 13,  2,
                                          41, 52, 31, 37, 47, 55,
                                          30, 40, 51, 45, 33, 48,
                                          44, 49, 39, 56, 34, 53,
                                          46, 42, 50, 36, 29, 32};

static const int message_expansion[] =  {32,  1,  2,  3,  4,  5,
                                          4,  5,  6,  7,  8,  9,
                                          8,  9, 10, 11, 12, 13,
                                         12, 13, 14, 15, 16, 17,
                                         16, 17, 18, 19, 20, 21,
                                         20, 21, 22, 23, 24, 25,
                                         24, 25, 26, 27, 28, 29,
                                         28, 29, 30, 31, 32,  1};

static const int S1[] = {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
                          0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
                          4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
                         15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13};

static const int S2[] = {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
                          3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
                          0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
                         13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9};

static const int S3[] = {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
                         13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
                         13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
                          1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12};

static const int S4[] = { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
                         13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
                         10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
                          3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14};

static const int S5[] = { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
                         14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
                          4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
                         11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3};

static const int S6[] = {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
                         10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
                          9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
                          4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13};

static const int S7[] = { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
                         13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
                          1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
                          6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12};

static const int S8[] = {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
                          1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
                          7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
                          2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11};

static const int right_sub_message_permutation[] = {16,  7, 20, 21,
                                                    29, 12, 28, 17,
                                                     1, 15, 23, 26,
                                                     5, 18, 31, 10,
                                                     2,  8, 24, 14,
                                                    32, 27,  3,  9,
                                                    19, 13, 30,  6,
                                                    22, 11,  4, 25};

static const int final_message_permutation[] = {40,  8, 48, 16, 56, 24, 64, 32,
                                                39,  7, 47, 15, 55, 23, 63, 31,
                                                38,  6, 46, 14, 54, 22, 62, 30,
                                                37,  5, 45, 13, 53, 21, 61, 29,
                                                36,  4, 44, 12, 52, 20, 60, 28,
                                                35,  3, 43, 11, 51, 19, 59, 27,
                                                34,  2, 42, 10, 50, 18, 58, 26,
                                                33,  1, 41,  9, 49, 17, 57, 25};

/**
 * @brief Construct a new DES object
 *        Invoke this version of constructer to generate
 *        key, expect a parameter of "-k". 
 * 
 * @param action expect "-k" only
 * @param filename 
 */
DES::DES(const char *action, const char *filename) {
	// Check parameter action
	if (strcmp(action, ACTION_GENERATE_KEY) != 0) {
		DES::error_log("> Wrong parameter, expect \"-k\". "); 
		exit(1); 
	}

	// Open file with write mode and empty the file
	std::ofstream key_file(filename, std::ofstream::out | std::ostream::trunc); 
	if (!key_file.is_open()) {
		DES::error_log("> Could not open file to write key. "); 
		exit(1); 
	}

	// Initialize random module
	unsigned int iseed = (unsigned int)time(NULL); 
	srand(iseed); 

	// Generate key
	unsigned char *des_key = (unsigned char*)malloc(8 * sizeof(char));
	generate_key(des_key);

	// Write key into key file
	key_file << des_key; 

	// Release memory
	free(des_key); 
	key_file.close(); 
}

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
DES::DES(const char *action, const char *key, const char *input, const char *output) {
	// Declare file handlers
	static FILE *key_file, *input_file, *output_file;

	// Read key file
	key_file = fopen(key, "rb");
	if (!key_file) {
		printf("Could not open key file to read key.");
		exit(1);
	}

	short int bytes_read;
	unsigned char* des_key = (unsigned char*) malloc(8 * sizeof(char));
	bytes_read = fread(des_key, sizeof(unsigned char), DES_KEY_SIZE, key_file);
	if (bytes_read != DES_KEY_SIZE) {
		printf("Key read from key file does nto have valid key size.");
		fclose(key_file);
		exit(1); 
	}
	fclose(key_file);

	// Open input file
	input_file = fopen(input, "rb");
	if (!input_file) {
		printf("Could not open input file to read data.");
		exit(1);
	}

	// Open output file
	output_file = fopen(output, "wb");
	if (!output_file) {
		printf("Could not open output file to write data.");
		exit(1);
	}

	// Generate DES key set
	short int bytes_written, process_mode;
	unsigned long block_count = 0, number_of_blocks;
	unsigned char* data_block = (unsigned char*) malloc(8 * sizeof(char));
	unsigned char* processed_block = (unsigned char*) malloc(8 * sizeof(char));
	key_set* key_sets = (key_set*)malloc(17 * sizeof(key_set));

	clock_t start, finish;
	double time_taken;
	start = clock();
	generate_sub_keys(des_key, key_sets);
	finish = clock();
	time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;

	// Determine process mode
	if (strcmp(action, ACTION_ENCRYPT) == 0) {
		process_mode = ENCRYPTION_MODE;
		printf("Encrypting..\n");
	} else {
		process_mode = DECRYPTION_MODE;
		printf("Decrypting..\n");
	}

	// Get number of blocks in the file
	fseek(input_file, 0L, SEEK_END);
	unsigned long file_size = ftell(input_file);

	fseek(input_file, 0L, SEEK_SET);
	number_of_blocks = file_size/8 + ((file_size%8)?1:0);

	start = clock();

	// Start reading input file, process and write to output file
	unsigned short padding; 
	while(fread(data_block, 1, 8, input_file)) {
		block_count++;
		if (block_count == number_of_blocks) {
			if (process_mode == ENCRYPTION_MODE) {
				padding = 8 - file_size % 8;
				if (padding < 8) { // Fill empty data block bytes with padding
					memset((data_block + 8 - padding), (unsigned char)padding, padding);
				}

				process_message(data_block, processed_block, key_sets, process_mode);
				bytes_written = fwrite(processed_block, 1, 8, output_file);

				if (padding == 8) { // Write an extra block for padding
					memset(data_block, (unsigned char)padding, 8);
					process_message(data_block, processed_block, key_sets, process_mode);
					bytes_written = fwrite(processed_block, 1, 8, output_file);
				}
			} else {
				process_message(data_block, processed_block, key_sets, process_mode);
				padding = processed_block[7];

				if (padding < 8) {
					bytes_written = fwrite(processed_block, 1, 8 - padding, output_file);
				}
			}
		} else {
			process_message(data_block, processed_block, key_sets, process_mode);
			bytes_written = fwrite(processed_block, 1, 8, output_file);
		}
		memset(data_block, 0, 8);
	}

	finish = clock();

	// Free up memory
	free(des_key);
	free(data_block);
	free(processed_block);
	fclose(input_file);
	fclose(output_file);

	// Provide feedback
	time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;
	printf("Finished processing %s. Time taken: %lf seconds.\n", input, time_taken);
}

/**
 * @brief 
 * 
 * @param ch 
 */
inline void DES::print_char_as_binary(char ch) {
    for (size_t i = 0; i < 8; ++i) {
        char shift = 0x01 << (7 - i); 
        if (shift & ch) printf("1"); 
        else printf("0"); 
    }
}

/**
 * @brief ***Use TRNG instead of rand()***
 * 
 * @param key 
 */
void DES::generate_key(unsigned char *key) {
    for (size_t i = 0; i < 8; ++i) {
        key[i] = rand() % 255; 
    }
}

/**
 * @brief 
 * 
 * @param ks 
 */
void DES::print_key_set(key_set ks) {
	printf("K: \n");
	for (size_t i = 0; i < 8; ++i) {
		printf("%02X : ", ks.k[i]);
		print_char_as_binary(ks.k[i]);
		printf("\n");
	}
	printf("\nC: \n");

	for (size_t i = 0; i < 4; ++i) {
		printf("%02X : ", ks.c[i]);
		print_char_as_binary(ks.c[i]);
		printf("\n");
	}
	printf("\nD: \n");

	for (size_t i = 0; i < 4; ++i) {
		printf("%02X : ", ks.d[i]);
		print_char_as_binary(ks.d[i]);
		printf("\n");
	}
	printf("\n");
}

/**
 * @brief 
 * 
 * @param main_key 
 * @param key_sets 
 */
void DES::generate_sub_keys(unsigned char* main_key, key_set* key_sets) {
	int i, j;
	int shift_size;
	unsigned char shift_byte, first_shift_bits, second_shift_bits, third_shift_bits, fourth_shift_bits;

	for (i=0; i<8; i++) {
		key_sets[0].k[i] = 0;
	}

	for (i=0; i<56; i++) {
		shift_size = initial_key_permutaion[i];
		shift_byte = 0x80 >> ((shift_size - 1)%8);
		shift_byte &= main_key[(shift_size - 1)/8];
		shift_byte <<= ((shift_size - 1)%8);

		key_sets[0].k[i/8] |= (shift_byte >> i%8);
	}

	for (i=0; i<3; i++) {
		key_sets[0].c[i] = key_sets[0].k[i];
	}

	key_sets[0].c[3] = key_sets[0].k[3] & 0xF0;

	for (i=0; i<3; i++) {
		key_sets[0].d[i] = (key_sets[0].k[i+3] & 0x0F) << 4;
		key_sets[0].d[i] |= (key_sets[0].k[i+4] & 0xF0) >> 4;
	}

	key_sets[0].d[3] = (key_sets[0].k[6] & 0x0F) << 4;


	for (i=1; i<17; i++) {
		for (j=0; j<4; j++) {
			key_sets[i].c[j] = key_sets[i-1].c[j];
			key_sets[i].d[j] = key_sets[i-1].d[j];
		}

		shift_size = key_shift_sizes[i];
		if (shift_size == 1){
			shift_byte = 0x80;
		} else {
			shift_byte = 0xC0;
		}

		// Process C
		first_shift_bits = shift_byte & key_sets[i].c[0];
		second_shift_bits = shift_byte & key_sets[i].c[1];
		third_shift_bits = shift_byte & key_sets[i].c[2];
		fourth_shift_bits = shift_byte & key_sets[i].c[3];

		key_sets[i].c[0] <<= shift_size;
		key_sets[i].c[0] |= (second_shift_bits >> (8 - shift_size));

		key_sets[i].c[1] <<= shift_size;
		key_sets[i].c[1] |= (third_shift_bits >> (8 - shift_size));

		key_sets[i].c[2] <<= shift_size;
		key_sets[i].c[2] |= (fourth_shift_bits >> (8 - shift_size));

		key_sets[i].c[3] <<= shift_size;
		key_sets[i].c[3] |= (first_shift_bits >> (4 - shift_size));

		// Process D
		first_shift_bits = shift_byte & key_sets[i].d[0];
		second_shift_bits = shift_byte & key_sets[i].d[1];
		third_shift_bits = shift_byte & key_sets[i].d[2];
		fourth_shift_bits = shift_byte & key_sets[i].d[3];

		key_sets[i].d[0] <<= shift_size;
		key_sets[i].d[0] |= (second_shift_bits >> (8 - shift_size));

		key_sets[i].d[1] <<= shift_size;
		key_sets[i].d[1] |= (third_shift_bits >> (8 - shift_size));

		key_sets[i].d[2] <<= shift_size;
		key_sets[i].d[2] |= (fourth_shift_bits >> (8 - shift_size));

		key_sets[i].d[3] <<= shift_size;
		key_sets[i].d[3] |= (first_shift_bits >> (4 - shift_size));

		for (j=0; j<48; j++) {
			shift_size = sub_key_permutation[j];
			if (shift_size <= 28) {
				shift_byte = 0x80 >> ((shift_size - 1)%8);
				shift_byte &= key_sets[i].c[(shift_size - 1)/8];
				shift_byte <<= ((shift_size - 1)%8);
			} else {
				shift_byte = 0x80 >> ((shift_size - 29)%8);
				shift_byte &= key_sets[i].d[(shift_size - 29)/8];
				shift_byte <<= ((shift_size - 29)%8);
			}

			key_sets[i].k[j/8] |= (shift_byte >> j%8);
		}
	}
}

/**
 * @brief 
 * 
 * @param message_piece 
 * @param processed_piece 
 * @param key_sets 
 * @param mode 
 */
void DES::process_message(unsigned char* message_piece, unsigned char* processed_piece, key_set* key_sets, int mode) {
	int i, k;
	int shift_size;
	unsigned char shift_byte;

	unsigned char initial_permutation[8];
	memset(initial_permutation, 0, 8);
	memset(processed_piece, 0, 8);

	for (i=0; i<64; i++) {
		shift_size = initial_message_permutation[i];
		shift_byte = 0x80 >> ((shift_size - 1)%8);
		shift_byte &= message_piece[(shift_size - 1)/8];
		shift_byte <<= ((shift_size - 1)%8);

		initial_permutation[i/8] |= (shift_byte >> i%8);
	}

	unsigned char l[4], r[4];
	for (i=0; i<4; i++) {
		l[i] = initial_permutation[i];
		r[i] = initial_permutation[i+4];
	}

	unsigned char ln[4], rn[4], er[6], ser[4];

	int key_index;
	for (k=1; k<=16; k++) {
		memcpy(ln, r, 4);

		memset(er, 0, 6);

		for (i=0; i<48; i++) {
			shift_size = message_expansion[i];
			shift_byte = 0x80 >> ((shift_size - 1)%8);
			shift_byte &= r[(shift_size - 1)/8];
			shift_byte <<= ((shift_size - 1)%8);

			er[i/8] |= (shift_byte >> i%8);
		}

		if (mode == DECRYPTION_MODE) {
			key_index = 17 - k;
		} else {
			key_index = k;
		}

		for (i=0; i<6; i++) {
			er[i] ^= key_sets[key_index].k[i];
		}

		unsigned char row, column;

		for (i=0; i<4; i++) {
			ser[i] = 0;
		}

		// 0000 0000 0000 0000 0000 0000
		// rccc crrc cccr rccc crrc cccr

		// Byte 1
		row = 0;
		row |= ((er[0] & 0x80) >> 6);
		row |= ((er[0] & 0x04) >> 2);

		column = 0;
		column |= ((er[0] & 0x78) >> 3);

		ser[0] |= ((unsigned char)S1[row*16+column] << 4);

		row = 0;
		row |= (er[0] & 0x02);
		row |= ((er[1] & 0x10) >> 4);

		column = 0;
		column |= ((er[0] & 0x01) << 3);
		column |= ((er[1] & 0xE0) >> 5);

		ser[0] |= (unsigned char)S2[row*16+column];

		// Byte 2
		row = 0;
		row |= ((er[1] & 0x08) >> 2);
		row |= ((er[2] & 0x40) >> 6);

		column = 0;
		column |= ((er[1] & 0x07) << 1);
		column |= ((er[2] & 0x80) >> 7);

		ser[1] |= ((unsigned char)S3[row*16+column] << 4);

		row = 0;
		row |= ((er[2] & 0x20) >> 4);
		row |= (er[2] & 0x01);

		column = 0;
		column |= ((er[2] & 0x1E) >> 1);

		ser[1] |= (unsigned char)S4[row*16+column];

		// Byte 3
		row = 0;
		row |= ((er[3] & 0x80) >> 6);
		row |= ((er[3] & 0x04) >> 2);

		column = 0;
		column |= ((er[3] & 0x78) >> 3);

		ser[2] |= ((unsigned char)S5[row*16+column] << 4);

		row = 0;
		row |= (er[3] & 0x02);
		row |= ((er[4] & 0x10) >> 4);

		column = 0;
		column |= ((er[3] & 0x01) << 3);
		column |= ((er[4] & 0xE0) >> 5);

		ser[2] |= (unsigned char)S6[row*16+column];

		// Byte 4
		row = 0;
		row |= ((er[4] & 0x08) >> 2);
		row |= ((er[5] & 0x40) >> 6);

		column = 0;
		column |= ((er[4] & 0x07) << 1);
		column |= ((er[5] & 0x80) >> 7);

		ser[3] |= ((unsigned char)S7[row*16+column] << 4);

		row = 0;
		row |= ((er[5] & 0x20) >> 4);
		row |= (er[5] & 0x01);

		column = 0;
		column |= ((er[5] & 0x1E) >> 1);

		ser[3] |= (unsigned char)S8[row*16+column];

		for (i=0; i<4; i++) {
			rn[i] = 0;
		}

		for (i=0; i<32; i++) {
			shift_size = right_sub_message_permutation[i];
			shift_byte = 0x80 >> ((shift_size - 1)%8);
			shift_byte &= ser[(shift_size - 1)/8];
			shift_byte <<= ((shift_size - 1)%8);

			rn[i/8] |= (shift_byte >> i%8);
		}

		for (i=0; i<4; i++) {
			rn[i] ^= l[i];
		}

		for (i=0; i<4; i++) {
			l[i] = ln[i];
			r[i] = rn[i];
		}
	}

	unsigned char pre_end_permutation[8];
	for (i=0; i<4; i++) {
		pre_end_permutation[i] = r[i];
		pre_end_permutation[4+i] = l[i];
	}

	for (i=0; i<64; i++) {
		shift_size = final_message_permutation[i];
		shift_byte = 0x80 >> ((shift_size - 1)%8);
		shift_byte &= pre_end_permutation[(shift_size - 1)/8];
		shift_byte <<= ((shift_size - 1)%8);

		processed_piece[i/8] |= (shift_byte >> i%8);
	}
}

/**
 * @brief 
 * 
 * @param err_msg 
 */
void DES::error_log(const std::string &err_msg) {
	std::cerr << err_msg << std::endl; 
}