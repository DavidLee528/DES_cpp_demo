#!/bin/sh

# clean if old build exist
if [ ! -d "/build" ]; then
	rm ./build -r
fi

# compile with cmake
mkdir build
cd build
echo "\033[35m*** [ STEP 01 ] CMake Configure ***\033[0m"
cmake ..
echo "\033[35m*** [ STEP 02 ] CMake Build ***\033[0m"
cmake --build .
cd ..

# clean files
rm ./files -r
mkdir files

# set variables
key="./files/k.key"
plaintext="./files/plain"
ciphertext="./files/cipher"

# step1: test generate key
echo "\033[35m*** [ STEP 03 ] TEST Generate key file ***\033[0m"
touch ${key}
./des -k ${key}
echo "${key}: " & cat ./files/k.key
echo ""

# step2: test encrypt
echo "\033[35m*** [ STEP 04 ] TEST encryption ***\033[0m"
touch ${plaintext} & echo "hello, this is plaintext message! " > ${plaintext}
touch ${ciphertext}
./des -e ${key} ${plaintext} ${ciphertext}
echo "\n> plaintext(input): " & cat ./files/plain
echo "\n> ciphertext(output): " & cat ./files/cipher

# step3: test decrypt
echo "\n\033[35m*** [ STEP 05 ] TEST decryption ***\033[0m"
rm ${plaintext}
touch ${plaintext}
./des -d ${key} ${ciphertext} ${plaintext}
echo "\n> ciphertext(input): " & cat ./files/cipher
echo "\n> plaintext(output): " & cat ./files/plain

