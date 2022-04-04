# DES algorithm demo program

## 01 Directories
- src: source codes, including des.cpp and test_des.cpp
- include: header file, including des.hpp
- files: key file, plaintext and ciphertext

## 02 Build
In a easy way, you can run ./compile_and_test.sh to configure, build and test whole project.

## 03 Usage of des
```shell
$ ./des -k <keyfile> # generate key file
$ ./des -e <keyfile> <inputfile> <outputfile> # encrypt the input file
$ ./des -d <keyfile> <inputfile> <outputfile> # decrypt the output file
```

## 04 Generate Dynamic Link Library
In a easy way, you can run ./generate_dynamic_link_library.sh to generate. 

## 05 Standing on the shoulders of giants
Special thanks to Tareque Hossain the Software architect, open source enthusiast, amateur videographer, world traveler.