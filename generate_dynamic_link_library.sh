#!/bin/sh
g++ -fPIC -shared -Iinclude ./src/des.cpp ./src/test_des.cpp -o libdes.so