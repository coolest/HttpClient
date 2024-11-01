g++ -Wall -std=c++20 \
    src/socket.cpp \
    test/socket_test.cpp \
    -o socket_test \
    -I. -Iinclude -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto

./socket_test
rm socket_test