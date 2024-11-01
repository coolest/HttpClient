#include "socket.hpp"
#include <iostream>

namespace socket_tests {

void print_error(const network::socket_base &socket, const std::string &err){
    printf("ERROR IN SOCKET{%s}:\n%s", 
        socket.get_hostname().c_str(), 
        err.c_str());
}

void handle_bad_create(
    const network::socket_base &socket, 
    const network::create_response &response,
    const int &err
){
    switch(response){
        case network::create_response::CREATE_SSL_CTX_FAIL: 
            print_error(socket, "CREATE SSL CTX FAIL"); break;
        case network::create_response::CREATE_FAIL: 
            print_error(socket, "CREATE SOCKET FAIL"); break;
        default: break;
    }
}

void handle_bad_connect(
    const network::socket_base &socket, 
    const network::connect_response &response,
    const int &err
){
    switch(response){
        case network::connect_response::CONNECT_BAD_IP: 
            print_error(socket, "CONNECT BAD IP"); break;
        case network::connect_response::CONNECT_DNS_LOOKUP_FAIL:
            print_error(socket, "CONNECT DNS LOOKUP FAIL\nERROR: " + std::to_string(socket.get_dns_host().err)); break;
        case network::connect_response::CONNECT_FAIL: 
            print_error(socket, "CONNECT FAIL\nERROR: " + std::to_string(err)); break;
        case network::connect_response::CONNECT_SSL_CREATE_FAIL:
            print_error(socket, "CONNECT SSL CREATE FAIL"); break;
        case network::connect_response::CONNECT_SSL_HANDSHAKE_FAIL:
            print_error(socket, "CONNECT SSL HANDSHAKE FAIL"); break;
        case network::connect_response::CONNECT_SSL_SET_FD_FAIL:
            print_error(socket, "CONNECT SSL SET FD FAIL"); break;
        case network::connect_response::CONNECT_SSL_CTX_NOT_INITIALIZED:
            print_error(socket, "CONNECT SSL CTX NOT INITIALIZED"); break;
        default: break;
    }
}

void handle_bad_send(
    const network::socket_base &socket, 
    const network::send_response &response,
    const int &err
){
    switch (response){
        case network::send_response::SEND_ERR:
            print_error(socket, "SEND ERROR\nERROR: " + std::to_string(err)); break;
        case network::send_response::SEND_NOT_CONNECTED:
            print_error(socket, "SOCKET NOT CONNECTED, CANNOT SEND"); break;
        default: break;
    }
}

void handle_bad_receive(
    const network::socket_base &socket, 
    const network::receive_response &response,
    const int &err
){
    switch(response){
        case network::receive_response::RECEIVE_ERROR:
            print_error(socket, "RECEIVE ERROR\nERROR: " + std::to_string(err)); break;
        case network::receive_response::RECEIVE_SELECT_ERR:
            print_error(socket, "SELECT ERROR\nERROR: " + std::to_string(err)); break;
        case network::receive_response::RECEIVE_TIMEOUT:
            print_error(socket, "RECEIVE TIMEOUT"); break;
        default: break;
    }
}

int perform_test(){
    int err{};

    std::cout << "Starting HTTPS socket test...\n";

    network::https_socket socket{"www.google.com"};
    network::create_response create_res = socket.create();
    if (create_res != network::create_response::CREATE_SUCCESS){
        handle_bad_create(socket, create_res, err);
        return 1;
    }

    std::cout << "Socket created for: www.google.com\n";

    std::cout << "Attempting to connect...\n";
    network::connect_response connect_res = socket.connect();
    if (connect_res != network::connect_response::CONNECT_SUCCESS){
        handle_bad_connect(socket, connect_res, err);
        return 1;
    }
    std::cout << "Connection successful!\n";

    std::cout << "Sending HTTP GET request...\n";
    network::send_response send_res = socket.send_string(
        "GET / HTTP/1.1\r\n"
        "Host: www.google.com\r\n"
        "Connection: close\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "\r\n",
        err);
    if (send_res != network::send_response::SEND_SUCCESS){
        handle_bad_send(socket, send_res, err);
        return 1;
    }
    std::cout << "Request sent successfully!\n";

    std::cout << "Waiting for response...\n";
    std::string res{};
    network::receive_response receive_res = socket.receive_string(res, err);
    if (receive_res != network::receive_response::RECEIVE_SUCCESS){
        handle_bad_receive(socket, receive_res, err);
        return 1;
    }
    
    std::cout << "Response received! First 100 characters:\n";
    std::cout << res.substr(0, 100) << "...\n";

    std::cout << "Test completed successfully!\n";
    return 0;
}

} // namespace socket_tests

int main() {
    return socket_tests::perform_test();
}