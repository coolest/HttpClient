#include "socket.hpp"
#include <iostream>

int main(){
    int ignore_flag{};

    std::cout << "here\n";

    network::https_socket socket{"google.com"};
    network::connect_response r = socket.connect();
    std::cout << r << std::endl;
    std::cout << socket.get_dns_host().err << std::endl;

    socket.send_string(
        "GET /  HTTP/1.1\r\nHost:" + socket.get_dns_host().host + "\r\n\r\n",
        ignore_flag
    );

    std::cout << "here\n" << ignore_flag << std::endl;

    std::string res{};
    socket.receive_string(res, ignore_flag);

    std::cout << res << std::endl;
}