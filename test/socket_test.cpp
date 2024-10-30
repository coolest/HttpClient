#include "socket.hpp"
#include <iostream>

int main(){
    int ignore_flag{};

    std::cout << "here\n";

    network::https_socket socket{"www.google.com", 443};
    network::connect_response r = socket.connect();
    std::cout << r << std::endl;
    std::cout << socket.get_dns_host().err << std::endl;

    socket.send_string(
        "GET / HTTP/1.1\r\n"
        "Host: www.google.com\r\n"
        "Connection: close\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "\r\n",
        ignore_flag
    );

    std::cout << "here\n" << ignore_flag << std::endl;

    std::string res{};
    network::receive_response r2 = socket.receive_string(res, ignore_flag);
    std::cout << r2 << " " << ignore_flag << std::endl;

    std::cout << res << std::endl;
}