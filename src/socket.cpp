#include "include/socket.hpp"

network::socket_base::socket_base(const std::string &hostname, int port) : host{}, hostname{hostname}, port{port}, socket_fd{-1} {

};

bool network::socket_base::is_connected(){
    return socket_fd != -1;
};

/*
    Only lookup hostname zero or one time.
*/
bool network::socket_base::dns_lookup(const std::string &hostname){
    if (host.success){
        return true;
    }

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(hostname.c_str(), NULL, &hints, &res);
    if (err != 0) {
        host.err = err;

        return false;
    }

    char dnshost[256];

    struct addrinfo* p = res;
    getnameinfo(p->ai_addr, p->ai_addrlen, dnshost, sizeof(host), NULL, 0, NI_NUMERICHOST);
    freeaddrinfo(res);

    host.host = new char[strlen(dnshost) + 1];
    strcpy(host.host, dnshost);
    host.success = true;

    return true;
}

network::connect_response network::socket_base::connect(){
    struct sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;  // ip4
    server_address.sin_port = htons(port);

    bool success = dns_lookup(hostname);
    if (!success){
        return connect_response::DNS_LOOKUP_FAIL;
    }

    if (inet_pton(AF_INET, host.host, &server_address.sin_addr) <= 0) {
        ::close(socket_fd);

        return connect_response::BAD_IP;
    }

    if (::connect(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        ::close(socket_fd);

        return connect_response::CONNECTION_FAIL;
    }

    return connect_response::SUCCESS;
}

network::receive_response network::socket_base::receive_data(
    std::vector<uint8_t> &data, 
    int &err,
    const int timeout_ms = 3000,
    const int chunk_size = 4096
){
    fd_set fd;
    FD_ZERO(&fd);
    FD_SET(socket_fd, &fd);

    timeval timeout;
    timeout.tv_sec = timeout_ms / 1000;
    timeout.tv_usec = (timeout_ms % 1000) * 1000; 

    int current_position = 0;
    int bytes = -1;

    while (bytes != 0){
        int ret = select(socket_fd + 1, &fd, nullptr, nullptr, &timeout);
        if (ret < 0){
            err = errno;
            return receive_response::SELECT_ERR;
        } else if (ret == 0){
            return receive_response::TIMEOUT;
        }

        if (data.size() < chunk_size + current_position){
            data.resize(data.size() + chunk_size);
        }
        
        bytes = receive_data_internal(data.data() + current_position, chunk_size);
        if (bytes < 0){
            err = get_error(bytes);
            return receive_response::RECEIVE_ERROR;
        }

        current_position += bytes;
    }

    data.resize(current_position);
    return receive_response::SUCCESS;
};

network::send_response network::socket_base::send_data(const std::vector<uint8_t> &data, int &err) {
    if (!is_connected()){
        return send_response::NOT_CONNECTED;
    }

    size_t total_sent = 0;
    size_t len = data.size();

    while (total_sent < len) {
        int sent = send_data_internal(data.data() + total_sent, len - total_sent);
        if (sent < 0){
            err = get_error(sent);
            return send_response::SEND_ERR;
        }

        total_sent += sent;
    }

    return send_response::SUCCESS;
}
//
// HTTP SOCKET
//
network::http_socket::http_socket(const std::string &host, int port) : socket_base{host, port} {
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (socket_fd < 0){
        throw std::runtime_error("Socket creation error: " + std::to_string(errno));
    }
}

ssize_t network::http_socket::send_data_internal(const void* data, size_t amt) {
    return send(socket_fd, data, amt, 0);
}

int network::http_socket::receive_data_internal(void* data, size_t amt){
    return recv(socket_fd, data, amt, 0);
}

int network::http_socket::get_error(int res){
    return errno;
}

bool network::http_socket::close(){
    if (socket_fd == -1){
        return true;
    }

    return ::close(socket_fd) == -1;
}
//
// HTTPS SOCKET
//
network::https_socket::https_socket(const std::string &host, int port = 443) : socket_base{host, port}, ssl{nullptr}, ssl_ctx{nullptr} {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        throw std::runtime_error("Failed to create SSL context");
    }

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        throw std::runtime_error("Socket creation error: " + std::to_string(errno));
    }
}

ssize_t network::https_socket::send_data_internal(const void* data, size_t amt){
    return SSL_write(ssl, data, amt);
}

int network::https_socket::receive_data_internal(void* data, size_t amt){
    return SSL_read(ssl, data, amt);
}

int network::https_socket::get_error(int res){
    return SSL_get_error(ssl, res);
}

bool network::https_socket::close(){
    if (ssl != nullptr){
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    if (ssl_ctx != nullptr){
        SSL_CTX_free(ssl_ctx);
        EVP_cleanup();
    }

    return socket_fd == -1 || ::close(socket_fd) == -1;
}