#include "socket.hpp"
#include <iostream>

network::socket_base::socket_base(const std::string &hostname, int port) : host{}, hostname{hostname}, port{port}, socket_fd{-1} {

};

network::socket_base::~socket_base() {}

bool network::socket_base::close(){
    if (!socket_base::is_connected()){
        return true;
    }

    int close_err = ::close(socket_fd);
    socket_fd = -1;

    return !close_err;
}

bool network::socket_base::is_connected(){
    return socket_fd >= 0;
};

// Only lookup hostname zero or one time.
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

    char host_buffer[NI_MAXHOST];
    struct addrinfo* p = res;
    err = getnameinfo(p->ai_addr, p->ai_addrlen, host_buffer, sizeof(host_buffer), NULL, 0, NI_NUMERICHOST);
    freeaddrinfo(res);

    if (err != 0){
        host.err = err;
        return false;
    }

    host.host = host_buffer;
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
        return connect_response::CONNECT_DNS_LOOKUP_FAIL;
    }

    if (inet_pton(AF_INET, host.host.c_str(), &server_address.sin_addr) <= 0) {
        socket_base::close();
        return connect_response::CONNECT_BAD_IP;
    }

    if (::connect(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        socket_base::close();
        return connect_response::CONNECT_FAIL;
    }

    return connect_response::CONNECT_SUCCESS;
}

network::receive_response network::socket_base::receive_data(
    std::vector<uint8_t> &data, 
    int &err,
    const int timeout_ms,
    const int chunk_size
){
    if (!is_connected()){
        return receive_response::RECEIVE_NOT_CONNECTED;
    }

    size_t current_position = 0;
    ssize_t bytes = -1;

    while (true){
        fd_set fd;
        FD_ZERO(&fd);
        FD_SET(socket_fd, &fd);

        timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000; 

        int ret = select(socket_fd + 1, &fd, nullptr, nullptr, &timeout);
        if (ret < 0){
            err = errno;
            return receive_response::RECEIVE_SELECT_ERR;
        } else if (ret == 0){
            return receive_response::RECEIVE_TIMEOUT;
        }

        if (data.size() < chunk_size + current_position){
            data.resize(data.size() + chunk_size);
        }
        
        bytes = receive_data_internal(data.data() + current_position, chunk_size);
        if (bytes < 0){
            err = get_error(bytes);
            return receive_response::RECEIVE_ERROR;
        } else if (bytes == 0){
            break;
        }

        current_position += bytes;
    }

    data.resize(current_position);
    if (current_position > 0){
        return receive_response::RECEIVE_SUCCESS;
    } else {
        return receive_response::RECEIVE_CLOSED;
    }
};

network::receive_response network::socket_base::receive_string(
    std::string &buff, 
    int &err,
    const int timeout_ms,
    const int chunk_size
){
    std::vector<uint8_t> bytes{};

    network::receive_response response = receive_data(bytes, err, timeout_ms, chunk_size);

    if (response == receive_response::RECEIVE_SUCCESS){
        buff = std::string(bytes.begin(), bytes.end());
    }

    return response;
}

network::send_response network::socket_base::send_data(const std::vector<uint8_t> &data, int &err) {
    if (!is_connected()){
        return send_response::SEND_NOT_CONNECTED;
    }

    size_t total_sent = 0;
    size_t len = data.size();

    while (total_sent < len) {
        int sent = send_data_internal(data.data() + total_sent, len - total_sent);
        if (sent <= 0){
            err = get_error(sent);
            return send_response::SEND_ERR;
        }

        total_sent += sent;
    }

    return send_response::SEND_SUCCESS;
}

network::send_response network::socket_base::send_string(const std::string &data, int &err){
    std::vector<uint8_t> bytes{data.begin(), data.end()};

    return send_data(bytes, err);
}

const network::dns_host network::socket_base::get_dns_host() const {
    return host;
}

const std::string network::socket_base::get_hostname() const {
    return hostname;
}
//
// HTTP SOCKET
//
network::http_socket::http_socket(const std::string &host, int port) : socket_base{host, port} {

}

network::http_socket::~http_socket() {
    socket_base::close();
}

network::create_response network::http_socket::create(){
    socket_base::close();

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0){
        return create_response::CREATE_FAIL;
    }

    return create_response::CREATE_SUCCESS;
}

ssize_t network::http_socket::send_data_internal(const void* data, size_t amt) {
    return send(socket_fd, data, amt, 0);
}

ssize_t network::http_socket::receive_data_internal(void* data, size_t amt){
    return recv(socket_fd, data, amt, 0);
}

int network::http_socket::get_error(int res){
    return errno;
}
//
// HTTPS SOCKET
//
SSL_CTX* network::https_socket::ssl_ctx = nullptr;
std::mutex network::https_socket::ssl_ctx_mutex{};

network::https_socket::https_socket(const std::string &host, int port) : socket_base{host, port} {

}

network::https_socket::~https_socket() {
    https_socket::close();
}

network::create_response network::https_socket::create(){
    socket_base::close();

    if (!ssl_ctx){
        std::lock_guard<std::mutex> lock{ssl_ctx_mutex};
        if (!ssl_ctx){
            ssl_ctx = SSL_CTX_new(TLS_client_method());
            if (!ssl_ctx) {
                return create_response::CREATE_SSL_CTX_FAIL;
            }
        }
    }

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0){
        return create_response::CREATE_FAIL;
    }

    return create_response::CREATE_SUCCESS;
}

network::connect_response network::https_socket::connect(){
    if (!ssl_ctx){
        return network::connect_response::CONNECT_SSL_CTX_NOT_INITIALIZED;
    }

    network::connect_response tcp_connect_result = socket_base::connect();
    if (tcp_connect_result != network::connect_response::CONNECT_SUCCESS) {
        return tcp_connect_result;
    }

    ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        return network::connect_response::CONNECT_SSL_CREATE_FAIL;
    }

    if (!SSL_set_fd(ssl, socket_fd)) {
        SSL_free(ssl);
        ssl = nullptr;

        return network::connect_response::CONNECT_SSL_SET_FD_FAIL;
    }

    if (SSL_connect(ssl) <= 0) {
        SSL_free(ssl);
        ssl = nullptr;

        return network::connect_response::CONNECT_SSL_HANDSHAKE_FAIL;
    }

    return network::connect_response::CONNECT_SUCCESS;
}

ssize_t network::https_socket::send_data_internal(const void* data, size_t amt){
    return SSL_write(ssl, data, amt);
}

ssize_t network::https_socket::receive_data_internal(void* data, size_t amt){
    return SSL_read(ssl, data, amt);
}

int network::https_socket::get_error(int res){
    return SSL_get_error(ssl, res);
}

bool network::https_socket::close(){
    if (ssl != nullptr){
        SSL_shutdown(ssl);
        SSL_free(ssl);
        ssl = nullptr;
    }

    return socket_base::close();
}

void network::https_socket::free_ssl_ctx(){
    std::lock_guard<std::mutex> lock{ssl_ctx_mutex};
    
    if (!ssl_ctx){
        return;
    }

    SSL_CTX_free(ssl_ctx);
    ssl_ctx = nullptr;
}