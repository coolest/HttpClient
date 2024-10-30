
#ifndef NETWORK_CLIENT_SOCKET
#define NETWORK_CLIENT_SOCKET

#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <vector>

namespace network {
    enum connect_response{
        BAD_IP,
        CONNECTION_FAIL,
        DNS_LOOKUP_FAIL,
        SUCCESS,
    };
    enum receive_response{
        TIMEOUT,
        SELECT_ERR,
        RECEIVE_ERROR,
        SUCCESS,
    };
    enum send_response{
        NOT_CONNECTED,
        SEND_ERR,
        SUCCESS,
    };

    struct dns_host{
        char* host;
        bool success;
        int err;

        dns_host() : host{nullptr}, success{false}, err{-1} {}; // TODO: std::unique_ptr()
        ~dns_host(){ 
            delete[] host; 
        }
    };

    class socket_base {
        protected:
            dns_host host;
            std::string hostname;
            int port;
            int socket_fd;

        public:
            socket_base(const std::string &hostname, int port);
            virtual ~socket_base();

            send_response send_data(const std::vector<uint8_t> &data, int& err);
            receive_response receive_data(std::vector<uint8_t> &buff, int &err, const int timeout_ms = 3000, const int chunk_size = 4096);
            connect_response connect();
            bool is_connected();
            virtual bool close();
        protected:
            bool dns_lookup(const std::string &host);
            virtual int receive_data_internal(void* data, size_t amt);
            virtual ssize_t send_data_internal(const void* data, size_t amt);
            virtual int get_error(int res);
    };

    class http_socket : public socket_base {
        public: 
            http_socket(const std::string &host, int port = 80);
            
            bool close() override;
        private:
            int get_error(int res) override;
            int receive_data_internal(void* data, size_t amt) override;
            ssize_t send_data_internal(const void* data, size_t amt) override;
    };

    class https_socket : public socket_base {
        private:
            SSL_CTX* ssl_ctx;
            SSL* ssl;

        public:
            https_socket(const std::string &host, int port = 443);
            
            bool close() override;
        private:
            int get_error(int res) override;
            int receive_data_internal(void* data, size_t amt) override;
            ssize_t send_data_internal(const void* data, size_t amt) override;
    };
} // namespace network

#endif // NETWORK_CLIENT_SOCKET