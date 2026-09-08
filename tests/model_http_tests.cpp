#include "indago/model_provider.hpp"
#include <iostream>
#include <thread>
#ifdef _WIN32
#include <winsock2.h>
using Socket = SOCKET;
constexpr Socket bad_socket = INVALID_SOCKET;
void close_socket(Socket s) { closesocket(s); }
#else
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
using Socket = int;
constexpr Socket bad_socket = -1;
void close_socket(Socket s) { close(s); }
#endif
using J = nlohmann::json;
struct MockServer {
  Socket listener = bad_socket;
  unsigned port = 0;
  std::jthread worker;
  explicit MockServer(std::string response, int delay_ms = 0) {
    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener == bad_socket)
      throw std::runtime_error("test socket failed");
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) ||
        listen(listener, 1))
      throw std::runtime_error("test loopback bind failed");
#ifdef _WIN32
    int size = sizeof(addr);
#else
    socklen_t size = sizeof(addr);
#endif
    getsockname(listener, reinterpret_cast<sockaddr *>(&addr), &size);
    port = ntohs(addr.sin_port);
    worker = std::jthread([this, response, delay_ms] {
      fd_set readers;
      FD_ZERO(&readers);
      FD_SET(listener, &readers);
      timeval timeout{5, 0};
      if (select(static_cast<int>(listener) + 1, &readers, nullptr, nullptr,
                 &timeout) <= 0)
        return;
      auto client = accept(listener, nullptr, nullptr);
      if (client == bad_socket)
        return;
      std::string request;
      char buffer[4096];
      while (request.size() < 65536) {
        fd_set pending;
        FD_ZERO(&pending);
        FD_SET(client, &pending);
        timeval bound{5, 0};
        if (select(static_cast<int>(client) + 1, &pending, nullptr, nullptr,
                   &bound) <= 0)
          break;
        int n = recv(client, buffer, sizeof(buffer), 0);
        if (n <= 0)
          break;
        request.append(buffer, n);
        auto split = request.find("\r\n\r\n");
        if (split != request.npos) {
          auto header = request.substr(0, split);
          for (auto &c : header)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
          auto length = header.find("content-length:");
          if (length != header.npos &&
              request.size() >=
                  split + 4 + std::stoul(header.substr(length + 15)))
            break;
        }
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
      for (std::size_t at = 0; at < response.size();) {
#ifdef _WIN32
        int n = send(client, response.data() + at,
                     static_cast<int>(response.size() - at), 0);
#else
        int n = static_cast<int>(send(client, response.data() + at,
                                      response.size() - at, MSG_NOSIGNAL));
#endif
        if (n <= 0)
          break;
        at += n;
      }
      close_socket(client);
    });
  }
  ~MockServer() {
    if (worker.joinable())
      worker.join();
    if (listener != bad_socket)
      close_socket(listener);
  }
};
int main() {
#ifdef _WIN32
  WSADATA sockets{};
  if (WSAStartup(MAKEWORD(2, 2), &sockets))
    return 1;
#endif
  try {
    std::string payload = "data: [DONE]\n\n";
    MockServer server("HTTP/1.1 200 OK\r\nContent-Type: "
                      "text/event-stream\r\nContent-Length: " +
                      std::to_string(payload.size()) +
                      "\r\nConnection: close\r\n\r\n" + payload);
    auto profile = indago::normalize_model_profile(
        {{"provider", "local"},
         {"model", "mock"},
         {"generation_ms", 2000},
         {"endpoint", "http://127.0.0.1:" + std::to_string(server.port) +
                          "/v1/chat/completions"}});
    if (indago::model_http_request(profile, J::object(),
                                   [] { return false; }) != payload)
      throw std::runtime_error("native HTTP payload mismatch");
    MockServer redirect("HTTP/1.1 302 Found\r\nLocation: "
                        "https://example.invalid/forbidden\r\nContent-Length: "
                        "0\r\nConnection: close\r\n\r\n");
    profile["endpoint"] = "http://127.0.0.1:" + std::to_string(redirect.port) +
                          "/v1/chat/completions";
    bool rejected = false;
    try {
      indago::model_http_request(profile, J::object(), [] { return false; });
    } catch (...) {
      rejected = true;
    }
    if (!rejected)
      throw std::runtime_error("HTTP redirect followed");
    MockServer slow(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        500);
    profile["endpoint"] = "http://127.0.0.1:" + std::to_string(slow.port) +
                          "/v1/chat/completions";
    profile["generation_ms"] = 100;
    rejected = false;
    auto start = std::chrono::steady_clock::now();
    try {
      indago::model_http_request(profile, J::object(), [] { return false; });
    } catch (...) {
      rejected = true;
    }
    if (!rejected ||
        std::chrono::steady_clock::now() - start > std::chrono::seconds(2))
      throw std::runtime_error("native transport deadline failed");
    std::cout << "Loopback HTTP payload, redirect refusal and bounded timeout "
                 "passed; no live inference\n";
  } catch (const std::exception &e) {
    std::cerr << e.what() << '\n';
    return 1;
  }
}
