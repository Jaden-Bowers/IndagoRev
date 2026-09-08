#include "indago/model_provider.hpp"
#include "workbench_db.hpp"
#include <atomic>
#include <charconv>
#include <thread>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#else
#include <cerrno>
#include <fcntl.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

namespace indago {
namespace {
constexpr std::size_t max_wire = 1048576;
using Clock = std::chrono::steady_clock;
struct Deadline {
  Clock::time_point end;
  const ModelCancel &cancel;
  void check() const {
    if (cancel && cancel())
      throw std::runtime_error("model generation cancelled");
    if (Clock::now() >= end)
      throw std::runtime_error("model generation timed out");
  }
};
std::string credential(const nlohmann::json &profile) {
  if (profile.at("provider") != "openrouter")
    return {};
  auto secret =
      wb::read(profile.at("credential_file").get<std::string>(), 4096);
  while (!secret.empty() && (secret.back() == '\r' || secret.back() == '\n'))
    secret.pop_back();
  if (secret.empty() ||
      secret.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTU"
                               "VWXYZ0123456789_-.") != secret.npos)
    throw std::runtime_error("invalid controller credential file");
  return secret;
}
#ifdef _WIN32
struct Internet {
  HINTERNET p{};
  ~Internet() {
    if (p)
      WinHttpCloseHandle(p);
  }
};
std::wstring wide(std::string_view s) { return {s.begin(), s.end()}; }
#else
struct Connection {
  int fd = -1;
  SSL_CTX *ctx{};
  SSL *ssl{};
  ~Connection() {
    if (ssl)
      SSL_free(ssl);
    if (ctx)
      SSL_CTX_free(ctx);
    if (fd >= 0)
      close(fd);
  }
};
struct BlockSigpipe {
  sigset_t blocked{}, previous{};
  BlockSigpipe() {
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &blocked, &previous);
  }
  ~BlockSigpipe() {
    if (!sigismember(&previous, SIGPIPE)) {
      timespec zero{};
      while (sigtimedwait(&blocked, nullptr, &zero) >= 0) {
      }
    }
    pthread_sigmask(SIG_SETMASK, &previous, nullptr);
  }
};
void ready(int fd, short events, const Deadline &deadline) {
  while (true) {
    deadline.check();
    pollfd p{fd, events, 0};
    int n = poll(&p, 1, 50);
    if (n > 0)
      return;
    if (n < 0 && errno != EINTR)
      throw std::runtime_error("model socket poll failed");
  }
}
struct Resolution {
  std::atomic<bool> done = false;
  addrinfo *addresses{};
  int error{};
  ~Resolution() {
    if (addresses)
      freeaddrinfo(addresses);
  }
};
void connect_socket(Connection &c, const std::string &host,
                    const std::string &port, const Deadline &deadline) {
  auto resolution = std::make_shared<Resolution>();
  std::thread([resolution, host, port] {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    resolution->error =
        getaddrinfo(host.c_str(), port.c_str(), &hints, &resolution->addresses);
    resolution->done = true;
  }).detach();
  while (!resolution->done) {
    deadline.check();
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }
  if (resolution->error)
    throw std::runtime_error("model hostname resolution failed");
  for (auto a = resolution->addresses; a; a = a->ai_next) {
    deadline.check();
    c.fd = socket(a->ai_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,
                  a->ai_protocol);
    if (c.fd < 0)
      continue;
    int n = connect(c.fd, a->ai_addr, a->ai_addrlen);
    if (n == 0)
      return;
    if (errno == EINPROGRESS) {
      ready(c.fd, POLLOUT, deadline);
      int error = 0;
      socklen_t len = sizeof(error);
      getsockopt(c.fd, SOL_SOCKET, SO_ERROR, &error, &len);
      if (error == 0)
        return;
    }
    close(c.fd);
    c.fd = -1;
  }
  throw std::runtime_error("model endpoint unavailable");
}
void tls_wait(Connection &c, int result, const Deadline &deadline) {
  auto error = SSL_get_error(c.ssl, result);
  if (error == SSL_ERROR_WANT_READ)
    ready(c.fd, POLLIN, deadline);
  else if (error == SSL_ERROR_WANT_WRITE)
    ready(c.fd, POLLOUT, deadline);
  else
    throw std::runtime_error("model TLS handshake/transfer failed");
}
std::string http_body(const std::string &wire) {
  auto split = wire.find("\r\n\r\n");
  if (split == wire.npos || split > 65536)
    throw std::runtime_error("invalid model HTTP headers");
  if (!wire.starts_with("HTTP/1.1 200 ") && !wire.starts_with("HTTP/1.0 200 "))
    throw std::runtime_error(
        "model HTTP request failed; redirects and retries disabled");
  auto headers = wire.substr(0, split);
  for (auto &c : headers)
    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  auto body = wire.substr(split + 4);
  if (headers.find("\r\ntransfer-encoding: chunked") != headers.npos) {
    std::string decoded;
    std::size_t at = 0;
    while (true) {
      auto line = body.find("\r\n", at);
      if (line == body.npos)
        throw std::runtime_error("truncated HTTP chunk");
      auto count = std::string_view(body).substr(at, line - at);
      auto semi = count.find(';');
      if (semi != count.npos)
        count = count.substr(0, semi);
      std::size_t size = 0;
      auto parsed =
          std::from_chars(count.data(), count.data() + count.size(), size, 16);
      if (parsed.ec != std::errc{} || parsed.ptr != count.data() + count.size())
        throw std::runtime_error("invalid HTTP chunk size");
      at = line + 2;
      if (size == 0)
        return decoded;
      if (size > max_wire - decoded.size() || size > body.size() - at ||
          body.size() - at - size < 2 || body.substr(at + size, 2) != "\r\n")
        throw std::runtime_error("truncated or excessive HTTP chunk");
      decoded.append(body, at, size);
      at += size + 2;
    }
  }
  auto length = headers.find("\r\ncontent-length:");
  if (length != headers.npos) {
    auto start = length + 17;
    while (start < headers.size() && headers[start] == ' ')
      ++start;
    auto end = headers.find("\r\n", start);
    if (end == headers.npos)
      end = headers.size();
    std::size_t n = 0;
    auto parsed =
        std::from_chars(headers.data() + start, headers.data() + end, n);
    if (parsed.ec != std::errc{} || parsed.ptr != headers.data() + end ||
        n != body.size())
      throw std::runtime_error("model HTTP content length mismatch");
  }
  if (body.size() > max_wire)
    throw std::runtime_error("model response byte budget exceeded");
  return body;
}
#endif
} // namespace
std::string model_http_request(const nlohmann::json &profile,
                               const nlohmann::json &body,
                               const ModelCancel &cancel) {
  auto duration = profile.at("generation_ms").get<unsigned>();
  Deadline deadline{Clock::now() + std::chrono::milliseconds(duration), cancel};
  deadline.check();
  const bool tls = profile.at("provider") == "openrouter";
  const auto endpoint = profile.at("endpoint").get<std::string>();
  const auto host =
      tls ? std::string("openrouter.ai") : std::string("127.0.0.1");
  const auto port = tls ? std::string("443")
                        : endpoint.substr(17, endpoint.find('/', 17) - 17);
  const auto path = tls ? std::string("/api/v1/chat/completions")
                        : std::string("/v1/chat/completions");
  auto secret = credential(profile);
  const auto data = body.dump();
  if (data.size() > 1048576)
    throw std::runtime_error("model request byte budget exceeded");
#ifdef _WIN32
  Internet session{WinHttpOpen(L"IndagoRev/0.1", WINHTTP_ACCESS_TYPE_NO_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS,
                               0)};
  if (!session.p)
    throw std::runtime_error("model HTTP initialization failed");
  WinHttpSetTimeouts(session.p, duration, duration, duration, duration);
  Internet connection{
      WinHttpConnect(session.p, wide(host).c_str(),
                     static_cast<INTERNET_PORT>(std::stoul(port)), 0)};
  if (!connection.p)
    throw std::runtime_error("model HTTP connect failed");
  std::atomic<HINTERNET> handle{WinHttpOpenRequest(
      connection.p, L"POST", wide(path).c_str(), nullptr, WINHTTP_NO_REFERER,
      WINHTTP_DEFAULT_ACCEPT_TYPES, tls ? WINHTTP_FLAG_SECURE : 0)};
  if (!handle)
    throw std::runtime_error("model HTTP request creation failed");
  std::atomic<bool> done = false;
  std::jthread guard([&] {
    while (!done) {
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
      if (done)
        break;
      if (Clock::now() >= deadline.end || (cancel && cancel())) {
        auto old = handle.exchange(nullptr);
        if (old)
          WinHttpCloseHandle(old);
        break;
      }
    }
  });
  auto close = [&] {
    done = true;
    guard.join();
    auto old = handle.exchange(nullptr);
    if (old)
      WinHttpCloseHandle(old);
  };
  try {
    DWORD redirect = WINHTTP_OPTION_REDIRECT_POLICY_NEVER,
          autologon = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
    WinHttpSetOption(handle, WINHTTP_OPTION_REDIRECT_POLICY, &redirect,
                     sizeof(redirect));
    WinHttpSetOption(handle, WINHTTP_OPTION_AUTOLOGON_POLICY, &autologon,
                     sizeof(autologon));
    std::wstring headers =
        L"Content-Type: application/json\r\nAccept: "
        L"text/event-stream\r\nAccept-Encoding: identity\r\n";
    if (!secret.empty())
      headers += L"Authorization: Bearer " + wide(secret) + L"\r\n";
    if (!WinHttpSendRequest(
            handle, headers.c_str(), static_cast<DWORD>(headers.size()),
            const_cast<char *>(data.data()), static_cast<DWORD>(data.size()),
            static_cast<DWORD>(data.size()), 0) ||
        !WinHttpReceiveResponse(handle, nullptr)) {
      deadline.check();
      throw std::runtime_error(
          "model endpoint unavailable or HTTP transfer failed");
    }
    DWORD status = 0, size = sizeof(status);
    if (!WinHttpQueryHeaders(
            handle, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size,
            WINHTTP_NO_HEADER_INDEX) ||
        status != 200)
      throw std::runtime_error("model HTTP status " + std::to_string(status) +
                               "; no automatic retry");
    std::string wire;
    char chunk[8192];
    while (true) {
      deadline.check();
      DWORD n = 0;
      if (!WinHttpReadData(handle, chunk, sizeof(chunk), &n)) {
        deadline.check();
        throw std::runtime_error("model stream read failed");
      }
      if (!n)
        break;
      if (n > max_wire - wire.size())
        throw std::runtime_error("model response byte budget exceeded");
      wire.append(chunk, n);
    }
    close();
    return wire;
  } catch (...) {
    close();
    throw;
  }
#else
  BlockSigpipe no_sigpipe;
  Connection c;
  connect_socket(c, host, port, deadline);
  if (tls) {
    c.ctx = SSL_CTX_new(TLS_client_method());
    if (!c.ctx)
      throw std::runtime_error("model TLS initialization failed");
    SSL_CTX_set_verify(c.ctx, SSL_VERIFY_PEER, nullptr);
    if (SSL_CTX_set_default_verify_paths(c.ctx) != 1)
      throw std::runtime_error("system TLS trust store unavailable");
    SSL_CTX_set_min_proto_version(c.ctx, TLS1_2_VERSION);
    c.ssl = SSL_new(c.ctx);
    if (!c.ssl || SSL_set_fd(c.ssl, c.fd) != 1 ||
        SSL_set_tlsext_host_name(c.ssl, host.c_str()) != 1 ||
        SSL_set1_host(c.ssl, host.c_str()) != 1)
      throw std::runtime_error("model TLS identity setup failed");
    while (true) {
      deadline.check();
      auto n = SSL_connect(c.ssl);
      if (n == 1)
        break;
      tls_wait(c, n, deadline);
    }
  }
  std::string request = "POST " + path + " HTTP/1.1\r\nHost: " + host + ":" +
                        port +
                        "\r\nContent-Type: application/json\r\nAccept: "
                        "text/event-stream\r\nAccept-Encoding: "
                        "identity\r\nConnection: close\r\nContent-Length: " +
                        std::to_string(data.size()) + "\r\n";
  if (!secret.empty())
    request += "Authorization: Bearer " + secret + "\r\n";
  request += "\r\n" + data;
  for (std::size_t at = 0; at < request.size();) {
    deadline.check();
    auto n = tls ? SSL_write(c.ssl, request.data() + at,
                             static_cast<int>(request.size() - at))
                 : static_cast<int>(send(c.fd, request.data() + at,
                                         request.size() - at, MSG_NOSIGNAL));
    if (n > 0) {
      at += n;
      continue;
    }
    if (tls)
      tls_wait(c, n, deadline);
    else if (errno == EAGAIN || errno == EINTR)
      ready(c.fd, POLLOUT, deadline);
    else
      throw std::runtime_error("model request write failed");
  }
  std::string wire;
  char chunk[8192];
  while (true) {
    deadline.check();
    auto n = tls ? SSL_read(c.ssl, chunk, sizeof(chunk))
                 : static_cast<int>(recv(c.fd, chunk, sizeof(chunk), 0));
    if (n > 0) {
      if (static_cast<std::size_t>(n) > max_wire + 65536 - wire.size())
        throw std::runtime_error("model HTTP response budget exceeded");
      wire.append(chunk, n);
      continue;
    }
    if (n == 0 && (!tls || SSL_get_error(c.ssl, n) == SSL_ERROR_ZERO_RETURN))
      break;
    if (tls)
      tls_wait(c, n, deadline);
    else if (errno == EAGAIN || errno == EINTR)
      ready(c.fd, POLLIN, deadline);
    else
      throw std::runtime_error("model response read failed");
  }
  return http_body(wire);
#endif
}
} // namespace indago
