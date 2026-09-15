#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "imgui_internal.h"
#include "imgui_stdlib.h"
#include "json.hpp"
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <d3d11.h>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <shellapi.h>
#include <shobjidl.h>
#include <string>
#include <thread>
#include <vector>
#include <windows.h>
using json = nlohmann::json;
namespace fs = std::filesystem;
static std::wstring wide(const std::string &s) {
  if (s.empty())
    return {};
  int n = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, s.data(),
                              (int)s.size(), nullptr, 0);
  if (!n)
    throw std::runtime_error("Invalid UTF-8 path");
  std::wstring r(n, 0);
  MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), r.data(), n);
  return r;
}
static std::string utf8(const std::wstring &s) {
  int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0,
                              nullptr, nullptr);
  std::string r(n, 0);
  WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), r.data(), n, nullptr,
                      nullptr);
  return r;
}
static std::string chooseFolder() {
  HRESULT initialized = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
  IFileOpenDialog *dialog = nullptr;
  std::string selected;
  if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr,
                                 CLSCTX_INPROC_SERVER,
                                 IID_PPV_ARGS(&dialog)))) {
    DWORD flags = 0;
    dialog->GetOptions(&flags);
    dialog->SetOptions(flags | FOS_PICKFOLDERS | FOS_FORCEFILESYSTEM);
    dialog->SetTitle(L"Choose your reverse-engineering project folder");
    if (SUCCEEDED(dialog->Show(nullptr))) {
      IShellItem *item = nullptr;
      if (SUCCEEDED(dialog->GetResult(&item))) {
        PWSTR name = nullptr;
        if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &name))) {
          selected = utf8(name);
          CoTaskMemFree(name);
        }
        item->Release();
      }
    }
    dialog->Release();
  }
  if (SUCCEEDED(initialized))
    CoUninitialize();
  return selected;
}
static std::wstring quote(const std::wstring &s) {
  std::wstring r = L"\"";
  unsigned slash = 0;
  for (auto c : s) {
    if (c == L'\\') {
      slash++;
      continue;
    }
    r.append(c == L'"' ? slash * 2 + 1 : slash, L'\\');
    slash = 0;
    r += c;
  }
  r.append(slash * 2, L'\\');
  return r + L'"';
}
class Bridge {
  HANDLE in = nullptr, out = nullptr, process = nullptr, job = nullptr;
  std::thread reader;
  std::mutex mutex;
  std::condition_variable capacity;
  bool stopping = false;
  std::deque<json> queue;

public:
  void start(const std::string &node, const std::string &script) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    HANDLE childIn = nullptr, childOut = nullptr;
    if (!CreatePipe(&childIn, &in, &sa, 0) ||
        !CreatePipe(&out, &childOut, &sa, 0))
      throw std::runtime_error("Cannot create worker pipes");
    SetHandleInformation(in, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(out, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = childIn;
    si.hStdOutput = childOut;
    HANDLE err = CreateFileW(L"NUL", GENERIC_WRITE, FILE_SHARE_WRITE, &sa,
                             OPEN_EXISTING, 0, nullptr);
    si.hStdError = err;
    PROCESS_INFORMATION pi{};
    auto cmd = quote(wide(node)) + L" " + quote(wide(script));
    BOOL ok = CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW | CREATE_SUSPENDED, nullptr,
                             nullptr, &si, &pi);
    CloseHandle(childIn);
    CloseHandle(childOut);
    CloseHandle(err);
    if (!ok)
      throw std::runtime_error(
          "Cannot start Node worker; check runtime and agent paths");
    process = pi.hProcess;
    job = CreateJobObjectW(nullptr, nullptr);
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags =
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!job ||
        !SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits)) ||
        !AssignProcessToJobObject(job, process)) {
      TerminateProcess(process, 1);
      CloseHandle(pi.hThread);
      throw std::runtime_error("Cannot contain worker process lifetime");
    }
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    reader = std::thread([this] {
      std::string pending;
      char bytes[8192];
      DWORD n;
      while (ReadFile(out, bytes, sizeof(bytes), &n, nullptr) && n) {
        pending.append(bytes, n);
        if (pending.size() > 8 * 1024 * 1024)
          break;
        size_t at;
        while ((at = pending.find('\n')) != std::string::npos) {
          auto s = pending.substr(0, at);
          pending.erase(0, at + 1);
          auto j = json::parse(s, nullptr, false);
          if (!j.is_discarded()) {
            std::unique_lock lock(mutex);
            capacity.wait(lock,
                          [this] { return stopping || queue.size() < 256; });
            if (stopping)
              return;
            queue.push_back(std::move(j));
          }
        }
      }
      std::lock_guard lock(mutex);
      queue.push_back({{"disconnected", true}});
    });
  }
  void send(const json &j) {
    auto s = j.dump() + "\n";
    DWORD written = 0;
    if (!in || !WriteFile(in, s.data(), (DWORD)s.size(), &written, nullptr) ||
        written != s.size())
      throw std::runtime_error("Worker disconnected");
  }
  std::deque<json> poll() {
    std::lock_guard lock(mutex);
    std::deque<json> r;
    r.swap(queue);
    capacity.notify_all();
    return r;
  }
  ~Bridge() {
    {
      std::lock_guard lock(mutex);
      stopping = true;
    }
    capacity.notify_all();
    if (in)
      CloseHandle(in);
    if (job)
      CloseHandle(job);
    else if (process)
      TerminateProcess(process, 0);
    if (reader.joinable())
      reader.join();
    if (out)
      CloseHandle(out);
    if (process)
      CloseHandle(process);
  }
};
struct View {
  struct Line {
    std::string text, id, function;
    int start = 0, end = 0;
    std::vector<std::pair<unsigned long long, unsigned long long>> addresses;
  };
  std::string id, text;
  int start = 0, end = 0;
  std::vector<Line> lines;
  int selected = -1, anchor = -1, scroll = -1;
};
static unsigned long long numeric(const std::string &s) {
  try {
    return std::stoull(s, nullptr, 16);
  } catch (...) {
    return 0;
  }
}
static int selectText(ImGuiInputTextCallbackData *d) {
  auto *v = (View *)d->UserData;
  v->start = std::min(d->SelectionStart, d->SelectionEnd);
  v->end = std::max(d->SelectionStart, d->SelectionEnd);
  return 0;
}
static bool unsaved = false;
struct App {
  Bridge bridge;
  bool connected = false, ready = false, busy = false, binary = false,
       dirty = false, quit = false;
  std::string root, exe,
      node = "node", agent, file, folder,
      status = "Choose a project folder to begin.", address, rename, prototype,
      symbol, typePath, analysisFolder, pendingBinary, initialAddress,
      contextSource = "Refresh provider to read its configured limit";
  bool analyzePopup = false, initialJump = false, providerLoaded = false;
  std::string prompt, chat, stream,
      provider = "lmstudio", endpoint = "http://127.0.0.1:1234/v1",
      model = "huihui-qwen3.8-27b-abliterated", keyEnv;
  int context = 0, output = 2048;
  long long inputTokens = 0, outputTokens = 0, totalOutput = 0;
  double rate = 0;
  std::chrono::steady_clock::time_point chatStart;
  bool chatting = false;
  json files = json::array(), functions = json::array(), refs = json::array(),
       detail;
  std::string cursor;
  long long revision = -1;
  View source, decomp, assembly;
  int serial = 0;
  std::map<int, json> pending;
  void request(json r) {
    try {
      int id = ++serial;
      r["id"] = id;
      pending[id] = r;
      bridge.send(r);
      if (r["op"] != "cancel")
        busy = true;
      status = "Working: " + r["op"].get<std::string>();
    } catch (const std::exception &e) {
      status = e.what();
      busy = false;
    }
  }
  void query(std::string op, std::string next = "") {
    request({{"op", "query"},
             {"operation", op},
             {"address", address},
             {"cursor", next}});
  }
  void log(const std::string &s) {
    chat += s;
    if (chat.size() > 256 * 1024) {
      auto p = chat.find('\n', chat.size() - 200 * 1024);
      chat.erase(0, p == std::string::npos ? chat.size() : p + 1);
    }
  }
  void useView(View &v, const json &j) {
    v.id = j.value("id", "");
    v.text = j.value("text", "");
    v.start = v.end = 0;
  }
  void appendListing(const json &j) {
    auto &v = j.value("kind", "") == "tokens" ? decomp : assembly;
    const std::string text = j.value("text", ""), id = j.value("id", ""),
                      fn = j.value("address", "");
    auto tokens = j.value("tokens", json::array());
    if (!fn.empty() && !j.value("continuation", false))
      v.lines.push_back({"// " + j.value("label", fn) + "  " + fn, id, fn});
    size_t at = 0;
    int offset16 = 0;
    while (at < text.size()) {
      auto end = text.find('\n', at);
      if (end == std::string::npos)
        end = text.size();
      else
        ++end;
      auto lineText = text.substr(at, end - at);
      int end16 = offset16 + (int)wide(lineText).size();
      View::Line line{lineText, id, fn, (int)at + j.value("byte_base", 0),
                      (int)end + j.value("byte_base", 0)};
      for (auto &t : tokens)
        if (t.value("rendered_offset", 0) < end16 &&
            t.value("rendered_end", 0) > offset16 &&
            t.contains("min_address") && t["min_address"].is_string()) {
          auto lo = numeric(t["min_address"].get<std::string>());
          auto hi = t.contains("max_address") && t["max_address"].is_string()
                        ? numeric(t["max_address"].get<std::string>())
                        : lo;
          line.addresses.push_back({lo, hi});
        }
      if (!line.text.empty() && line.text.back() == '\n')
        line.text.pop_back();
      v.lines.push_back(std::move(line));
      at = end;
      offset16 = end16;
    }
    if (!initialJump && fn == initialAddress) {
      jump(initialAddress);
      initialJump = true;
    }
  }
  void focusLine(View &v, int at) {
    v.scroll = v.selected = v.anchor = at;
    v.id.clear();
    v.start = v.end = 0;
    if (at >= 0 && at < (int)v.lines.size()) {
      auto &line = v.lines[at];
      v.id = line.id;
      v.start = line.start;
      v.end = line.end;
    }
  }
  void jump(const std::string &where) {
    const auto n = numeric(where);
    address = where;
    for (auto *v : {&decomp, &assembly}) {
      int fallback = -1, match = -1;
      for (size_t i = 0; i < v->lines.size(); ++i) {
        auto &line = v->lines[i];
        if (fallback < 0 && line.function == where)
          fallback = (int)i;
        for (auto [lo, hi] : line.addresses)
          if (n >= lo && n <= hi) {
            match = (int)i;
            break;
          }
        if (match >= 0)
          break;
      }
      focusLine(*v, match >= 0 ? match : fallback);
    }
    for (auto &f : functions)
      if (f.value("entry", "") == where) {
        rename = f.value("name", "");
        prototype = f.value("signature", "");
        break;
      }
  }
  void synchronize(View &from, View &to, const View::Line &line) {
    std::string fn = line.function;
    if (fn.empty() && !line.addresses.empty())
      for (auto &f : functions)
        for (auto &r : f.value("ranges", json::array()))
          if (line.addresses[0].first >= numeric(r.value("min", "")) &&
              line.addresses[0].first <= numeric(r.value("max", "")))
            fn = f.value("entry", "");
    if (!fn.empty()) {
      address = fn;
      for (auto &f : functions)
        if (f.value("entry", "") == fn) {
          rename = f.value("name", "");
          prototype = f.value("signature", "");
        }
    }
    int fallback = -1;
    for (size_t i = 0; i < to.lines.size(); i++) {
      const auto &other = to.lines[i];
      if (fallback < 0 && !fn.empty() && other.function == fn)
        fallback = (int)i;
      if (fallback < 0 && !fn.empty())
        for (auto [a, b] : other.addresses)
          if (numeric(fn) >= a && numeric(fn) <= b)
            fallback = (int)i;
      for (auto [lo, hi] : line.addresses)
        for (auto [a, b] : other.addresses)
          if (lo <= b && a <= hi) {
            focusLine(to, (int)i);
            return;
          }
    }
    focusLine(to, fallback);
    status = "No direct Ghidra address mapping for this line; showing "
             "containing function when available.";
  }
  json providerRequest(const char *op) {
    return {{"op", op},
            {"provider", provider},
            {"endpoint", endpoint},
            {"model", model},
            {"apiKeyEnv", keyEnv}};
  }
  void pump() {
    for (auto &r : bridge.poll())
      try {
        if (r.contains("program_functions")) {
          for (auto &f : r["program_functions"])
            functions.push_back(f);
          continue;
        }
        if (r.contains("provider_info")) {
          auto &p = r["provider_info"];
          context = p["contextTokens"].is_number_integer()
                        ? p["contextTokens"].get<int>()
                        : 0;
          contextSource = p.value("source", "");
          continue;
        }
        if (r.contains("progress")) {
          status = r["progress"].get<std::string>();
          continue;
        }
        if (r.contains("program")) {
          auto &p = r["program"];
          file = p.value("file", "");
          functions = p["functions"];
          initialAddress = p.value("initial", "");
          revision = p.value("revision", -1LL);
          binary = true;
          decomp = {};
          assembly = {};
          refs = json::array();
          initialJump = false;
          continue;
        }
        if (r.contains("listing")) {
          appendListing(r["listing"]);
          continue;
        }
        if (r.value("disconnected", false)) {
          connected = ready = busy = false;
          status = "Worker exited. Restart workbench to reconnect.";
          continue;
        }
        if (r.contains("event")) {
          auto &e = r["event"];
          auto kind = e.value("type", "");
          if (kind == "message_update" && e.contains("assistantMessageEvent")) {
            auto &a = e["assistantMessageEvent"];
            if (a.value("type", "") == "text_delta")
              stream += a.value("delta", "");
          }
          if (kind == "message_end" && e.contains("message")) {
            auto &m = e["message"];
            if (m.value("role", "") == "assistant") {
              std::string text;
              for (auto &c : m.value("content", json::array()))
                if (c.value("type", "") == "text")
                  text += c.value("text", "");
              if (m.value("stopReason", "") == "error")
                log("\nProvider error: " + m.value("errorMessage", "unknown") +
                    "\n");
              if (!text.empty())
                log("\nAgent:\n" + text + "\n");
              stream.clear();
              if (m.contains("usage")) {
                auto &u = m["usage"];
                inputTokens = u.value("input", 0LL) + u.value("cacheRead", 0LL);
                outputTokens = u.value("output", 0LL);
                totalOutput += outputTokens;
              }
            }
          }
          if (kind == "tool_execution_start")
            status = "Agent tool: " + e.value("toolName", "");
          if (chatting) {
            double seconds = std::chrono::duration<double>(
                                 std::chrono::steady_clock::now() - chatStart)
                                 .count();
            rate = seconds > 0 ? totalOutput / seconds : 0;
          }
          continue;
        }
        int id = r.value("id", 0);
        if (!pending.contains(id))
          continue;
        auto req = pending[id];
        pending.erase(id);
        if (req["op"] != "cancel")
          busy = false;
        if (!r.value("ok", false)) {
          status = r.value("error", "Unknown worker error");
          if (req["op"] == "chat") {
            chatting = false;
            log("\nError: " + status + "\n");
          }
          continue;
        }
        auto d = r.value("data", json::object());
        std::string op = req.value("op", "");
        status = "Ready";
        if (op == "init") {
          ready = true;
          chat = d.value("history", "");
          if (d.contains("settings") && d["settings"].is_object()) {
            auto &s = d["settings"];
            provider = s.value("provider", provider);
            endpoint = s.value("endpoint", endpoint);
            model = s.value("model", model);
            keyEnv = s.value("apiKeyEnv", keyEnv);
            output = s.value("outputTokens", output);
          }
          request({{"op", "tree"}});
          analysisFolder = d.value("state", "");
        } else if (op == "tree") {
          files = d["files"];
          folder = d.value("path", "");
          if (!providerLoaded) {
            providerLoaded = true;
            request(providerRequest("provider"));
          }
        } else if (op == "open") {
          if (d.value("binary", false)) {
            pendingBinary = d.value("file", "");
            if (d.value("previous_analysis", false))
              request({{"op", "program"}, {"path", pendingBinary}});
            else
              analyzePopup = true;
            continue;
          }
          binary = d.value("binary", false);
          dirty = false;
          refs = json::array();
          functions = json::array();
          address.clear();
          revision = -1;
          decomp = {};
          assembly = {};
          source = {};
          detail = {};
          if (binary) {
            file = d.value("file", "");
            query("functions");
          } else {
            useView(source, d["view"]);
            file = d["view"].value("file", "");
          }
        } else if (op == "save") {
          useView(source, d);
          dirty = false;
          refs = json::array();
        } else if (op == "reference") {
          refs.push_back(d);
          for (const auto &location : d.value("locations", json::array())) {
            if (location.contains("symbol_id") &&
                location["symbol_id"].is_string()) {
              symbol = location["symbol_id"].get<std::string>();
              typePath = location.value("type_path", "");
              break;
            }
          }
        } else if (op == "query") {
          auto result = d.value("result", json::object());
          detail = result;
          auto data = result.value("data", json::object());
          if (data.contains("program_revision"))
            revision = data["program_revision"].get<long long>();
          auto operation = req.value("operation", "");
          if (operation == "functions") {
            auto list = data.value("functions", json::array());
            if (req.value("cursor", "").empty())
              functions = list;
            else
              for (auto &f : list)
                functions.push_back(f);
            auto p = data.value("pagination", json::object());
            cursor = p.contains("next_cursor") && p["next_cursor"].is_string()
                         ? p["next_cursor"].get<std::string>()
                         : "";
          }
          if (d.contains("view")) {
            if (operation == "tokens")
              useView(decomp, d["view"]);
            else
              useView(assembly, d["view"]);
          }
          status = "Analysis: " +
                   result.value("status", data.value("status", "unknown")) +
                   "; inspect Evidence for partial results";
          if (operation == "tokens" && d.contains("view") &&
              assembly.id.empty())
            query("assembly");
        } else if (op == "annotate") {
          detail = d;
          refs = json::array();
          decomp = {};
          assembly = {};
          status = "Edit receipt received; reloading changed decompilation";
          request({{"op", "program"}, {"path", file}, {"confirm", true}});
        } else if (op == "program") {
          revision = d.value("revision", -1LL);
          jump(d.value("initial", initialAddress));
          status =
              "Saved analysis: " + std::to_string(d.value("functions", 0)) +
              " functions; " + std::to_string(d.value("incomplete", 0)) +
              " incomplete decompilations" +
              (d.value("assembly_incomplete", false)
                   ? "; instruction listing partial"
                   : "") +
              (d.value("inventory_incomplete", false)
                   ? "; function inventory partial"
                   : "");
        } else if (op == "provider") {
          context = d["contextTokens"].is_number_integer()
                        ? d["contextTokens"].get<int>()
                        : 0;
          contextSource = d.value("source", "");
        } else if (op == "chat") {
          chatting = false;
          refs = json::array();
          status = "Agent stopped (code " + d.value("code", json(0)).dump() +
                   "). Review claims; not independently verified.";
          if (d.value("timedOut", false))
            status = "Agent deadline reached; inspect interrupted effects.";
        }
      } catch (const std::exception &e) {
        status = std::string("Response error: ") + e.what();
        busy = false;
      }
  }
  void reference(View &v) {
    ImGui::BeginDisabled(busy || v.id.empty() || v.start == v.end || dirty);
    if (ImGui::Button("AI reference"))
      request({{"op", "reference"},
               {"view", v.id},
               {"start", v.start},
               {"end", v.end}});
    ImGui::EndDisabled();
    ImGui::SameLine();
    ImGui::TextDisabled("Highlight text first (%d bytes)", v.end - v.start);
  }
  void code(const char *title, View &v, bool editable) {
    ImGui::Begin(title);
    if (binary) {
      reference(v);
      ImGui::TextDisabled(
          "Click to synchronize; Shift-click to select lines for AI reference");
      ImGui::BeginChild("listing", ImVec2(0, 0), ImGuiChildFlags_None,
                        ImGuiWindowFlags_HorizontalScrollbar);
      ImGuiListClipper clipper;
      clipper.Begin((int)v.lines.size());
      if (v.scroll >= 0 && v.scroll < (int)v.lines.size())
        clipper.IncludeItemByIndex(v.scroll);
      while (clipper.Step())
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
          auto &line = v.lines[i];
          ImGui::PushID(i);
          const auto pos = ImGui::GetCursorScreenPos();
          if (ImGui::Selectable(
                  "##line",
                  i == v.selected ||
                      (v.anchor >= 0 && i >= std::min(v.anchor, v.selected) &&
                       i <= std::max(v.anchor, v.selected) && line.id == v.id),
                  ImGuiSelectableFlags_None,
                  ImVec2(std::max(ImGui::GetContentRegionAvail().x,
                                  ImGui::CalcTextSize(line.text.c_str()).x),
                         0))) {
            int anchor = ImGui::GetIO().KeyShift ? v.anchor : i;
            if (anchor < 0 || v.lines[anchor].id != line.id)
              anchor = i;
            v.anchor = anchor;
            v.selected = i;
            v.id = line.id;
            v.start = v.lines[std::min(anchor, i)].start;
            v.end = v.lines[std::max(anchor, i)].end;
            synchronize(v, &v == &decomp ? assembly : decomp, line);
          }
          ImGui::GetWindowDrawList()->AddText(
              pos, ImGui::GetColorU32(ImGuiCol_Text), line.text.c_str(),
              line.text.c_str() + line.text.size());
          if (v.scroll == i) {
            ImGui::SetScrollHereY(.3f);
            v.scroll = -1;
          }
          ImGui::PopID();
        }
      ImGui::EndChild();
      ImGui::End();
      return;
    }
    reference(v);
    ImGuiInputTextFlags flags =
        ImGuiInputTextFlags_CallbackAlways | ImGuiInputTextFlags_AllowTabInput;
    if (!editable)
      flags |= ImGuiInputTextFlags_ReadOnly;
    if (ImGui::InputTextMultiline("##text", &v.text, ImVec2(-1, -1), flags,
                                  selectText, &v) &&
        editable)
      dirty = true;
    ImGui::End();
  }
  void render() {
    pump();
    unsaved = dirty;
    auto dock = ImGui::DockSpaceOverViewport(0, ImGui::GetMainViewport());
    if (!ImGui::DockBuilderGetNode(dock)->IsSplitNode()) {
      static bool first = true;
      if (first) {
        first = false;
        ImGui::DockBuilderRemoveNode(dock);
        ImGui::DockBuilderAddNode(dock, ImGuiDockNodeFlags_DockSpace);
        ImGui::DockBuilderSetNodeSize(dock, ImGui::GetMainViewport()->WorkSize);
        auto center = dock;
        auto left = ImGui::DockBuilderSplitNode(center, ImGuiDir_Left, .20f,
                                                nullptr, &center);
        auto right = ImGui::DockBuilderSplitNode(center, ImGuiDir_Right, .36f,
                                                 nullptr, &center);
        auto bottom = ImGui::DockBuilderSplitNode(center, ImGuiDir_Down, .40f,
                                                  nullptr, &center);
        ImGui::DockBuilderDockWindow("Project", left);
        ImGui::DockBuilderDockWindow("Decompiler / Source", center);
        ImGui::DockBuilderDockWindow("Disassembler", bottom);
        ImGui::DockBuilderDockWindow("Agent Chat", right);
        ImGui::DockBuilderDockWindow("Agent Settings", right);
        ImGui::DockBuilderDockWindow("Evidence / Edits", bottom);
        ImGui::DockBuilderFinish(dock);
      }
    }
    ImGui::Begin("Project");
    ImGui::BeginDisabled(connected);
    ImGui::TextUnformatted("Project folder");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##Folder", &root);
    ImGui::TextUnformatted("Analysis folder (optional)");
    ImGui::SetNextItemWidth(-1);
    ImGui::InputText("##AnalysisFolder", &analysisFolder);
    if (ImGui::Button("Choose analysis storage...")) {
      auto selected = chooseFolder();
      if (!selected.empty())
        analysisFolder = selected;
    }
    bool picked = false;
    if (ImGui::Button("Choose folder...")) {
      auto selected = chooseFolder();
      if (!selected.empty()) {
        root = selected;
        picked = true;
      }
    }
    if (ImGui::CollapsingHeader("Advanced runtime paths")) {
      ImGui::InputText("Native CLI", &exe);
      ImGui::InputText("Node", &node);
      ImGui::InputText("Agent bridge", &agent);
    }
    if (ImGui::Button("Open project") || picked)
      try {
        if (root.empty() || !fs::is_directory(fs::path(wide(root))))
          throw std::runtime_error("Choose an existing project folder");
        if (!fs::is_regular_file(fs::path(wide(exe))) ||
            !fs::is_regular_file(fs::path(wide(agent))))
          throw std::runtime_error(
              "Package is incomplete: native CLI or agent bridge is missing");
        bridge.start(node, agent);
        connected = true;
        request({{"op", "init"},
                 {"cwd", root},
                 {"exe", exe},
                 {"state", analysisFolder}});
      } catch (const std::exception &e) {
        status = e.what();
      }
    ImGui::EndDisabled();
    if (analyzePopup) {
      ImGui::OpenPopup("Analyze binary?");
      analyzePopup = false;
    }
    ImGui::SetNextWindowSize(ImVec2(600, 0), ImGuiCond_Appearing);
    if (ImGui::BeginPopupModal("Analyze binary?", nullptr,
                               ImGuiWindowFlags_AlwaysAutoResize)) {
      ImGui::TextWrapped("Analyze %s with Ghidra?", pendingBinary.c_str());
      ImGui::TextWrapped("Runs standard static analysis, then decompiles all "
                         "discovered functions. Does not execute the target.");
      ImGui::TextWrapped("Saved under: %s", analysisFolder.c_str());
      if (ImGui::Button("Analyze")) {
        request(
            {{"op", "program"}, {"path", pendingBinary}, {"confirm", true}});
        ImGui::CloseCurrentPopup();
      }
      ImGui::SameLine();
      if (ImGui::Button("Cancel"))
        ImGui::CloseCurrentPopup();
      ImGui::EndPopup();
    }
    ImGui::TextWrapped("%s", status.c_str());
    if (busy && ImGui::Button("Cancel operation"))
      request({{"op", "cancel"}});
    ImGui::BeginDisabled(!ready || busy || dirty);
    if (ImGui::Button("Up") && !folder.empty())
      request({{"op", "tree"},
               {"path", utf8(fs::path(wide(folder)).parent_path().wstring())}});
    ImGui::SameLine();
    if (ImGui::Button("Refresh"))
      request({{"op", "tree"}, {"path", folder}});
    ImGui::BeginChild("files", ImVec2(0, 180), ImGuiChildFlags_Borders);
    for (auto &f : files) {
      auto name =
          (f.value("directory", false) ? "[+] " : "") + f.value("name", "");
      if (ImGui::Selectable(name.c_str()))
        request({{"op", f.value("directory", false) ? "tree" : "open"},
                 {"path", f["path"]}});
    }
    ImGui::EndChild();
    ImGui::EndDisabled();
    if (dirty) {
      ImGui::TextWrapped(
          "Unsaved changes: Save or Discard before navigating/referencing.");
      if (ImGui::Button("Save") && !busy)
        request({{"op", "save"}, {"view", source.id}, {"text", source.text}});
      ImGui::SameLine();
      if (ImGui::Button("Discard") && !busy)
        request({{"op", "open"}, {"path", file}});
    }
    ImGui::TextWrapped("%s", file.c_str());
    ImGui::SeparatorText("Functions (Ghidra)");
    ImGui::BeginDisabled(busy || !binary);
    if (ImGui::Button("Reload saved analysis"))
      request({{"op", "program"}, {"path", file}});
    ImGui::InputText("Address", &address);
    if (ImGui::Button("Go to address"))
      jump(address);
    for (auto &f : functions) {
      auto entry = f.value("entry", "");
      std::string label = f.value("name", "?") + " " + entry;
      if (ImGui::Selectable(label.c_str(), address == entry)) {
        address = entry;
        rename = f.value("name", "");
        prototype = f.value("signature", "");
        jump(entry);
      }
    }
    if (!cursor.empty() && ImGui::Button("More functions"))
      query("functions", cursor);
    ImGui::EndDisabled();
    ImGui::End();
    code("Decompiler / Source", binary ? decomp : source,
         !binary && !source.id.empty() && !busy);
    code("Disassembler", assembly, false);
    ImGui::Begin("Evidence / Edits");
    ImGui::Text("Ghidra revision: %lld", revision);
    ImGui::TextWrapped("Edits are user assertions, not proven facts. Changes "
                       "persist in Ghidra's Program database.");
    ImGui::BeginDisabled(busy || !binary || revision < 0 || address.empty());
    ImGui::InputText("Function name", &rename);
    if (ImGui::Button("Rename function"))
      request({{"op", "annotate"},
               {"address", address},
               {"revision", revision},
               {"annotation", {{"kind", "rename"}, {"name", rename}}}});
    ImGui::InputText("C prototype", &prototype);
    if (ImGui::Button("Apply signature"))
      request(
          {{"op", "annotate"},
           {"address", address},
           {"revision", revision},
           {"annotation", {{"kind", "signature"}, {"prototype", prototype}}}});
    if (ImGui::Button("List variables"))
      query("variables");
    ImGui::SameLine();
    if (ImGui::Button("List types"))
      query("types");
    ImGui::SameLine();
    if (ImGui::Button("Xrefs"))
      query("xrefs");
    ImGui::InputText("Symbol ID", &symbol);
    ImGui::InputText("Existing type path", &typePath);
    if (ImGui::Button("Retype variable"))
      request({{"op", "annotate"},
               {"address", address},
               {"revision", revision},
               {"annotation",
                {{"kind", "variable_type"},
                 {"symbol_id", symbol},
                 {"type_path", typePath}}}});
    ImGui::EndDisabled();
    std::string evidence = detail.dump(2);
    ImGui::InputTextMultiline("##evidence", &evidence, ImVec2(-1, -1),
                              ImGuiInputTextFlags_ReadOnly);
    ImGui::End();
    ImGui::Begin("Agent Settings");
    ImGui::TextWrapped(
        "OpenAI-compatible providers. Remote requests send selected evidence "
        "and agent tool context to that provider.");
    ImGui::BeginDisabled(busy);
    int choice = provider == "lmstudio" ? 0 : provider == "openrouter" ? 1 : 2;
    const char *names[] = {"LM Studio (local)", "OpenRouter",
                           "Other OpenAI-compatible"};
    if (ImGui::Combo("Provider", &choice, names, 3)) {
      provider = choice == 0   ? "lmstudio"
                 : choice == 1 ? "openrouter"
                               : "custom";
      endpoint = choice == 0   ? "http://127.0.0.1:1234/v1"
                 : choice == 1 ? "https://openrouter.ai/api/v1"
                               : "https://api.openai.com/v1";
      keyEnv = choice == 0   ? ""
               : choice == 1 ? "OPENROUTER_API_KEY"
                             : "OPENAI_API_KEY";
    }
    ImGui::InputText("Endpoint", &endpoint);
    ImGui::InputText("Model ID", &model);
    ImGui::InputText("API key env var", &keyEnv);
    if (ImGui::Button("Refresh provider context") && ready)
      request(providerRequest("provider"));
    if (context > 0)
      ImGui::Text("Provider context: %d tokens (read only)", context);
    else
      ImGui::TextDisabled("Provider context: unknown");
    ImGui::TextWrapped("%s", contextSource.c_str());
    ImGui::InputInt("Max output tokens", &output);
    ImGui::EndDisabled();
    ImGui::Text("Last input (incl cache): %lld / %d", inputTokens, context);
    ImGui::ProgressBar(context > 0 ? std::min(1.f, float(inputTokens) / context)
                                   : 0);
    ImGui::Text("Last output: %lld tokens", outputTokens);
    ImGui::Text("Effective output: %.1f tok/s", rate);
    ImGui::TextWrapped(
        "Rate = completed output tokens / whole request elapsed time, "
        "including tools and prefill. Not server decode speed. Context is "
        "read from the provider and refreshed before each chat. API "
        "keys are never saved by the GUI.");
    ImGui::End();
    ImGui::Begin("Agent Chat");
    ImGui::TextWrapped(
        "Pair mode | target execution prohibited by policy, NOT sandboxed");
    std::string shown =
        chat + (stream.empty() ? "" : "\nAgent (streaming):\n" + stream);
    ImGui::InputTextMultiline(
        "##chat", &shown,
        ImVec2(-1, std::max(100.f, ImGui::GetContentRegionAvail().y - 200)),
        ImGuiInputTextFlags_ReadOnly | ImGuiInputTextFlags_WordWrap);
    for (size_t i = 0; i < refs.size(); i++) {
      auto &r = refs[i];
      ImGui::PushID((int)i);
      ImGui::Text("Reference: %s, line %d", r.value("view", "").c_str(),
                  r.value("line_start", 0));
      if (ImGui::IsItemHovered())
        ImGui::SetTooltip("%s", r.value("text", "").c_str());
      ImGui::SameLine();
      if (ImGui::SmallButton("Remove")) {
        if (!busy)
          request({{"op", "remove_reference"}, {"reference", refs[i]["id"]}});
        refs.erase(i);
        ImGui::PopID();
        break;
      }
      ImGui::PopID();
    }
    ImGui::InputTextMultiline("##prompt", &prompt, ImVec2(-1, 85),
                              ImGuiInputTextFlags_WordWrap);
    ImGui::BeginDisabled(busy || !ready || file.empty() || prompt.empty() ||
                         dirty);
    if (ImGui::Button("Send")) {
      json ids = json::array();
      for (auto &r : refs)
        ids.push_back(r["id"]);
      log("\nYou:\n" + prompt + "\n");
      chatStart = std::chrono::steady_clock::now();
      chatting = true;
      totalOutput = 0;
      rate = 0;
      request({{"op", "chat"},
               {"text", prompt},
               {"references", ids},
               {"provider", provider},
               {"endpoint", endpoint},
               {"model", model},
               {"apiKeyEnv", keyEnv},
               {"outputTokens", output}});
      prompt.clear();
    }
    ImGui::EndDisabled();
    ImGui::End();
    unsaved = dirty;
  }
};
static ID3D11Device *device;
static ID3D11DeviceContext *context;
static IDXGISwapChain *swap;
static ID3D11RenderTargetView *target;
static void makeTarget() {
  ID3D11Texture2D *b = nullptr;
  if (SUCCEEDED(swap->GetBuffer(0, IID_PPV_ARGS(&b)))) {
    device->CreateRenderTargetView(b, nullptr, &target);
    b->Release();
  }
}
extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM,
                                                             LPARAM);
static LRESULT WINAPI wndProc(HWND w, UINT m, WPARAM a, LPARAM b) {
  if (ImGui_ImplWin32_WndProcHandler(w, m, a, b))
    return true;
  if (m == WM_SIZE && device && a != SIZE_MINIMIZED) {
    if (target) {
      target->Release();
      target = nullptr;
    }
    swap->ResizeBuffers(0, LOWORD(b), HIWORD(b), DXGI_FORMAT_UNKNOWN, 0);
    makeTarget();
    return 0;
  }
  if (m == WM_CLOSE) {
    if (unsaved &&
        MessageBoxW(w, L"Discard unsaved source edits and exit?",
                    L"Unsaved edits", MB_YESNO | MB_ICONWARNING) != IDYES)
      return 0;
    PostQuitMessage(0);
    return 0;
  }
  return DefWindowProcW(w, m, a, b);
}
int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int) {
  try {
    App app;
    wchar_t module[32768];
    GetModuleFileNameW(nullptr, module, 32768);
    auto base = fs::path(module).parent_path();
    app.root = "";
    app.exe = utf8((base / L"indago.exe").wstring());
    app.agent = utf8((base / L"agent" / L"desktop.mjs").wstring());
    if (fs::exists(base / L"runtime" / L"node.exe"))
      app.node = utf8((base / L"runtime" / L"node.exe").wstring());
    int argc = 0;
    auto argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    for (int i = 1; i + 1 < argc; i += 2) {
      auto k = utf8(argv[i]), v = utf8(argv[i + 1]);
      if (k == "--project")
        app.root = v;
      else if (k == "--exe")
        app.exe = v;
      else if (k == "--node")
        app.node = v;
      else if (k == "--agent")
        app.agent = v;
    }
    LocalFree(argv);
    ImGui_ImplWin32_EnableDpiAwareness();
    WNDCLASSEXW wc{sizeof(wc),         CS_CLASSDC, wndProc, 0,       0,
                   instance,           nullptr,    nullptr, nullptr, nullptr,
                   L"IndagoWorkbench", nullptr};
    RegisterClassExW(&wc);
    HWND window = CreateWindowW(wc.lpszClassName, L"IndagoRev - Pair Reversing",
                                WS_OVERLAPPEDWINDOW, 100, 100, 1500, 950,
                                nullptr, nullptr, instance, nullptr);
    DXGI_SWAP_CHAIN_DESC sd{};
    sd.BufferCount = 2;
    sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    sd.OutputWindow = window;
    sd.SampleDesc.Count = 1;
    sd.Windowed = TRUE;
    sd.SwapEffect = DXGI_SWAP_EFFECT_FLIP_DISCARD;
    D3D_FEATURE_LEVEL level;
    HRESULT hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, nullptr, 0,
        D3D11_SDK_VERSION, &sd, &swap, &device, &level, &context);
    if (FAILED(hr))
      hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr,
                                         0, nullptr, 0, D3D11_SDK_VERSION, &sd,
                                         &swap, &device, &level, &context);
    if (FAILED(hr))
      throw std::runtime_error("D3D11 initialization failed");
    makeTarget();
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().ConfigFlags |=
        ImGuiConfigFlags_DockingEnable | ImGuiConfigFlags_NavEnableKeyboard;
    ImGui::GetIO().IniFilename = nullptr;
    ImGui::StyleColorsDark();
    ImGui::GetStyle().FontSizeBase = 16.f;
    ImGui::GetStyle().Colors[ImGuiCol_FrameBg] = ImVec4(.08f, .09f, .11f, 1);
    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(device, context);
    ShowWindow(window, SW_SHOWDEFAULT);
    bool done = false;
    while (!done) {
      MSG msg;
      while (PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
        if (msg.message == WM_QUIT)
          done = true;
      }
      if (done)
        break;
      if (IsIconic(window)) {
        Sleep(50);
        continue;
      }
      ImGui_ImplDX11_NewFrame();
      ImGui_ImplWin32_NewFrame();
      ImGui::NewFrame();
      app.render();
      ImGui::Render();
      float clear[]{.07f, .08f, .1f, 1};
      context->OMSetRenderTargets(1, &target, nullptr);
      context->ClearRenderTargetView(target, clear);
      ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
      swap->Present(1, 0);
    }
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    if (target)
      target->Release();
    swap->Release();
    context->Release();
    device->Release();
    DestroyWindow(window);
    UnregisterClassW(wc.lpszClassName, instance);
    return 0;
  } catch (const std::exception &e) {
    MessageBoxA(nullptr, e.what(), "IndagoRev startup error",
                MB_OK | MB_ICONERROR);
    return 1;
  }
}
