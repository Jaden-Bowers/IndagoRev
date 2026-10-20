#include "project.hpp"
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using namespace macbuild;
void Require(bool value) { if (!value) throw std::runtime_error("Project assertion failed"); }
template<class F> void Reject(F action) {
  bool rejected = false;
  try { action(); } catch (const std::exception&) { rejected = true; }
  Require(rejected);
}
int main() {
  auto root = fs::temp_directory_path() / ("indago-project-" + std::to_string(getpid()));
  try {
    // Minimal structurally valid header; integration tests use compiled programs.
    Bytes header(32);
    header[0] = 0xcf; header[1] = 0xfa; header[2] = 0xed; header[3] = 0xfe;
    header[4] = 12; header[7] = 1; header[12] = 2;
    Require(Arm64Slice(header).size == 32);
    Require(Sha256({}) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    Reject([] { Arm64Slice({}); });
    auto x64 = header; x64[4] = 7;
    Reject([&] { Arm64Slice(x64); });
    auto arm64e = header; arm64e[8] = 2;
    Reject([&] { Arm64Slice(arm64e); });
    auto invalid = header; invalid[20] = 8;
    Reject([&] { Arm64Slice(invalid); });
    WriteAtomic(root / "sample", std::string(header.begin(), header.end()));
    auto p = Import(root / "sample", root / "workspace");
    Require(LoadProject(p.directory).metadata == p.metadata);
    WriteAtomic(p.directory / "notes.md", "Keep this note");
    Require(Import(root / "sample", root / "workspace").directory == p.directory);
    auto notes = ReadBytes(p.directory / "notes.md");
    Require(std::string(notes.begin(), notes.end()) == "Keep this note");
    WriteAtomic(p.directory / "arm64.macho", "corruption");
    Reject([&] { LoadProject(p.directory); });
    fs::remove_all(root);
    std::cout << "Project validation and persistence passed\n";
  } catch (const std::exception& error) {
    fs::remove_all(root);
    std::cerr << error.what() << '\n'; return 1;
  }
}
