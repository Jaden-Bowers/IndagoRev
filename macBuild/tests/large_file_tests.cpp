#include "analysis.hpp"
#include "file_io.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <unistd.h>

using namespace macbuild;
namespace {
void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}
template<class Action> void Reject(Action action) {
  bool rejected = false;
  try { action(); } catch (const std::exception&) { rejected = true; }
  Require(rejected, "Expected invalid input to be rejected");
}
void Put(Bytes& data, std::size_t offset, std::uint64_t value, unsigned count) {
  for (unsigned i = 0; i < count; ++i)
    data[offset + i] = (value >> (8 * (count - 1 - i))) & 255;
}
void ChangeByte(const fs::path& path, std::size_t offset) {
  std::fstream file(path, std::ios::binary | std::ios::in | std::ios::out);
  file.seekp(offset); file.put('!'); file.flush();
  Require(bool(file), "Could not write test marker");
}
}

int main(int argc, char** argv) {
  const auto root = fs::temp_directory_path() / ("indago-large-" + std::to_string(getpid()));
  try {
    Require(argc == 2, "Expected compiled ARM64 fixture");
    fs::create_directories(root);
    const auto input = root / "large.macho";
    // Pad a real compiled program with trailing data. Its mapped code is intact,
    // so Ghidra can verify the full pipeline without a huge synthetic codebase.
    constexpr std::size_t largeSize = 320ULL * 1024 * 1024;
    fs::copy_file(argv[1], input);
    fs::resize_file(input, largeSize);
    ChangeByte(input, largeSize - 1);
    BinaryFile large(input);
    Require(Arm64Slice(large).size == largeSize, "Large thin file rejected");
    Require(large[largeSize - 1] == '!', "Header reader failed beyond old size limit");
    const auto project = Import(input, root / "workspace");
    Require(project.metadata.at("slice_size") == largeSize, "Input was truncated");
    Require(fs::file_size(project.directory / "original.bin") == largeSize, "Original copy truncated");
    Require(fs::file_size(project.directory / "arm64.macho") == largeSize, "Selected copy truncated");
    Require(LoadProject(project.directory).metadata == project.metadata, "Large project failed to reopen");
    WriteAtomic(project.directory / "notes.md", "Keep large-file notes");
    Require(Import(input, root / "workspace").directory == project.directory, "Reimport changed identity");
    const auto notes = ReadBytes(project.directory / "notes.md");
    Require(std::string(notes.begin(), notes.end()) == "Keep large-file notes", "Reimport lost notes");

    // Exercise the same validation used by the real background worker, including
    // Ghidra import of the entire 320 MiB file, without ever executing the sample.
    std::atomic_bool cancel{false};
    const auto report = Analyze(project, DefaultTools(), cancel);
    Require(report.at("target_executed") == false, "Unexpected execution flag");
    bool decoded = false;
    for (const auto& function : report.at("functions"))
      if (function.at("name") == "_decode_buffer")
        decoded = function.at("code").get<std::string>().find("0x5a") != std::string::npos;
    Require(decoded, "Large-file analysis did not recover the decoder");
    Require(LoadAnalysis(project).at("input_sha256") == project.metadata.at("slice_sha256"),
            "Persisted evidence lost its input identity");
    ChangeByte(project.directory / "arm64.macho", largeSize - 2);
    Reject([&] { LoadProject(project.directory); });
    fs::remove_all(project.directory); // Keep peak test disk usage modest.

    // Large universal containers must hash all bytes, but export only the ARM
    // slice. Place it near the end so offsets past 64 MiB are exercised too.
    const auto fixture = ReadBytes(argv[1]);
    const auto fatPath = root / "universal.macho";
    const std::size_t offset = largeSize;
    Bytes table(28);
    Put(table, 0, 0xcafebabe, 4); Put(table, 4, 1, 4);
    Put(table, 8, 0x0100000c, 4); Put(table, 16, offset, 4);
    Put(table, 20, fixture.size(), 4); Put(table, 24, 12, 4);
    WriteAtomic(fatPath, std::string(table.begin(), table.end()));
    {
      std::fstream file(fatPath, std::ios::binary | std::ios::in | std::ios::out);
      file.seekp(offset);
      file.write(reinterpret_cast<const char*>(fixture.data()), fixture.size());
      Require(bool(file), "Could not write universal fixture");
    }
    const auto fatProject = Import(fatPath, root / "workspace");
    Require(fatProject.metadata.at("slice_offset") == offset, "Large slice offset lost");
    Require(fatProject.metadata.at("slice_sha256") == Sha256(fixture), "Wrong slice extracted");
    Require(ReadBytes(fatProject.directory / "arm64.macho") == fixture, "Slice bytes differ");
    Require(LoadProject(fatProject.directory).metadata == fatProject.metadata, "Universal reopen failed");
    ChangeByte(fatProject.directory / "original.bin", offset - 1);
    Reject([&] { LoadProject(fatProject.directory); });
    fs::remove_all(fatProject.directory);

    // A sparse FAT64 file checks 64-bit offsets without allocating/copying GiBs.
    Bytes fat64(40);
    const std::size_t wideOffset = (1ULL << 32) + 4096;
    Put(fat64, 0, 0xcafebabf, 4); Put(fat64, 4, 1, 4);
    Put(fat64, 8, 0x0100000c, 4); Put(fat64, 16, wideOffset, 8);
    Put(fat64, 24, fixture.size(), 8); Put(fat64, 32, 12, 4);
    WriteAtomic(fatPath, std::string(fat64.begin(), fat64.end()));
    {
      std::fstream file(fatPath, std::ios::binary | std::ios::in | std::ios::out);
      file.seekp(wideOffset);
      file.write(reinterpret_cast<const char*>(fixture.data()), fixture.size());
      Require(bool(file), "Could not write FAT64 fixture");
    }
    BinaryFile wide(fatPath);
    Require(Arm64Slice(wide).offset == wideOffset, "64-bit slice offset truncated");
    Require(wide.Hash(wideOffset, fixture.size()) == Sha256(fixture), "64-bit range hashing failed");
    Reject([&] { wide.Hash(wide.size(), 1); });
    Reject([&] { wide.CopyAtomic(root / "bad-copy", 0, 40, "wrong hash"); });
    Require(!fs::exists(root / "bad-copy"), "Failed copy was published");
    fs::resize_file(fatPath, 40);
    Reject([&] { wide.Hash(wideOffset, fixture.size()); });
    Reject([&] { BinaryFile directory(root); });
    fs::remove_all(root);
    std::cout << "320 MiB import, analysis, persistence and universal-file checks passed\n";
  } catch (const std::exception& error) {
    fs::remove_all(root);
    std::cerr << error.what() << '\n';
    return 1;
  }
}
