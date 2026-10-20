#import <Foundation/Foundation.h>
#include "bundle.hpp"
#include "file_io.hpp"
#include <iostream>
#include <unistd.h>

using namespace macbuild;
namespace {
void Require(bool value) {
  if (!value) throw std::runtime_error("Bundle assertion failed");
}
template<class F> void Reject(F action) {
  bool rejected = false;
  try { action(); } catch (const std::exception&) { rejected = true; }
  Require(rejected);
}
void Plist(const fs::path& app, id value, NSPropertyListFormat format = NSPropertyListXMLFormat_v1_0) {
  NSData* data = [NSPropertyListSerialization dataWithPropertyList:value format:format options:0 error:nil];
  Require(data != nil);
  WriteAtomic(app / "Contents/Info.plist", std::string(static_cast<const char*>(data.bytes), data.length));
}
void Put(Bytes& bytes, std::size_t at, std::uint32_t value, bool big) {
  for (unsigned i = 0; i < 4; ++i) bytes[at + i] = (value >> (8 * (big ? 3 - i : i))) & 255;
}
Bytes Thin(std::uint32_t subtype) {
  Bytes bytes(32);
  Put(bytes, 0, 0xfeedfacf, false); Put(bytes, 4, 0x0100000c, false);
  Put(bytes, 8, subtype, false); Put(bytes, 12, 2, false);
  return bytes;
}
Bytes Fat(std::uint32_t first, std::uint32_t second) {
  Bytes bytes(12288);
  Put(bytes, 0, 0xcafebabe, true); Put(bytes, 4, 2, true);
  for (int i = 0; i < 2; ++i) {
    const auto at = 8 + i * 20;
    const auto subtype = i ? second : first;
    const auto offset = (i + 1) * 4096;
    Put(bytes, at, 0x0100000c, true); Put(bytes, at + 4, subtype, true);
    Put(bytes, at + 8, offset, true); Put(bytes, at + 12, 32, true);
    Put(bytes, at + 16, 12, true);
    const auto thin = Thin(subtype);
    std::copy(thin.begin(), thin.end(), bytes.begin() + offset);
  }
  return bytes;
}
}

int main(int argc, char** argv) {
  const auto root = fs::temp_directory_path() / ("indago-bundle-" + std::to_string(getpid()));
  @autoreleasepool {
    try {
      Require(argc == 2);
      const auto app = root / "Renamed App ' $.app";
      const auto executable = app / "Contents/MacOS/ActualProgram";
      fs::create_directories(executable.parent_path());
      fs::copy_file(argv[1], executable);
      // The declared name deliberately differs from the app's visible name.
      Plist(app, @{ @"CFBundleExecutable": @"ActualProgram" });
      Require(ResolveAnalysisInput(app).executable == fs::canonical(executable));
      Require(ResolveAnalysisInput(executable).bundle.empty());
      const auto raw = Import(executable, root / "workspace");
      WriteAtomic(raw.directory / "notes.md", "Preserve these notes");
      const auto project = Import(app, root / "workspace");
      Require(project.directory == raw.directory);
      Require(project.metadata.at("name") == app.filename().string());
      Require(project.metadata.at("bundle_executable") == "Contents/MacOS/ActualProgram");
      const auto notes = ReadBytes(project.directory / "notes.md");
      Require(std::string(notes.begin(), notes.end()) == "Preserve these notes");
      Require(LoadProject(project.directory).metadata == project.metadata);

      // Binary plists are common in shipped apps and must behave identically.
      Plist(app, @{ @"CFBundleExecutable": @"ActualProgram" }, NSPropertyListBinaryFormat_v1_0);
      Require(Import(app, root / "workspace").directory == project.directory);
      Plist(app, @{}); Reject([&] { ResolveAnalysisInput(app); });
      Plist(app, @{ @"CFBundleExecutable": @42 }); Reject([&] { ResolveAnalysisInput(app); });
      Plist(app, @{ @"CFBundleExecutable": @"../ActualProgram" }); Reject([&] { ResolveAnalysisInput(app); });
      Plist(app, @{ @"CFBundleExecutable": @"/bin/sh" }); Reject([&] { ResolveAnalysisInput(app); });
      Plist(app, @{ @"CFBundleExecutable": @"Missing" }); Reject([&] { ResolveAnalysisInput(app); });
      Plist(app, @[]); Reject([&] { ResolveAnalysisInput(app); });
      WriteAtomic(app / "Contents/Info.plist", "malformed plist");
      Reject([&] { ResolveAnalysisInput(app); });
      fs::remove(app / "Contents/Info.plist"); Reject([&] { ResolveAnalysisInput(app); });
      Reject([&] { ResolveAnalysisInput(root); });

      Plist(app, @{ @"CFBundleExecutable": @"LinkedProgram" });
      const auto link = executable.parent_path() / "LinkedProgram";
      fs::create_symlink("ActualProgram", link);
      Require(ResolveAnalysisInput(app).executable == fs::canonical(executable));
      fs::remove(link); fs::create_symlink(fs::absolute(argv[1]), link);
      Reject([&] { ResolveAnalysisInput(app); });

      // Books-like files contain baseline arm64e and a newer arm64e.x1 slice.
      const auto books = Fat(0x80000002, 0x8000000c);
      Require(Arm64Slice(books).offset == 4096);
      Require(Arm64Slice(books).cpuSubtype == 0x80000002);
      Require(Arm64Slice(Fat(0x8000000c, 0x80000002)).offset == 8192);
      Require(Arm64Slice(Fat(2, 0)).cpuSubtype == 0);
      Require(Arm64Slice(Fat(0, 2)).cpuSubtype == 0);
      Reject([&] { Arm64Slice(Fat(2, 2)); });
      Reject([&] { Arm64Slice(Fat(12, 12)); });
      auto mismatch = books; Put(mismatch, 4096 + 8, 0, false);
      Reject([&] { Arm64Slice(mismatch); });
      const auto armFile = root / "arm64e";
      WriteAtomic(armFile, std::string(books.begin(), books.end()));
      const auto armProject = Import(armFile, root / "workspace");
      Require(armProject.metadata.at("isa_variant") == "arm64e");
      Require(LoadProject(armProject.directory).metadata == armProject.metadata);
      fs::remove_all(app);
      Require(LoadProject(project.directory).metadata == project.metadata); // Snapshot survives app removal.
      fs::remove_all(root);
      std::cout << "Bundle resolution, persistence and arm64e selection passed\n";
    } catch (const std::exception& error) {
      fs::remove_all(root);
      std::cerr << error.what() << '\n'; return 1;
    }
  }
}
