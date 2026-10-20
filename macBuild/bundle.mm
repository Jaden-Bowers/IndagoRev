#import <Foundation/Foundation.h>
#include "bundle.hpp"
#include <algorithm>
#include <cctype>

namespace macbuild {
namespace {
fs::path InsideBundle(const fs::path& bundle, const fs::path& child) {
  // Canonical paths allow internal symlinks but reject links outside the bundle.
  const auto resolved = fs::canonical(child);
  const auto relative = resolved.lexically_relative(bundle);
  if (relative.empty() || *relative.begin() == "..")
    throw std::runtime_error("Application bundle points outside its own directory.");
  return resolved;
}
}

AnalysisInput ResolveAnalysisInput(const fs::path& selected) {
  if (!fs::is_directory(selected)) return {selected, Json::object()};
  auto extension = selected.extension().string();
  std::transform(extension.begin(), extension.end(), extension.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  if (extension != ".app")
    throw std::runtime_error("Choose a .app application or an ARM64 executable, not an ordinary folder.");
  const auto bundle = fs::canonical(selected);
  const auto info = bundle / "Contents/Info.plist";
  if (!fs::is_regular_file(info))
    throw std::runtime_error("Application is missing Contents/Info.plist.");
  const auto bytes = ReadBytes(InsideBundle(bundle, info), 1024 * 1024);
  @autoreleasepool {
    // Foundation handles both XML and binary property lists. Do not guess the
    // executable from the application name: renamed bundles still work.
    NSData* data = [NSData dataWithBytes:bytes.data() length:bytes.size()];
    NSError* error = nil;
    id plist = [NSPropertyListSerialization propertyListWithData:data
        options:NSPropertyListImmutable format:nullptr error:&error];
    if (![plist isKindOfClass:[NSDictionary class]])
      throw std::runtime_error("Application Info.plist is not a valid dictionary.");
    id value = plist[@"CFBundleExecutable"];
    if (![value isKindOfClass:[NSString class]] || [value length] == 0)
      throw std::runtime_error("Application Info.plist has no valid CFBundleExecutable name.");
    NSString* name = value;
    // The documented value is a filename within Contents/MacOS, not a command
    // or arbitrary path. Reject NULs and traversal before joining path elements.
    const char* utf8 = name.UTF8String;
    if (!utf8 || strlen(utf8) != [name lengthOfBytesUsingEncoding:NSUTF8StringEncoding])
      throw std::runtime_error("Application executable name contains invalid characters.");
    const fs::path leaf(utf8);
    if (leaf.empty() || leaf == "." || leaf == ".." || leaf.has_parent_path())
      throw std::runtime_error("CFBundleExecutable must name a file within Contents/MacOS.");
    const auto candidate = bundle / "Contents/MacOS" / leaf;
    if (!fs::is_regular_file(candidate))
      throw std::runtime_error("Application main executable is missing: " + leaf.string());
    const auto executable = InsideBundle(bundle, candidate);
    Json provenance{{"name", selected.filename().string()},
        {"bundle_path", bundle.string()}, {"bundle_executable", "Contents/MacOS/" + leaf.string()}};
    return {executable, std::move(provenance)};
  }
}
} // namespace macbuild
