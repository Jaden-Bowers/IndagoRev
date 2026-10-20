#include "project.hpp"
#include <iostream>

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "capabilities")
      std::cout << macbuild::Capabilities().dump(2) << '\n';
    else if (argc == 4 && std::string(argv[1]) == "import")
      std::cout << macbuild::Import(argv[2], argv[3]).metadata.dump(2) << '\n';
    else if (argc == 3 && std::string(argv[1]) == "show")
      std::cout << macbuild::LoadProject(argv[2]).metadata.dump(2) << '\n';
    else {
      std::cerr << "Usage: indago-mac capabilities | import FILE WORKSPACE | show PROJECT\n";
      return 2;
    }
  } catch (const std::exception& error) {
    std::cerr << error.what() << '\n';
    return 1;
  }
}
