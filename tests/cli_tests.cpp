#include <cstdlib>
#include <string>

#include "upf/cli.hpp"

int main() {
    upf::RuntimeConfig cfg {};
    upf::UpfCli cli(cfg);

    if (cli.execute("set node_id upf-test") != "OK") {
        return EXIT_FAILURE;
    }
    if (cli.execute("commit") != "OK") {
        return EXIT_FAILURE;
    }

    const std::string running = cli.execute("show running");
    if (running.find("upf-test") == std::string::npos) {
        return EXIT_FAILURE;
    }

    if (cli.execute("show mode").find("operational") == std::string::npos) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
