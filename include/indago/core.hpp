#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json.hpp>

namespace indago {

namespace fs = std::filesystem;

struct CommandResult {
    int exit_code{1};
    std::string status{"failed"};
    std::string json;
};

struct TargetRecord {
    std::string id;
    std::string project;
    std::string sha256;
    std::string display_name;
    std::uintmax_t size{};
    fs::path object_path;
};

std::string json_escape(std::string_view value);
std::string quote(std::string_view value);
std::string hex_address(std::uint64_t value);
std::string utc_timestamp();
std::string make_id(std::string_view prefix);
std::string sha256_file(const fs::path& path);
std::string sha256_text(std::string_view text);
void atomic_write(const fs::path& destination, std::string_view content);

class ProjectStore {
public:
    explicit ProjectStore(fs::path root);
    const fs::path& root() const noexcept { return root_; }
    void initialize() const;
    CommandResult create_project(std::string_view name) const;
    TargetRecord import_target(std::string_view project, const fs::path& source) const;
    TargetRecord latest_target(std::string_view project) const;
    void record_derivation(const TargetRecord& target, const nlohmann::json& lineage) const;
    nlohmann::json derivations(std::string_view project, std::string_view artifact) const;
    fs::path analysis_path(std::string_view project, std::string_view id) const;
    void append_evidence(std::string_view project, std::string_view json_record) const;
    TargetRecord target(std::string_view project, std::string_view id, bool verify = true) const;
    nlohmann::json claim_job(std::string_view project, std::string_view id) const;
    void heartbeat(std::string_view id, std::string_view token) const;
    nlohmann::json recover_jobs(std::string_view project) const;
    nlohmann::json job_events(std::string_view project, std::string_view id) const;
    nlohmann::json project_info(std::string_view project) const;
    nlohmann::json start_job(const TargetRecord& target, const nlohmann::json& request) const;
    nlohmann::json publish_result(const TargetRecord& target, const nlohmann::json& job,
                                  std::string_view backend, const CommandResult& result) const;
    nlohmann::json job_info(std::string_view project, std::string_view id) const;
    nlohmann::json cancel_job(std::string_view project, std::string_view id) const;
    nlohmann::json evidence(std::string_view project, std::string_view id = {},
                            std::size_t offset = 0, std::size_t limit = 100) const;
    nlohmann::json functions(std::string_view project, std::string_view artifact = {},
                             std::size_t offset = 0, std::size_t limit = 100) const;
    nlohmann::json function_views(std::string_view project, std::string_view id,
                                std::size_t offset = 0, std::size_t limit = 100) const;
    nlohmann::json index_query(std::string_view project, const nlohmann::json& filter) const;
    nlohmann::json reindex(std::string_view project) const;
    fs::path cancellation_path(std::string_view job) const;

private:
    fs::path root_;
};

struct XairOptions {
    std::string profile{"balanced"};
    std::uint64_t wall_time_ms{120000};
    std::uint64_t memory_bytes{2ULL * 1024ULL * 1024ULL * 1024ULL};
};

CommandResult analyze_xair(const TargetRecord& target, const XairOptions& options);
CommandResult analyze_ghidra(const TargetRecord& target, const ProjectStore& store,
                             std::uint64_t timeout_seconds);
std::optional<fs::path> find_ghidra_headless();

} // namespace indago
