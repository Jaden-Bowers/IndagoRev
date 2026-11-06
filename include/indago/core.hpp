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

// Outcome of one command/backend invocation: process exit code, a coarse
// status word (completed/partial/failed), and the backend's JSON payload.
struct CommandResult {
    int exit_code{1};
    std::string status{"failed"};
    std::string json;
};

// Identity of an imported artifact: its database id, owning project, content
// hash, display name, byte size and the content-addressed object path.
struct TargetRecord {
    std::string id;
    std::string project;
    std::string sha256;
    std::string display_name;
    std::uintmax_t size{};
    fs::path object_path;
};

// Escapes a string for embedding inside a JSON string, without the quotes.
std::string json_escape(std::string_view value);
// Encodes a string as a complete JSON string literal, including quotes.
std::string quote(std::string_view value);
// Formats an integer as a lowercase "0x" address.
std::string hex_address(std::uint64_t value);
// Returns the current UTC time as an ISO-8601 "YYYY-MM-DDTHH:MM:SSZ" stamp.
std::string utc_timestamp();
// Generates a unique identifier of the form "<prefix>_<32 hex digits>".
std::string make_id(std::string_view prefix);
// Returns the lowercase hex SHA-256 of a file's contents.
std::string sha256_file(const fs::path& path);
// Returns the lowercase hex SHA-256 of a string's bytes.
std::string sha256_text(std::string_view text);
// Atomically writes content by staging a temp file and renaming it into place.
void atomic_write(const fs::path& destination, std::string_view content);

// Durable workspace store: projects, imported artifacts, jobs, evidence and
// the derived static index, backed by SQLite plus a content-addressed object
// directory. All operations are safe to call concurrently across processes.
class ProjectStore {
public:
    // Records the absolute, lexically normalized workspace root.
    explicit ProjectStore(fs::path root);
    // Workspace root directory.
    const fs::path& root() const noexcept { return root_; }
    // Creates the directory layout and schema, then imports legacy manifests.
    void initialize() const;
    // Creates an empty project and returns its manifest record.
    CommandResult create_project(std::string_view name) const;
    // Lists projects with target/function counts, newest first.
    nlohmann::json list_projects() const;
    // Copies an artifact into the object store and registers it, returning the
    // stored target (deduplicated by content hash).
    TargetRecord import_target(std::string_view project, const fs::path& source) const;
    // Returns the most recently imported target of a project.
    TargetRecord latest_target(std::string_view project) const;
    // Appends a provenance/derivation record for an artifact.
    void record_derivation(const TargetRecord& target, const nlohmann::json& lineage) const;
    // Returns recorded derivations for an artifact, verifying each checksum.
    nlohmann::json derivations(std::string_view project, std::string_view artifact) const;
    // Path of the convenience JSON mirror for one analysis revision.
    fs::path analysis_path(std::string_view project, std::string_view id) const;
    // Legacy evidence append entrypoint; new code should use publish_result().
    void append_evidence(std::string_view project, std::string_view json_record) const;
    // Looks up a target by id (or the latest when id is empty) and optionally
    // verifies that the stored bytes still match the recorded hash.
    TargetRecord target(std::string_view project, std::string_view id, bool verify = true) const;
    // Atomically claims a queued job, returning it with a fresh lease token.
    nlohmann::json claim_job(std::string_view project, std::string_view id) const;
    // Extends the caller's lease; throws if the lease was lost or expired.
    void heartbeat(std::string_view id, std::string_view token) const;
    // Marks running jobs with expired leases as interrupted and releases them.
    nlohmann::json recover_jobs(std::string_view project) const;
    // Returns the ordered audit events recorded for a job.
    nlohmann::json job_events(std::string_view project, std::string_view id) const;
    // Returns a project manifest with its targets.
    nlohmann::json project_info(std::string_view project) const;
    // Enqueues a new job for a target, honoring an optional idempotency key.
    nlohmann::json start_job(const TargetRecord& target, const nlohmann::json& request) const;
    // Publishes a backend result: stores raw JSON as evidence, updates the
    // derived index and finishes the job under one transaction. Returns the
    // result envelope, or the prior result when already published.
    nlohmann::json publish_result(const TargetRecord& target, const nlohmann::json& job,
                                  std::string_view backend, const CommandResult& result) const;
    // Returns one job with its result, or a paged list when id is empty.
    nlohmann::json job_info(std::string_view project, std::string_view id) const;
    // Requests cancellation of an active job, or reports its terminal status.
    nlohmann::json cancel_job(std::string_view project, std::string_view id) const;
    // Returns evidence records (paged) with native payloads when an id is given.
    nlohmann::json evidence(std::string_view project, std::string_view id = {},
                            std::size_t offset = 0, std::size_t limit = 100) const;
    // Returns function locations (paged), optionally filtered by artifact.
    nlohmann::json functions(std::string_view project, std::string_view artifact = {},
                             std::size_t offset = 0, std::size_t limit = 100) const;
    // Returns the backend-native views and claims recorded for one function.
    nlohmann::json function_views(std::string_view project, std::string_view id,
                                std::size_t offset = 0, std::size_t limit = 100) const;
    // Queries the derived index (entities/relations/claims/revisions or a
    // cross-backend "compare" by anchor).
    nlohmann::json index_query(std::string_view project, const nlohmann::json& filter) const;
    // Rebuilds the derived indexes from immutable evidence; never touches raw
    // evidence or jobs.
    nlohmann::json reindex(std::string_view project) const;
    // Path of the cooperative cancellation marker for a job.
    fs::path cancellation_path(std::string_view job) const;

private:
    fs::path root_;
};

// Resource limits and profile for a native xair analysis run.
struct XairOptions {
    std::string profile{"balanced"};
    std::uint64_t wall_time_ms{120000};
    std::uint64_t memory_bytes{2ULL * 1024ULL * 1024ULL * 1024ULL};
};

// Runs the xair backend on a target and returns its command result.
CommandResult analyze_xair(const TargetRecord& target, const XairOptions& options);
// Runs Ghidra headless on a target, publishing into the given store.
CommandResult analyze_ghidra(const TargetRecord& target, const ProjectStore& store,
                             std::uint64_t timeout_seconds);
// Locates the bundled/system Ghidra headless launcher, if present.
std::optional<fs::path> find_ghidra_headless();

} // namespace indago
