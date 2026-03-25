#pragma once

#include <optional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "upf/interfaces.hpp"

namespace upf {
namespace modules {

struct SessionInfo {
    std::string imsi;
    uint32_t pdu_session_id;
    // другие поля по необходимости
};

class SessionTable {
public:
    SessionTable(size_t max_sessions);
    ~SessionTable();

    bool add_session(const SessionInfo& info);
    bool remove_session(const std::string& imsi, uint32_t pdu_session_id);
    std::optional<SessionInfo> find_session(const std::string& imsi, uint32_t pdu_session_id);
    size_t size() const;
    void clear();

private:
    std::string make_key(const std::string& imsi, uint32_t pdu_session_id) const;
    std::unordered_map<std::string, SessionInfo> sessions_;
    size_t max_sessions_;
    mutable std::mutex mutex_;
};

} // namespace modules
} // namespace upf
