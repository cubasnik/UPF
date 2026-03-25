#include "upf/modules/session_table.hpp"
#include <sstream>
#include <mutex>

namespace upf {
namespace modules {

SessionTable::SessionTable(size_t max_sessions) : max_sessions_(max_sessions) {
}

SessionTable::~SessionTable() = default;

std::string SessionTable::make_key(const std::string& imsi, uint32_t pdu_session_id) const {
    return imsi + ":" + std::to_string(pdu_session_id);
}

bool SessionTable::add_session(const SessionInfo& info) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = make_key(info.imsi, info.pdu_session_id);
    
    if (sessions_.size() >= max_sessions_) {
        return false;
    }
    
    if (sessions_.find(key) != sessions_.end()) {
        return false;
    }
    
    sessions_[key] = info;
    return true;
}

bool SessionTable::remove_session(const std::string& imsi, uint32_t pdu_session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = make_key(imsi, pdu_session_id);
    auto it = sessions_.find(key);
    
    if (it == sessions_.end()) {
        return false;
    }
    
    sessions_.erase(it);
    return true;
}

std::optional<SessionInfo> SessionTable::find_session(const std::string& imsi, uint32_t pdu_session_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string key = make_key(imsi, pdu_session_id);
    auto it = sessions_.find(key);
    
    if (it != sessions_.end()) {
        return it->second;
    }
    
    return std::nullopt;
}

size_t SessionTable::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

void SessionTable::clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    sessions_.clear();
}

} // namespace modules
} // namespace upf