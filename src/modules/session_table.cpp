#include "upf/modules/session_table.hpp"

namespace upf {

bool SessionTable::create(const SessionContext& context) {
    const std::string key = key_of(context.imsi, context.pdu_session_id);
    return sessions_.emplace(key, context).second;
}

bool SessionTable::modify(const SessionContext& context) {
    const std::string key = key_of(context.imsi, context.pdu_session_id);
    auto it = sessions_.find(key);
    if (it == sessions_.end()) {
        return false;
    }
    it->second = context;
    return true;
}

bool SessionTable::remove(const std::string& imsi, const std::string& pdu_session_id) {
    return sessions_.erase(key_of(imsi, pdu_session_id)) > 0;
}

std::optional<SessionContext> SessionTable::find(const std::string& imsi, const std::string& pdu_session_id) const {
    const auto it = sessions_.find(key_of(imsi, pdu_session_id));
    if (it == sessions_.end()) {
        return std::nullopt;
    }
    return it->second;
}

std::vector<SessionContext> SessionTable::list() const {
    std::vector<SessionContext> items;
    items.reserve(sessions_.size());
    for (const auto& kv : sessions_) {
        items.push_back(kv.second);
    }
    return items;
}

std::size_t SessionTable::size() const {
    return sessions_.size();
}

std::string SessionTable::key_of(const std::string& imsi, const std::string& pdu_session_id) {
    return imsi + "|" + pdu_session_id;
}

}  // namespace upf
