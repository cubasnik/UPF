#pragma once

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "upf/interfaces.hpp"

namespace upf {

class SessionTable {
public:
    bool create(const SessionContext& context);
    bool modify(const SessionContext& context);
    bool remove(const std::string& imsi, const std::string& pdu_session_id);

    std::optional<SessionContext> find(const std::string& imsi, const std::string& pdu_session_id) const;
    std::vector<SessionContext> list() const;
    std::size_t size() const;

private:
    static std::string key_of(const std::string& imsi, const std::string& pdu_session_id);

    std::unordered_map<std::string, SessionContext> sessions_;
};

}  // namespace upf
