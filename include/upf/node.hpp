#pragma once

#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <cstdint>
#include "upf/upf.hpp"

namespace upf {

class UpfNode {
public:
    // ...existing code...
    // Заглушка для inspect_n6_session
    std::optional<N6SessionBufferSnapshot> inspect_n6_session(const std::string& imsi, const std::string& pdu_session_id) const { return std::nullopt; }
public:
    UpfNode(const std::string& n4_address, 
            const std::string& sbi_address,
            const std::vector<std::string>& peer_addresses);

    // Constructor for test compatibility: accepts N4, SBI, and peer interfaces
    UpfNode(IN4Interface& n4, ISbiInterface& sbi, const UpfPeerInterfaces& peers);
    ~UpfNode();

    bool start();
    bool stop();
    bool is_running() const;

    bool establish_session(const SessionRequest& request);
    // Overload for test/interface compatibility
    bool establish_session(const PfcpSessionRequest& request);
    bool modify_session(const SessionRequest& request);
    bool release_session(const std::string& imsi, uint32_t pdu_session_id);
    std::optional<SessionRequest> find_session(const std::string& imsi, uint32_t pdu_session_id);

    bool process_uplink(const std::string& imsi, uint32_t pdu_session_id, size_t bytes);
    bool process_downlink(const std::string& imsi, uint32_t pdu_session_id, size_t bytes);

    // Перегрузки для поддержки строкового pdu_session_id
    bool process_uplink(const std::string& imsi, const std::string& pdu_session_id, size_t bytes) {
        return process_uplink(imsi, static_cast<uint32_t>(std::stoul(pdu_session_id)), bytes);
    }
    bool process_downlink(const std::string& imsi, const std::string& pdu_session_id, size_t bytes) {
        return process_downlink(imsi, static_cast<uint32_t>(std::stoul(pdu_session_id)), bytes);
    }

    UpfStatusSnapshot status() const;
    bool notify_sbi(const std::string& event, const std::string& data);

private:
    struct Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace upf
