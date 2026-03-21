#pragma once

#include <mutex>

#include "upf/interfaces.hpp"
#include "upf/modules/session_table.hpp"

namespace upf {

class UpfNode final : public IUpfNode {
public:
    UpfNode(IN4Interface& n4, ISbiInterface& sbi, UpfPeerInterfaces peers = {});

    bool start() override;
    bool stop() override;
    bool set_degraded() override;
    bool recover() override;
    void tick() override;

    bool establish_session(const PfcpSessionRequest& request) override;
    bool modify_session(const PfcpSessionRequest& request) override;
    bool release_session(const std::string& imsi, const std::string& pdu_session_id) override;

    bool process_uplink(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;
    bool process_downlink(const std::string& imsi, const std::string& pdu_session_id, std::size_t bytes) override;

    std::optional<SessionContext> find_session(const std::string& imsi, const std::string& pdu_session_id) const override;
    std::vector<SessionContext> list_sessions() const override;

    bool notify_sbi(const std::string& service_name, const std::string& payload) override;
    UpfStatusSnapshot status() const override;
    void clear_stats() override;

private:
    bool is_operational() const;

    IN4Interface& n4_;
    ISbiInterface& sbi_;
    UpfPeerInterfaces peers_ {};

    mutable std::mutex mutex_;
    UpfState state_ {UpfState::Idle};
    SessionTable sessions_ {};
    UpfStats stats_ {};
};

}  // namespace upf
