#pragma once

#include "upf/interfaces.hpp"

#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace upf {

class N6PacketBuffer final {
public:
    struct SessionStats {
        std::size_t enqueued_packets {0};
        std::size_t dequeued_packets {0};
        std::size_t dropped_packets {0};
        std::size_t dropped_overflow_oldest {0};
        std::size_t dropped_overflow_newest {0};
        std::size_t dropped_session_removed {0};
        std::size_t rejected_by_policy {0};
        std::size_t buffered_packets {0};
    };

    struct Stats {
        std::size_t enqueued_packets {0};
        std::size_t dequeued_packets {0};
        std::size_t dropped_packets {0};
        std::size_t buffered_packets {0};
        std::size_t active_sessions {0};
        std::size_t dropped_overflow_oldest {0};
        std::size_t dropped_overflow_newest {0};
        std::size_t dropped_session_removed {0};
        std::size_t rejected_by_policy {0};
    };

    struct EnqueueResult {
        bool accepted {false};
        N6BufferDropReason drop_reason {N6BufferDropReason::None};
    };

    explicit N6PacketBuffer(std::size_t per_session_capacity = 16);

    EnqueueResult enqueue(const std::string& session_key,
                          N6Packet packet,
                          N6BufferOverflowPolicy policy = N6BufferOverflowPolicy::DropOldest);
    std::optional<N6Packet> dequeue(const std::string& session_key);
    void clear_session(const std::string& session_key);
    std::size_t buffered_packets(const std::string& session_key) const;
    SessionStats session_stats(const std::string& session_key) const;
    Stats stats() const;
    std::size_t capacity() const;

private:
    using PacketQueue = std::deque<N6Packet>;

    std::size_t per_session_capacity_ {16};
    mutable std::mutex mutex_;
    std::unordered_map<std::string, PacketQueue> session_queues_;
    std::unordered_map<std::string, SessionStats> session_stats_;
    Stats stats_;
};

}  // namespace upf