#include "upf/modules/n6_packet_buffer.hpp"

#include <utility>

namespace upf {

N6PacketBuffer::N6PacketBuffer(std::size_t per_session_capacity)
    : per_session_capacity_(per_session_capacity == 0 ? 1 : per_session_capacity) {}

N6PacketBuffer::EnqueueResult N6PacketBuffer::enqueue(const std::string& session_key,
                                                      N6Packet packet,
                                                      N6BufferOverflowPolicy policy) {
    if (session_key.empty()) {
        return EnqueueResult {false, N6BufferDropReason::None};
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto& queue = session_queues_[session_key];
    auto& session_stats = session_stats_[session_key];
    if (queue.empty()) {
        stats_.active_sessions = session_queues_.size();
    }
    if (queue.size() >= per_session_capacity_) {
        ++stats_.dropped_packets;
        if (policy == N6BufferOverflowPolicy::DropNewest) {
            ++stats_.dropped_overflow_newest;
            ++stats_.rejected_by_policy;
            ++session_stats.dropped_packets;
            ++session_stats.dropped_overflow_newest;
            ++session_stats.rejected_by_policy;
            return EnqueueResult {false, N6BufferDropReason::OverflowDropNewest};
        }

        queue.pop_front();
        ++stats_.dropped_overflow_oldest;
        ++session_stats.dropped_packets;
        ++session_stats.dropped_overflow_oldest;
        --stats_.buffered_packets;
        --session_stats.buffered_packets;
        queue.push_back(std::move(packet));
        ++stats_.enqueued_packets;
        ++session_stats.enqueued_packets;
        ++stats_.buffered_packets;
        ++session_stats.buffered_packets;
        return EnqueueResult {true, N6BufferDropReason::OverflowDropOldest};
    }
    queue.push_back(std::move(packet));
    ++stats_.enqueued_packets;
    ++session_stats.enqueued_packets;
    ++stats_.buffered_packets;
    ++session_stats.buffered_packets;
    return EnqueueResult {true, N6BufferDropReason::None};
}

std::optional<N6Packet> N6PacketBuffer::dequeue(const std::string& session_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = session_queues_.find(session_key);
    if (it == session_queues_.end() || it->second.empty()) {
        return std::nullopt;
    }

    N6Packet packet = std::move(it->second.front());
    it->second.pop_front();
    ++stats_.dequeued_packets;
    ++session_stats_[session_key].dequeued_packets;
    --stats_.buffered_packets;
    --session_stats_[session_key].buffered_packets;
    if (it->second.empty()) {
        session_queues_.erase(it);
        stats_.active_sessions = session_queues_.size();
    }
    return packet;
}

void N6PacketBuffer::clear_session(const std::string& session_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = session_queues_.find(session_key);
    if (it == session_queues_.end()) {
        return;
    }

    stats_.dropped_packets += it->second.size();
    stats_.dropped_session_removed += it->second.size();
    session_stats_[session_key].dropped_packets += it->second.size();
    session_stats_[session_key].dropped_session_removed += it->second.size();
    stats_.buffered_packets -= it->second.size();
    session_stats_[session_key].buffered_packets = 0;
    session_queues_.erase(it);
    stats_.active_sessions = session_queues_.size();
}

std::size_t N6PacketBuffer::buffered_packets(const std::string& session_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = session_queues_.find(session_key);
    return it == session_queues_.end() ? 0U : it->second.size();
}

N6PacketBuffer::SessionStats N6PacketBuffer::session_stats(const std::string& session_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    SessionStats stats = {};
    if (const auto it = session_stats_.find(session_key); it != session_stats_.end()) {
        stats = it->second;
    }
    return stats;
}

N6PacketBuffer::Stats N6PacketBuffer::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

std::size_t N6PacketBuffer::capacity() const {
    return per_session_capacity_;
}

}  // namespace upf