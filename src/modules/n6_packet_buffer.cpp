

#include "upf/modules/n6_packet_buffer.hpp"
#include <algorithm>

namespace upf {

N6PacketBuffer::N6PacketBuffer(std::size_t per_session_capacity)
    : per_session_capacity_(per_session_capacity) {}

N6PacketBuffer::EnqueueResult N6PacketBuffer::enqueue(const std::string& session_key,
                                                     N6Packet packet,
                                                     N6BufferOverflowPolicy policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& queue = session_queues_[session_key];
    auto& stats = session_stats_[session_key];
    EnqueueResult result;
    if (queue.size() >= per_session_capacity_) {
        result.accepted = false;
        if (policy == N6BufferOverflowPolicy::DropOldest) {
            queue.pop_front();
            stats.dropped_overflow_oldest++;
            result.drop_reason = N6BufferDropReason::OverflowDropOldest;
        } else {
            stats.dropped_overflow_newest++;
            result.drop_reason = N6BufferDropReason::OverflowDropNewest;
            return result;
        }
    }
    queue.push_back(std::move(packet));
    stats.enqueued_packets++;
    stats.buffered_packets = queue.size();
    stats.rejected_by_policy = 0; // For simplicity
    result.accepted = true;
    result.drop_reason = N6BufferDropReason::None;
    return result;
}

std::optional<N6Packet> N6PacketBuffer::dequeue(const std::string& session_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = session_queues_.find(session_key);
    if (it == session_queues_.end() || it->second.empty()) {
        return std::nullopt;
    }
    auto& queue = it->second;
    N6Packet pkt = std::move(queue.front());
    queue.pop_front();
    session_stats_[session_key].dequeued_packets++;
    session_stats_[session_key].buffered_packets = queue.size();
    return pkt;
}

void N6PacketBuffer::clear_session(const std::string& session_key) {
    std::lock_guard<std::mutex> lock(mutex_);
    session_queues_.erase(session_key);
    session_stats_.erase(session_key);
}

std::size_t N6PacketBuffer::buffered_packets(const std::string& session_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = session_queues_.find(session_key);
    return (it != session_queues_.end()) ? it->second.size() : 0;
}

N6PacketBuffer::SessionStats N6PacketBuffer::session_stats(const std::string& session_key) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = session_stats_.find(session_key);
    return (it != session_stats_.end()) ? it->second : SessionStats{};
}

N6PacketBuffer::Stats N6PacketBuffer::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    Stats total;
    for (const auto& [key, stats] : session_stats_) {
        total.enqueued_packets += stats.enqueued_packets;
        total.dequeued_packets += stats.dequeued_packets;
        total.dropped_packets += stats.dropped_packets;
        total.buffered_packets += stats.buffered_packets;
        total.dropped_overflow_oldest += stats.dropped_overflow_oldest;
        total.dropped_overflow_newest += stats.dropped_overflow_newest;
        total.dropped_session_removed += stats.dropped_session_removed;
        total.rejected_by_policy += stats.rejected_by_policy;
        total.active_sessions++;
    }
    return total;
}

std::size_t N6PacketBuffer::capacity() const {
    return per_session_capacity_;
}

} // namespace upf