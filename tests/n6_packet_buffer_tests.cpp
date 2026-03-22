#include <cstdlib>
#include <string>

#include "upf/modules/n6_packet_buffer.hpp"

namespace {

upf::N6Packet make_packet(std::size_t payload_bytes, const std::string& destination_ipv4) {
    upf::N6Packet packet {};
    packet.protocol = upf::N6Protocol::IPv4;
    packet.source_ipv4 = "198.51.100.1";
    packet.destination_ipv4 = destination_ipv4;
    packet.payload.resize(payload_bytes);
    return packet;
}

}  // namespace

int main() {
    upf::N6PacketBuffer buffer(2);

    if (!buffer.enqueue("001|10", make_packet(64, "10.0.0.1")).accepted ||
        !buffer.enqueue("001|10", make_packet(96, "10.0.0.2")).accepted) {
        return EXIT_FAILURE;
    }

    auto stats = buffer.stats();
    if (stats.enqueued_packets != 2 || stats.buffered_packets != 2 || stats.dropped_packets != 0 || stats.active_sessions != 1) {
        return EXIT_FAILURE;
    }

    auto session_stats = buffer.session_stats("001|10");
    if (session_stats.enqueued_packets != 2 || session_stats.dequeued_packets != 0 || session_stats.dropped_packets != 0 ||
        session_stats.dropped_overflow_oldest != 0 || session_stats.dropped_overflow_newest != 0 || session_stats.dropped_session_removed != 0 || session_stats.rejected_by_policy != 0 ||
        session_stats.buffered_packets != 2) {
        return EXIT_FAILURE;
    }

    const auto drop_oldest = buffer.enqueue("001|10", make_packet(128, "10.0.0.3"));
    if (!drop_oldest.accepted || drop_oldest.drop_reason != upf::N6BufferDropReason::OverflowDropOldest) {
        return EXIT_FAILURE;
    }

    stats = buffer.stats();
    if (stats.enqueued_packets != 3 || stats.buffered_packets != 2 || stats.dropped_packets != 1 || stats.active_sessions != 1 || stats.dropped_overflow_oldest != 1) {
        return EXIT_FAILURE;
    }

    session_stats = buffer.session_stats("001|10");
    if (session_stats.enqueued_packets != 3 || session_stats.dequeued_packets != 0 || session_stats.dropped_packets != 1 ||
        session_stats.dropped_overflow_oldest != 1 || session_stats.dropped_overflow_newest != 0 || session_stats.dropped_session_removed != 0 || session_stats.rejected_by_policy != 0 ||
        session_stats.buffered_packets != 2) {
        return EXIT_FAILURE;
    }

    const auto first = buffer.dequeue("001|10");
    if (!first.has_value() || first->payload.size() != 96 || first->destination_ipv4 != "10.0.0.2") {
        return EXIT_FAILURE;
    }

    const auto second = buffer.dequeue("001|10");
    if (!second.has_value() || second->payload.size() != 128 || second->destination_ipv4 != "10.0.0.3") {
        return EXIT_FAILURE;
    }

    session_stats = buffer.session_stats("001|10");
    if (session_stats.enqueued_packets != 3 || session_stats.dequeued_packets != 2 || session_stats.dropped_packets != 1 ||
        session_stats.dropped_overflow_oldest != 1 || session_stats.dropped_overflow_newest != 0 || session_stats.dropped_session_removed != 0 || session_stats.rejected_by_policy != 0 ||
        session_stats.buffered_packets != 0) {
        return EXIT_FAILURE;
    }

    if (buffer.dequeue("001|10").has_value()) {
        return EXIT_FAILURE;
    }

    if (!buffer.enqueue("001|10", make_packet(48, "10.0.0.4")).accepted ||
        !buffer.enqueue("001|11", make_packet(80, "10.0.1.1")).accepted) {
        return EXIT_FAILURE;
    }

    stats = buffer.stats();
    if (stats.buffered_packets != 2 || stats.active_sessions != 2) {
        return EXIT_FAILURE;
    }

    buffer.clear_session("001|10");
    if (buffer.buffered_packets("001|10") != 0 || buffer.buffered_packets("001|11") != 1) {
        return EXIT_FAILURE;
    }

    stats = buffer.stats();
    if (stats.buffered_packets != 1 || stats.active_sessions != 1 || stats.dropped_packets != 2 || stats.dropped_session_removed != 1 || buffer.capacity() != 2) {
        return EXIT_FAILURE;
    }

    session_stats = buffer.session_stats("001|10");
    if (session_stats.enqueued_packets != 4 || session_stats.dequeued_packets != 2 || session_stats.dropped_packets != 2 ||
        session_stats.dropped_overflow_oldest != 1 || session_stats.dropped_overflow_newest != 0 || session_stats.dropped_session_removed != 1 || session_stats.rejected_by_policy != 0 ||
        session_stats.buffered_packets != 0) {
        return EXIT_FAILURE;
    }

    upf::N6PacketBuffer drop_newest_buffer(1);
    if (!drop_newest_buffer.enqueue("001|20", make_packet(32, "10.0.2.1")).accepted) {
        return EXIT_FAILURE;
    }

    const auto drop_newest = drop_newest_buffer.enqueue("001|20",
                                                        make_packet(48, "10.0.2.2"),
                                                        upf::N6BufferOverflowPolicy::DropNewest);
    if (drop_newest.accepted || drop_newest.drop_reason != upf::N6BufferDropReason::OverflowDropNewest) {
        return EXIT_FAILURE;
    }

    const auto preserved = drop_newest_buffer.dequeue("001|20");
    if (!preserved.has_value() || preserved->destination_ipv4 != "10.0.2.1") {
        return EXIT_FAILURE;
    }

    stats = drop_newest_buffer.stats();
    if (stats.dropped_packets != 1 || stats.dropped_overflow_newest != 1 || stats.rejected_by_policy != 1) {
        return EXIT_FAILURE;
    }

    session_stats = drop_newest_buffer.session_stats("001|20");
    if (session_stats.enqueued_packets != 1 || session_stats.dequeued_packets != 1 || session_stats.dropped_packets != 1 ||
        session_stats.dropped_overflow_oldest != 0 || session_stats.dropped_overflow_newest != 1 || session_stats.dropped_session_removed != 0 || session_stats.rejected_by_policy != 1 ||
        session_stats.buffered_packets != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}