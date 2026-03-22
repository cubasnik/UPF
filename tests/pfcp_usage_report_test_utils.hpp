#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace test_pfcp {

struct UsageReportContextSpec {
    std::uint32_t urr_id {0};
    std::string measurement_method;
    std::string reporting_trigger;
    std::uint8_t cause_code {1};
    std::optional<std::string> detail;
    std::optional<std::uint64_t> threshold_value;
    std::optional<std::uint64_t> quota_value;
    std::uint64_t bytes_ul {0};
    std::uint64_t bytes_dl {0};
    std::uint64_t packets_ul {0};
    std::uint64_t packets_dl {0};
};

constexpr std::uint16_t kUrrIdIe = 81;
constexpr std::uint16_t kMeasurementMethodValueIe = 62;
constexpr std::uint16_t kReportingTriggerValueIe = 63;
constexpr std::uint16_t kCauseIe = 19;
constexpr std::uint16_t kImsiIe = 0x0101;
constexpr std::uint16_t kPduSessionIdIe = 0x0102;
constexpr std::uint16_t kSessionVersionIe = 0x0109;
constexpr std::uint16_t kRecoveryTimeStampIe = 96;
constexpr std::uint16_t kUserIdentityIe = 0x0130;
constexpr std::uint16_t kBytesUlIe = 0x010B;
constexpr std::uint16_t kBytesDlIe = 0x010C;
constexpr std::uint16_t kPacketsUlIe = 0x010D;
constexpr std::uint16_t kPacketsDlIe = 0x010E;

inline void append_u16(std::vector<std::uint8_t>* buffer, std::uint16_t value) {
    buffer->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer->push_back(static_cast<std::uint8_t>(value & 0xFF));
}

inline void append_u32(std::vector<std::uint8_t>* buffer, std::uint32_t value) {
    buffer->push_back(static_cast<std::uint8_t>((value >> 24) & 0xFF));
    buffer->push_back(static_cast<std::uint8_t>((value >> 16) & 0xFF));
    buffer->push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
    buffer->push_back(static_cast<std::uint8_t>(value & 0xFF));
}

inline void append_u64(std::vector<std::uint8_t>* buffer, std::uint64_t value) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        buffer->push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
    }
}

inline std::vector<std::uint8_t> encode_u32_value(std::uint32_t value) {
    std::vector<std::uint8_t> encoded;
    append_u32(&encoded, value);
    return encoded;
}

inline std::vector<std::uint8_t> encode_u64_value(std::uint64_t value) {
    std::vector<std::uint8_t> encoded;
    append_u64(&encoded, value);
    return encoded;
}

inline std::uint16_t read_u16_value(const std::vector<std::uint8_t>& buffer, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(buffer[offset]) << 8) | buffer[offset + 1]);
}

inline void append_ie_raw(std::vector<std::uint8_t>* buffer, std::uint16_t type, const std::vector<std::uint8_t>& value) {
    append_u16(buffer, type);
    append_u16(buffer, static_cast<std::uint16_t>(value.size()));
    buffer->insert(buffer->end(), value.begin(), value.end());
}

inline void append_ie_string_raw(std::vector<std::uint8_t>* buffer, std::uint16_t type, const std::string& value) {
    append_ie_raw(buffer, type, std::vector<std::uint8_t>(value.begin(), value.end()));
}

inline std::vector<std::uint8_t> encode_usage_report_context(const UsageReportContextSpec& spec) {
    std::vector<std::uint8_t> grouped;
    append_ie_raw(&grouped, kUrrIdIe, encode_u32_value(spec.urr_id));
    append_ie_string_raw(&grouped, kMeasurementMethodValueIe, spec.measurement_method);
    append_ie_string_raw(&grouped, kReportingTriggerValueIe, spec.reporting_trigger);
    append_ie_raw(&grouped, kCauseIe, std::vector<std::uint8_t> {spec.cause_code});
    append_ie_raw(&grouped, kBytesUlIe, encode_u64_value(spec.bytes_ul));
    append_ie_raw(&grouped, kBytesDlIe, encode_u64_value(spec.bytes_dl));
    append_ie_raw(&grouped, kPacketsUlIe, encode_u64_value(spec.packets_ul));
    append_ie_raw(&grouped, kPacketsDlIe, encode_u64_value(spec.packets_dl));
    return grouped;
}

inline std::vector<std::uint8_t> encode_response_context(std::uint8_t cause_code,
                                                         const std::string& detail,
                                                         std::optional<std::uint64_t> session_version = std::nullopt,
                                                         std::optional<std::uint32_t> recovery_time_stamp = std::nullopt) {
    std::vector<std::uint8_t> grouped;
    (void)detail;
    append_ie_raw(&grouped, kCauseIe, std::vector<std::uint8_t> {cause_code});
    if (session_version.has_value()) {
        append_ie_raw(&grouped, kSessionVersionIe, encode_u64_value(*session_version));
    }
    if (recovery_time_stamp.has_value()) {
        append_ie_raw(&grouped, kRecoveryTimeStampIe, encode_u32_value(*recovery_time_stamp));
    }
    return grouped;
}

inline std::vector<std::uint8_t> encode_response_context_bad_order(std::uint8_t cause_code,
                                                                   const std::string& detail) {
    std::vector<std::uint8_t> grouped;
    (void)detail;
    append_ie_raw(&grouped, kSessionVersionIe, encode_u64_value(1));
    append_ie_raw(&grouped, kCauseIe, std::vector<std::uint8_t> {cause_code});
    return grouped;
}

inline std::vector<std::uint8_t> encode_response_context_duplicate_cause(std::uint8_t cause_code,
                                                                         const std::string& detail) {
    std::vector<std::uint8_t> grouped;
    (void)detail;
    append_ie_raw(&grouped, kCauseIe, std::vector<std::uint8_t> {cause_code});
    append_ie_raw(&grouped, kCauseIe, std::vector<std::uint8_t> {cause_code});
    return grouped;
}

inline std::vector<std::uint8_t> encode_usage_query_context(const std::string& imsi,
                                                            const std::string& pdu_session_id,
                                                            const std::vector<std::uint32_t>& urr_ids = {}) {
    std::vector<std::uint8_t> grouped;
    (void)imsi;
    (void)pdu_session_id;
    for (const std::uint32_t urr_id : urr_ids) {
        append_ie_raw(&grouped, kUrrIdIe, encode_u32_value(urr_id));
    }
    return grouped;
}

template <typename IeType>
inline std::optional<std::vector<std::uint8_t>> find_grouped_entry(const std::vector<std::uint8_t>& grouped_value, IeType type) {
    std::size_t cursor = 0;
    while (cursor + 4 <= grouped_value.size()) {
        const std::uint16_t decoded_type = read_u16_value(grouped_value, cursor);
        const std::uint16_t decoded_length = read_u16_value(grouped_value, cursor + 2);
        cursor += 4;
        if (cursor + decoded_length > grouped_value.size()) {
            return std::nullopt;
        }
        if (decoded_type == static_cast<std::uint16_t>(type)) {
            return std::vector<std::uint8_t>(grouped_value.begin() + static_cast<std::ptrdiff_t>(cursor),
                                             grouped_value.begin() + static_cast<std::ptrdiff_t>(cursor + decoded_length));
        }
        cursor += decoded_length;
    }
    return std::nullopt;
}

template <typename IeType>
inline std::vector<std::vector<std::uint8_t>> find_grouped_entries(const std::vector<std::uint8_t>& grouped_value, IeType type) {
    std::vector<std::vector<std::uint8_t>> values;
    std::size_t cursor = 0;
    while (cursor + 4 <= grouped_value.size()) {
        const std::uint16_t decoded_type = read_u16_value(grouped_value, cursor);
        const std::uint16_t decoded_length = read_u16_value(grouped_value, cursor + 2);
        cursor += 4;
        if (cursor + decoded_length > grouped_value.size()) {
            return {};
        }
        if (decoded_type == static_cast<std::uint16_t>(type)) {
            values.emplace_back(grouped_value.begin() + static_cast<std::ptrdiff_t>(cursor),
                                grouped_value.begin() + static_cast<std::ptrdiff_t>(cursor + decoded_length));
        }
        cursor += decoded_length;
    }
    return values;
}

template <typename Message, typename IeType>
inline std::optional<std::vector<std::uint8_t>> decode_grouped_ie(const Message& message,
                                                                  IeType outer_type,
                                                                  IeType inner_type) {
    const auto it = message.ies.find(static_cast<std::uint16_t>(outer_type));
    if (it == message.ies.end() || it->second.empty()) {
        return std::nullopt;
    }
    const auto& grouped = it->second.front();
    if (grouped.size() < 4) {
        return std::nullopt;
    }
    const std::uint16_t decoded_inner_type = read_u16_value(grouped, 0);
    const std::uint16_t decoded_inner_length = read_u16_value(grouped, 2);
    if (decoded_inner_type == static_cast<std::uint16_t>(inner_type) && grouped.size() == static_cast<std::size_t>(decoded_inner_length) + 4U) {
        return std::vector<std::uint8_t>(grouped.begin() + 4, grouped.end());
    }
    return grouped;
}

template <typename Message, typename IeType>
inline std::vector<std::vector<std::uint8_t>> decode_grouped_ies(const Message& message,
                                                                 IeType outer_type,
                                                                 IeType inner_type) {
    const auto it = message.ies.find(static_cast<std::uint16_t>(outer_type));
    if (it == message.ies.end()) {
        return {};
    }
    std::vector<std::vector<std::uint8_t>> decoded;
    for (const auto& grouped : it->second) {
        if (grouped.size() < 4) {
            return {};
        }
        const std::uint16_t decoded_inner_type = read_u16_value(grouped, 0);
        const std::uint16_t decoded_inner_length = read_u16_value(grouped, 2);
        if (decoded_inner_type == static_cast<std::uint16_t>(inner_type) && grouped.size() == static_cast<std::size_t>(decoded_inner_length) + 4U) {
            decoded.emplace_back(grouped.begin() + 4, grouped.end());
            continue;
        }
        decoded.push_back(grouped);
    }
    return decoded;
}

}  // namespace test_pfcp