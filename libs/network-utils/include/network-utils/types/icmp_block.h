#pragma once
#include <QString>
#include <compare> // For std::strong_ordering

enum class IcmpBlock {
    EchoRequest,
    // Extend with other ICMP types as needed
};

inline QString toString(IcmpBlock block) {
    switch (block) {
        case IcmpBlock::EchoRequest: return QStringLiteral("echo-request");
    }
    return {};
}

inline bool operator==(IcmpBlock a, IcmpBlock b) noexcept {
    return static_cast<int>(a) == static_cast<int>(b);
}
inline std::strong_ordering operator<=>(IcmpBlock a, IcmpBlock b) noexcept {
    return static_cast<int>(a) <=> static_cast<int>(b);
}
