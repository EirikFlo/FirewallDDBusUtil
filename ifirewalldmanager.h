#pragma once

#include <QString>
#include <QStringList>
#include <QList>
#include <compare>

// --- Domain Types ---

struct Service {
    QString name;
    QString toString() const { return name; }

    bool operator==(const Service &other) const noexcept {
        return name == other.name;
    }
    std::strong_ordering operator<=>(const Service &other) const noexcept {
        int cmp = QString::compare(name, other.name);
        if (cmp < 0) return std::strong_ordering::less;
        if (cmp > 0) return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }
};

struct Port {
    quint16 port;
    QString protocol;
    QString toString() const { return QStringLiteral("%1/%2").arg(port).arg(protocol); }

    bool operator==(const Port &other) const noexcept {
        return port == other.port && protocol == other.protocol;
    }
    std::strong_ordering operator<=>(const Port &other) const noexcept {
        if (port < other.port) return std::strong_ordering::less;
        if (port > other.port) return std::strong_ordering::greater;
        int cmp = QString::compare(protocol, other.protocol);
        if (cmp < 0) return std::strong_ordering::less;
        if (cmp > 0) return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }
};

struct RichRule {
    QString rule;
    QString toString() const { return rule; }

    bool operator==(const RichRule &other) const noexcept {
        return rule == other.rule;
    }
    std::strong_ordering operator<=>(const RichRule &other) const noexcept {
        int cmp = QString::compare(rule, other.rule);
        if (cmp < 0) return std::strong_ordering::less;
        if (cmp > 0) return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }
};

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

struct ZoneDetails {
    QList<Service> services;
    QList<Port> ports;
    QList<RichRule> richRules;
    QList<IcmpBlock> icmpBlocks;
};

// --- Interface ---

class IFirewalldManager {
public:
    virtual ~IFirewalldManager() = default;

    // List all zone names
    virtual QStringList zoneNames() = 0;

    // Detailed information about a zone
    virtual ZoneDetails zoneDetails(const QString &zone) = 0;

    // Services
    virtual void addService(const QString &zone, const Service &service) = 0;
    virtual void removeService(const QString &zone, const Service &service) = 0;

    // Rich rules
    virtual void addRichRule(const QString &zone, const RichRule &rule) = 0;
    virtual void removeRichRule(const QString &zone, const RichRule &rule) = 0;

    // Ports
    virtual void addPort(const QString &zone, const Port &port) = 0;
    virtual void removePort(const QString &zone, const Port &port) = 0;

    // ICMP ping
    virtual void enablePing(const QString &zone) = 0;
    virtual void disablePing(const QString &zone) = 0;
};
