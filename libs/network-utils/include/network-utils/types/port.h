#pragma once
#include <QString>
#include <QtGlobal> // For quint16
#include <compare> // For std::strong_ordering
#include <QMetaType> // For Q_DECLARE_METATYPE

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

Q_DECLARE_METATYPE(Port)
