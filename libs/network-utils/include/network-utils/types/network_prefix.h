#pragma once

#include <QString> // For toString method
#include <compare>
#include <QtGlobal> // For quint8
#include <QMetaType> // For Q_DECLARE_METATYPE

// ip_address.h is not strictly needed if only prefixLength is used.
// #include "ip_address.h"

struct NetworkPrefix {
    quint8 prefixLength = 0; // e.g. 24 for /24

    bool operator==(const NetworkPrefix &other) const noexcept { return prefixLength == other.prefixLength; }
    std::strong_ordering operator<=>(const NetworkPrefix &other) const noexcept { return prefixLength <=> other.prefixLength; }
    QString toString() const { return QString::number(prefixLength); }
};

Q_DECLARE_METATYPE(NetworkPrefix)
