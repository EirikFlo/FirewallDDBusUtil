#pragma once

#include <QString>
#include <compare>
#include <QMetaType> // For Q_DECLARE_METATYPE

// For simplicity, focusing on IPv4 as a QString. Can be expanded later.
struct IpAddress {
    QString address; // e.g., "192.168.1.10"

    bool operator==(const IpAddress &other) const noexcept { return address == other.address; }
    std::strong_ordering operator<=>(const IpAddress &other) const noexcept {
        int cmp = QString::compare(address, other.address);
        if (cmp < 0) return std::strong_ordering::less;
        if (cmp > 0) return std::strong_ordering::greater;
        return std::strong_ordering::equal;
    }
    bool isValid() const { /* Basic validation can be added */ return !address.isEmpty(); }
    QString toString() const { return address; } // Corrected method name from QStringtoString
};

Q_DECLARE_METATYPE(IpAddress)
