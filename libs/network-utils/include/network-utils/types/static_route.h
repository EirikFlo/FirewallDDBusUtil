#pragma once

#include "ip_address.h"
#include "network_prefix.h"
#include "gateway_address.h" // Route via this gateway
#include <compare>
#include <QtGlobal> // For quint32
#include <QMetaType> // For Q_DECLARE_METATYPE

struct StaticRoute {
    IpAddress destination;
    NetworkPrefix prefix;
    GatewayAddress gateway; // The 'via' address
    quint32 metric = 0;     // Optional, 0 for default

    bool operator==(const StaticRoute &other) const noexcept {
        return destination == other.destination &&
               prefix == other.prefix &&
               gateway == other.gateway &&
               metric == other.metric;
    }
    // For full ordering, a custom <=> would be needed if QList<StaticRoute> needs it.
    // std::strong_ordering operator<=>(const StaticRoute &other) const noexcept {
    //     if (auto cmp = destination <=> other.destination; cmp != 0) return cmp;
    //     if (auto cmp = prefix <=> other.prefix; cmp != 0) return cmp;
    //     if (auto cmp = gateway <=> other.gateway; cmp != 0) return cmp;
    //     return metric <=> other.metric;
    // }
};

Q_DECLARE_METATYPE(StaticRoute)
