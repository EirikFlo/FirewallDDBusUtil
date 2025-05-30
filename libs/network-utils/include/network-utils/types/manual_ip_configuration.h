#pragma once

#include "ip_address.h"
#include "network_prefix.h"
#include "gateway_address.h"
#include <QList> // For DNS servers
#include <QString> // For IpAddress::toString, NetworkPrefix::toString if used in comparisons implicitly
#include <QMetaType> // For Q_DECLARE_METATYPE

struct ManualIpConfiguration {
    IpAddress address;
    NetworkPrefix prefix;
    GatewayAddress gateway; // Optional, might not always be set
    QList<IpAddress> dnsServers; // Optional

    bool operator==(const ManualIpConfiguration &other) const noexcept {
        return address == other.address &&
               prefix == other.prefix &&
               gateway == other.gateway &&
               dnsServers == other.dnsServers;
    }
    // No spaceship operator here as QList<IpAddress> doesn't have a direct one.
    // If full ordering is needed, a custom <=> would be required.
};

Q_DECLARE_METATYPE(ManualIpConfiguration)
