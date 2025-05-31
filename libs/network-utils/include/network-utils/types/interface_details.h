#pragma once

#include <QString>
#include <QList>
#include "ip_address.h"
#include "network_prefix.h"
#include "gateway_address.h"
#include "interface_configuration.h"
#include "static_route.h"
#include <QtGlobal> // For quint64

struct InterfaceDetails {
    QString name;
    QString macAddress; // e.g., "00:1A:2B:3C:4D:5E"
    InterfaceConfiguration configuration;

    // Current effective settings (might be from DHCP or manual)
    IpAddress currentIpAddress;
    NetworkPrefix currentPrefix;
    GatewayAddress currentGateway;
    QList<IpAddress> currentDnsServers;

    QList<StaticRoute> staticRoutes; // Configured static routes for this interface

    bool isUp = false;
    // Add other relevant details like duplex, state string from NM, etc.
};
