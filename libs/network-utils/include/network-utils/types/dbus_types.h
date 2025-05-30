#pragma once

#include "network-utils/types/port.h"
#include "network-utils/types/service.h"
#include "network-utils/types/rich_rule.h"
#include "network-utils/types/ip_address.h"
#include "network-utils/types/network_prefix.h"
// GatewayAddress is a using alias for IpAddress, no separate include
#include "network-utils/types/interface_configuration_mode.h" // Enum, might not need custom streaming if passed as int/string
#include "network-utils/types/manual_ip_configuration.h"
#include "network-utils/types/interface_configuration.h"
#include "network-utils/types/static_route.h"
// InterfaceDetails is not typically streamed directly as one D-Bus type, but composed.

#include <QMetaType>
#include <QList> // Required for QList<T>

// Forward declaration for QDBusArgument to allow operator declarations first
class QDBusArgument;

// Custom streaming operators declared before including <QDBusArgument>
// Implementations are now inline in this header.

#include <QDBusArgument> // Include the full header first

inline QDBusArgument &operator<<(QDBusArgument &argument, const Port& p) {
    argument.beginStructure();
    argument << p.port << p.protocol;
    argument.endStructure();
    return argument;
}

inline const QDBusArgument &operator>>(const QDBusArgument &argument, Port& p) {
    argument.beginStructure();
    argument >> p.port >> p.protocol;
    argument.endStructure();
    return argument;
}

inline QDBusArgument &operator<<(QDBusArgument &argument, const Service& s) {
    argument.beginStructure();
    argument << s.name;
    argument.endStructure();
    return argument;
}

inline const QDBusArgument &operator>>(const QDBusArgument &argument, Service& s) {
    argument.beginStructure();
    argument >> s.name;
    argument.endStructure();
    return argument;
}

inline QDBusArgument &operator<<(QDBusArgument &argument, const RichRule& r) {
    argument.beginStructure();
    argument << r.rule;
    argument.endStructure();
    return argument;
}

inline const QDBusArgument &operator>>(const QDBusArgument &argument, RichRule& r) {
    argument.beginStructure();
    argument >> r.rule;
    argument.endStructure();
    return argument;
}

// NetworkManager Types - Declarations
QDBusArgument &operator<<(QDBusArgument &argument, const IpAddress& val);
const QDBusArgument &operator>>(const QDBusArgument &argument, IpAddress& val);
QDBusArgument &operator<<(QDBusArgument &argument, const NetworkPrefix& val);
const QDBusArgument &operator>>(const QDBusArgument &argument, NetworkPrefix& val);
// InterfaceConfigurationMode is an enum, assume handled by int conversion or direct qDBusRegisterMetaType<EnumType>() if needed.
QDBusArgument &operator<<(QDBusArgument &argument, const ManualIpConfiguration& val);
const QDBusArgument &operator>>(const QDBusArgument &argument, ManualIpConfiguration& val);
QDBusArgument &operator<<(QDBusArgument &argument, const InterfaceConfiguration& val);
const QDBusArgument &operator>>(const QDBusArgument &argument, InterfaceConfiguration& val);
QDBusArgument &operator<<(QDBusArgument &argument, const StaticRoute& val);
const QDBusArgument &operator>>(const QDBusArgument &argument, StaticRoute& val);

// Metatype declarations for QList<T> are REMOVED to prevent auto-streaming attempts for lists.
// Individual types (Port, Service, IpAddress, etc.) have Q_DECLARE_METATYPE in their own headers.


namespace NetworkUtils {
    void registerDbusTypes();
} // namespace NetworkUtils
