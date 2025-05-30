#include "network-utils/types/dbus_types.h" // For NetworkUtils::registerDbusTypes declaration and operator declarations (though definitions are inline)
#include "network-utils/types/port.h"    // For Port type (needed for Q_DECLARE_METATYPE if it was here)
#include "network-utils/types/service.h" // For Service type (needed for Q_DECLARE_METATYPE if it was here)
#include "network-utils/types/rich_rule.h"
#include "network-utils/types/ip_address.h"
#include "network-utils/types/network_prefix.h"
#include "network-utils/types/manual_ip_configuration.h"
#include "network-utils/types/interface_configuration.h"
#include "network-utils/types/static_route.h"
#include "network-utils/types/interface_configuration_mode.h" // For enum

#include <QMetaType>
#include <QDBusMetaType> // For qDBusRegisterMetaType
#include <QList>
#include <QDBusArgument> // For implementing streaming operators

// Q_DECLARE_METATYPE for individual types are in their respective headers (e.g. port.h)
// Q_DECLARE_METATYPE for QList<T> types are in dbus_types.h.
// Operator implementations for Port, Service, RichRule are inline in dbus_types.h.

// --- NetworkManager Type Streaming Operators ---

// IpAddress (Q_DECLARE_METATYPE is in ip_address.h)
QDBusArgument &operator<<(QDBusArgument &argument, const IpAddress& val) {
    argument.beginStructure();
    argument << val.address;
    argument.endStructure();
    return argument;
}
const QDBusArgument &operator>>(const QDBusArgument &argument, IpAddress& val) {
    argument.beginStructure();
    argument >> val.address;
    argument.endStructure();
    return argument;
}

// NetworkPrefix (Q_DECLARE_METATYPE is in network_prefix.h)
QDBusArgument &operator<<(QDBusArgument &argument, const NetworkPrefix& val) {
    argument.beginStructure();
    argument << val.prefixLength;
    argument.endStructure();
    return argument;
}
const QDBusArgument &operator>>(const QDBusArgument &argument, NetworkPrefix& val) {
    argument.beginStructure();
    argument >> val.prefixLength;
    argument.endStructure();
    return argument;
}

// ManualIpConfiguration (Q_DECLARE_METATYPE is in manual_ip_configuration.h)
QDBusArgument &operator<<(QDBusArgument &argument, const ManualIpConfiguration& val) {
    argument.beginStructure();
    argument << val.address << val.prefix << val.gateway << val.dnsServers;
    argument.endStructure();
    return argument;
}
const QDBusArgument &operator>>(const QDBusArgument &argument, ManualIpConfiguration& val) {
    argument.beginStructure();
    argument >> val.address >> val.prefix >> val.gateway >> val.dnsServers;
    argument.endStructure();
    return argument;
}

// InterfaceConfiguration (Q_DECLARE_METATYPE is in interface_configuration.h)
QDBusArgument &operator<<(QDBusArgument &argument, const InterfaceConfiguration& val) {
    argument.beginStructure();
    argument << static_cast<int>(val.mode) << val.manualSettings;
    argument.endStructure();
    return argument;
}
const QDBusArgument &operator>>(const QDBusArgument &argument, InterfaceConfiguration& val) {
    argument.beginStructure();
    int modeAsInt;
    argument >> modeAsInt >> val.manualSettings;
    val.mode = static_cast<InterfaceConfigurationMode>(modeAsInt);
    argument.endStructure();
    return argument;
}

// StaticRoute (Q_DECLARE_METATYPE is in static_route.h)
QDBusArgument &operator<<(QDBusArgument &argument, const StaticRoute& val) {
    argument.beginStructure();
    argument << val.destination << val.prefix << val.gateway << val.metric;
    argument.endStructure();
    return argument;
}
const QDBusArgument &operator>>(const QDBusArgument &argument, StaticRoute& val) {
    argument.beginStructure();
    argument >> val.destination >> val.prefix >> val.gateway >> val.metric;
    argument.endStructure();
    return argument;
}


namespace NetworkUtils {
void registerDbusTypes() {
    // Firewalld Types (operators are inline in dbus_types.h)
    // Their Q_DECLARE_METATYPE is in their respective headers.
    // QList<T> Q_DECLARE_METATYPE calls were removed from dbus_types.h.
    qDBusRegisterMetaType<Port>();
    // qDBusRegisterMetaType<QList<Port>>(); // REMOVED
    qDBusRegisterMetaType<Service>();
    // qDBusRegisterMetaType<QList<Service>>(); // REMOVED
    qDBusRegisterMetaType<RichRule>();
    // qDBusRegisterMetaType<QList<RichRule>>(); // REMOVED

    // NetworkManager Types
    // Their Q_DECLARE_METATYPE is in their respective headers.
    qDBusRegisterMetaType<IpAddress>();
    qDBusRegisterMetaType<NetworkPrefix>();
    qRegisterMetaType<InterfaceConfigurationMode>("InterfaceConfigurationMode"); // Enum needs qRegisterMetaType for QVariant
    // qDBusRegisterMetaType<InterfaceConfigurationMode>(); // Keep removed, streamed as int
    qDBusRegisterMetaType<ManualIpConfiguration>();
    qDBusRegisterMetaType<InterfaceConfiguration>();
    qDBusRegisterMetaType<StaticRoute>();

    // Remove QList<T> registrations for D-Bus
    // qDBusRegisterMetaType<QList<IpAddress>>(); // REMOVED
    // qDBusRegisterMetaType<QList<ManualIpConfiguration>>();
    // qDBusRegisterMetaType<QList<InterfaceConfiguration>>();
    // qDBusRegisterMetaType<QList<StaticRoute>>();

    // Ensure QVariantMap and QList<QVariantMap> are registered for D-Bus,
    // as they are used in properties (e.g. AddressData aa{sv})
    qDBusRegisterMetaType<QMap<QString, QVariant>>();      // For QVariantMap
    qDBusRegisterMetaType<QList<QMap<QString, QVariant>>>();// For QList<QVariantMap>

    // Attempt to explicitly register marshalling operators for QList<QVariantMap>
    // This might help with property system if it's not picking them up automatically.
    // Note: QDBusArgument operators for QList<T> and QMap<K,V> are usually provided by QtDBus if T, K, V are registered.
    // This explicit call is more about ensuring the type signature 'aa{sv}' is correctly associated.
    // QDBusMetaType::registerMarshallOperators<QList<QMap<QString, QVariant>>>(); // This might be redundant if the above is enough

    // We might still need qRegisterMetaType for QList<T> if they are used in QVariant (e.g. signals)
    // For now, removing them to see the effect on D-Bus, can add back if QVariant use breaks.
    // qRegisterMetaType<QList<Port>>();
    // qRegisterMetaType<QList<Service>>();
    // qRegisterMetaType<QList<RichRule>>();
    // qRegisterMetaType<QList<IpAddress>>();
    // qRegisterMetaType<QList<ManualIpConfiguration>>();
    // qRegisterMetaType<QList<InterfaceConfiguration>>();
    // qRegisterMetaType<QList<StaticRoute>>();
}
} // namespace NetworkUtils
