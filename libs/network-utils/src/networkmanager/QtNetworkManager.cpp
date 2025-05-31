#include "network-utils/networkmanager/QtNetworkManager.h" // Updated path
#include <QDebug>
#include <QMetaType>     // For QMetaType::fromType
#include <QDBusObjectPath>
#include <QDBusArgument> // Required for QVariant::value<QDBusArgument>() and streaming QList<QVariantMap>
#include <QHostAddress>  // Required for IP address conversions

// Anonymous namespace for helper utilities
namespace {

quint32 QHostAddressToUint32(const QString &ipString, bool *ok = nullptr) {
    QHostAddress addr(ipString);
    bool conversionOk;
    quint32 ipv4Addr = addr.toIPv4Address(&conversionOk);
    if (ok) {
        *ok = conversionOk;
    }
    if (!conversionOk) {
        qWarning() << "Failed to convert IP string" << ipString << "to quint32.";
        return 0; // Return 0 on error, caller should check 'ok'
    }
    return ipv4Addr;
}

QString Uint32ToQHostAddressString(quint32 ipUint32) {
    return QHostAddress(ipUint32).toString();
}

// Converts a C++ StaticRoute object to a QList<QVariant> suitable for the `aau` "routes" format
// Format: [dest_uint, prefix_uint, gateway_uint, metric_uint]
QList<QVariant> CppRouteToAauVariant(const StaticRoute &route, bool &conversionSuccess) {
    QList<QVariant> aauRoute;
    bool ok1, ok2 = true, ok3 = true; // ok2, ok3 for optional gateway

    quint32 destIp = QHostAddressToUint32(route.destination.address, &ok1);
    quint32 gatewayIp = 0;
    if (route.gateway.isValid() && !route.gateway.address.isEmpty()) { // Check if gateway is valid and not empty
        gatewayIp = QHostAddressToUint32(route.gateway.address, &ok2);
    } else { // No gateway or explicitly empty gateway
        gatewayIp = 0; // NM uses 0 for no gateway in aau format
        ok2 = true; // This path is valid
    }

    // For metric, if it's 0, it's fine. If it's non-zero, it's included.
    // NM uses 0 for default/no metric in aau format.
    quint32 metric = static_cast<quint32>(route.metric);

    conversionSuccess = ok1 && ok2; // ok3 is implicitly true if we don't have a gateway string

    if (!conversionSuccess) {
        qWarning() << "Failed to convert StaticRoute to AAU variant due to IP address conversion errors.";
        return {};
    }

    aauRoute << QVariant::fromValue(destIp)
             << QVariant::fromValue(static_cast<quint32>(route.prefix.prefixLength))
             << QVariant::fromValue(gatewayIp)
             << QVariant::fromValue(metric);
    return aauRoute;
}

// Converts an `aau` route entry (as QList<QVariant>) back to a C++ StaticRoute.
StaticRoute AauVariantToCppRoute(const QList<QVariant> &aauRouteData, bool &conversionSuccess) {
    StaticRoute route;
    conversionSuccess = false;
    if (aauRouteData.count() < 4) { // Must have at least dest, prefix, gateway, metric
        qWarning() << "AAU route data has too few elements:" << aauRouteData.count();
        return route;
    }

    bool okDest = aauRouteData[0].canConvert<quint32>();
    bool okPrefix = aauRouteData[1].canConvert<quint32>();
    bool okGateway = aauRouteData[2].canConvert<quint32>();
    bool okMetric = aauRouteData[3].canConvert<quint32>();

    if (!okDest || !okPrefix || !okGateway || !okMetric) {
        qWarning() << "AAU route data elements cannot be converted to quint32.";
        return route;
    }

    route.destination.address = Uint32ToQHostAddressString(aauRouteData[0].toUInt());
    route.prefix.prefixLength = aauRouteData[1].toUInt();

    quint32 gatewayIp = aauRouteData[2].toUInt();
    if (gatewayIp != 0) { // 0 means no gateway in aau
        route.gateway.address = Uint32ToQHostAddressString(gatewayIp);
    } else {
        route.gateway.address = QString(); // Explicitly empty
    }
    route.metric = aauRouteData[3].toUInt();

    conversionSuccess = true;
    return route;
}

// Converts C++ ManualIpConfiguration (first address only) to QList<QVariant> for `aau` "addresses" format
// Format: [addr_uint, prefix_uint, gateway_uint]
QList<QVariant> CppManualIpToAauVariant(const ManualIpConfiguration &manualIp, bool &conversionSuccess) {
    QList<QVariant> aauAddress;
    bool okAddr, okGateway = true;

    quint32 addrIp = QHostAddressToUint32(manualIp.address.address, &okAddr);
    quint32 gatewayIp = 0;

    if (manualIp.gateway.isValid() && !manualIp.gateway.address.isEmpty()) {
        gatewayIp = QHostAddressToUint32(manualIp.gateway.address, &okGateway);
    } else {
        gatewayIp = 0; // No gateway
        okGateway = true;
    }

    conversionSuccess = okAddr && okGateway;
    if (!conversionSuccess) {
        qWarning() << "Failed to convert ManualIpConfiguration to AAU variant due to IP address conversion errors.";
        return {};
    }

    aauAddress << QVariant::fromValue(addrIp)
               << QVariant::fromValue(static_cast<quint32>(manualIp.prefix.prefixLength))
               << QVariant::fromValue(gatewayIp);
    return aauAddress;
}

// Converts an `aau` address entry to relevant parts of ManualIpConfiguration.
// Only fills address, prefix, gateway. DNS is handled separately.
ManualIpConfiguration AauVariantToCppManualIp(const QList<QVariant> &aauAddrData, bool &conversionSuccess) {
    ManualIpConfiguration manualIp;
    conversionSuccess = false;
    if (aauAddrData.count() < 3) { // Must have addr, prefix, gateway
        qWarning() << "AAU address data has too few elements:" << aauAddrData.count();
        return manualIp;
    }

    bool okAddr = aauAddrData[0].canConvert<quint32>();
    bool okPrefix = aauAddrData[1].canConvert<quint32>();
    bool okGateway = aauAddrData[2].canConvert<quint32>();

    if (!okAddr || !okPrefix || !okGateway) {
        qWarning() << "AAU address data elements cannot be converted to quint32.";
        return manualIp;
    }

    manualIp.address.address = Uint32ToQHostAddressString(aauAddrData[0].toUInt());
    manualIp.prefix.prefixLength = aauAddrData[1].toUInt();
    quint32 gatewayIp = aauAddrData[2].toUInt();
    if (gatewayIp != 0) {
        manualIp.gateway.address = Uint32ToQHostAddressString(gatewayIp);
    } else {
        manualIp.gateway.address = QString();
    }
    // DNS servers are not part of this specific "addresses" aau structure, handled separately.

    conversionSuccess = true;
    return manualIp;
}

} // anonymous namespace

// D-Bus Service and Path Constants
const QString NM_SERVICE = "org.freedesktop.NetworkManager";
const QString NM_PATH = "/org/freedesktop/NetworkManager";
const QString NM_MAIN_INTERFACE = "org.freedesktop.NetworkManager"; // Corrected, was NM_INTERFACE
const QString NM_DEVICE_INTERFACE = "org.freedesktop.NetworkManager.Device";
const QString NM_IP4CONFIG_INTERFACE = "org.freedesktop.NetworkManager.IP4Config";
const QString NM_IP6CONFIG_INTERFACE = "org.freedesktop.NetworkManager.IP6Config"; // For future use

QtNetworkManager::QtNetworkManager(QDBusConnection connection)
    : m_dbusConnection(connection) {
    // D-Bus types should be registered once globally.
    // NetworkUtils::registerDbusTypes(); // Assuming this is done elsewhere or not strictly needed for connection objects

    m_nmDbusInterface = createNetworkManagerInterface(); // Store for later use if needed for global signals
    if (!m_nmDbusInterface || !m_nmDbusInterface->isValid()) {
        qWarning() << "Failed to create a valid D-Bus interface for NetworkManager. Signal handling will be disabled.";
        // Optionally throw, or allow object creation but with degraded functionality
        return;
    }

    // Connect to global NetworkManager signals for device addition/removal
    bool c1 = QDBusConnection::systemBus().connect(
        NM_SERVICE, NM_PATH, NM_MAIN_INTERFACE, "DeviceAdded",
        this, SLOT(onDeviceAdded(QDBusObjectPath))
    );
    bool c2 = QDBusConnection::systemBus().connect(
        NM_SERVICE, NM_PATH, NM_MAIN_INTERFACE, "DeviceRemoved",
        this, SLOT(onDeviceRemoved(QDBusObjectPath))
    );

    if (!c1 || !c2) {
        qWarning() << "QtNetworkManager: Failed to connect to DeviceAdded/DeviceRemoved signals."
                   << "c1:" << c1 << m_nmDbusInterface->lastError().message()
                   << "c2:" << c2 << m_nmDbusInterface->lastError().message();
        // Proceeding, but device hotplugging might not work.
    }

    // Initial subscription to signals for already existing devices
    try {
        QStringList currentInterfaces = listInterfaceNames(); // This can throw if NM is down
        for (const QString &ifaceName : currentInterfaces) {
            subscribeToSignalsForInterface(ifaceName);
        }
    } catch (const NetworkManagerDBusError &e) {
        qWarning() << "QtNetworkManager: Failed to list initial interfaces for signal subscription: " << e.what()
                   << "Signal handling for existing devices might be incomplete.";
    }
}

// --- Helper methods for creating D-Bus interfaces ---
QDBusInterface* QtNetworkManager::createNetworkManagerInterface() const {
    return new QDBusInterface(NM_SERVICE, NM_PATH, NM_MAIN_INTERFACE, m_dbusConnection, nullptr);
}

QDBusInterface* QtNetworkManager::createDeviceInterface(const QString& devicePath) const {
    return new QDBusInterface(NM_SERVICE, devicePath, NM_DEVICE_INTERFACE, m_dbusConnection, nullptr);
}

QDBusInterface* QtNetworkManager::createIp4ConfigInterface(const QString& ip4ConfigPath) const {
    return new QDBusInterface(NM_SERVICE, ip4ConfigPath, NM_IP4CONFIG_INTERFACE, m_dbusConnection, nullptr);
}

QDBusInterface* QtNetworkManager::createIp6ConfigInterface(const QString& ip6ConfigPath) const {
    return new QDBusInterface(NM_SERVICE, ip6ConfigPath, NM_IP6CONFIG_INTERFACE, m_dbusConnection, nullptr);
}

QDBusInterface* QtNetworkManager::createSettingsInterface() const {
    return new QDBusInterface(NM_SERVICE, "/org/freedesktop/NetworkManager/Settings", "org.freedesktop.NetworkManager.Settings", m_dbusConnection, nullptr);
}

QDBusInterface* QtNetworkManager::createSettingsConnectionInterface(const QString& connectionPath) const {
    return new QDBusInterface(NM_SERVICE, connectionPath, "org.freedesktop.NetworkManager.Settings.Connection", m_dbusConnection, nullptr);
}


QString QtNetworkManager::getDevicePath(const QString &interfaceName) const {
    QScopedPointer<QDBusInterface> nmInterface(createNetworkManagerInterface());
    if (!nmInterface || !nmInterface->isValid()) {
        throw NetworkManagerDBusError("Failed to connect to NetworkManager service: " +
                                      (nmInterface ? nmInterface->lastError().message() : "Interface creation failed"));
    }

    QDBusReply<QList<QDBusObjectPath>> devicesReply = nmInterface->call("GetDevices");
    if (!devicesReply.isValid()) {
        throw NetworkManagerDBusError("GetDevices call failed: " + devicesReply.error().message());
    }

    for (const QDBusObjectPath &devicePath : devicesReply.value()) {
        QScopedPointer<QDBusInterface> deviceInterface(createDeviceInterface(devicePath.path()));
        if (deviceInterface && deviceInterface->isValid()) {
            QVariant interfaceProperty = deviceInterface->property("Interface");
            if (interfaceProperty.isValid() && interfaceProperty.toString() == interfaceName) {
                return devicePath.path();
            }
             if (deviceInterface->lastError().type() != QDBusError::NoError) {
                qWarning() << "Error reading Interface property from" << devicePath.path() << ":" << deviceInterface->lastError().message();
            }
        } else {
            qWarning() << "QtNetworkManager::getDevicePath: Could not create valid interface for device path" << devicePath.path() << ":" << (deviceInterface ? deviceInterface->lastError().message() : "Interface creation failed");
        }
    }
    throw NetworkManagerDBusError(QString("Device with interface name '%1' not found.").arg(interfaceName));
}

QString QtNetworkManager::getInterfaceNameFromDevicePath(const QString &devicePath) const {
    if (m_devicePathToNameMap.contains(devicePath)) {
        return m_devicePathToNameMap.value(devicePath);
    }
    // Fallback: Query the device directly if not in map (e.g., during onDeviceAdded before map is populated by subscribe)
    // This might be slow if called frequently for unknown paths.
    QScopedPointer<QDBusInterface> deviceInterface(createDeviceInterface(devicePath));
    if (deviceInterface && deviceInterface->isValid()) {
        QVariant interfaceProperty = deviceInterface->property("Interface");
        if (interfaceProperty.isValid() && !interfaceProperty.toString().isEmpty()) {
            return interfaceProperty.toString();
        }
    }
    qWarning() << "getInterfaceNameFromDevicePath: Could not resolve interface name for path" << devicePath;
    return QString(); // Empty string if not found
}


QStringList QtNetworkManager::listInterfaceNames() const {
    // Use m_nmDbusInterface if it's valid, otherwise create a temporary one.
    // Prefer not to use m_nmDbusInterface directly in const methods if it implies state change,
    // but for reading GetDevices it's okay.
    QDBusInterface* nmInterfaceToUse = nullptr;
    QScopedPointer<QDBusInterface> tempInterface;

    if (m_nmDbusInterface && m_nmDbusInterface->isValid()) {
        nmInterfaceToUse = m_nmDbusInterface;
    } else {
        tempInterface.reset(createNetworkManagerInterface());
        if (!tempInterface || !tempInterface->isValid()) {
             throw NetworkManagerDBusError("Failed to connect to NetworkManager service: " +
                                      (tempInterface ? tempInterface->lastError().message() : "Interface creation failed"));
        }
        nmInterfaceToUse = tempInterface.data();
    }

    Q_ASSERT(nmInterfaceToUse); // Should be valid or thrown above

    QDBusReply<QList<QDBusObjectPath>> devicesReply = nmInterfaceToUse->call("GetDevices");

    if (!devicesReply.isValid()) {
        throw NetworkManagerDBusError("GetDevices call failed: " + devicesReply.error().message());
    }

    QStringList interfaceNames;
    for (const QDBusObjectPath &devicePath : devicesReply.value()) {
        QScopedPointer<QDBusInterface> deviceInterface(createDeviceInterface(devicePath.path()));
        if (deviceInterface && deviceInterface->isValid()) {
            QVariant interfaceProperty = deviceInterface->property("Interface");
            if (interfaceProperty.isValid() && !interfaceProperty.toString().isEmpty()) {
                interfaceNames.append(interfaceProperty.toString());
            } else if (deviceInterface->lastError().type() != QDBusError::NoError) {
                 qWarning() << "Failed to read Interface property for device" << devicePath.path() << ":" << deviceInterface->lastError().message();
            }
        } else {
             qWarning() << "Could not create valid interface for device path" << devicePath.path() << ":" << (deviceInterface ? deviceInterface->lastError().message() : "Interface creation failed");
        }
    }
    return interfaceNames;
}

InterfaceDetails QtNetworkManager::getInterfaceDetails(const QString &interfaceName) const {
    InterfaceDetails details;
    details.name = interfaceName;

    QString devicePath = getDevicePath(interfaceName); // Can throw

    QScopedPointer<QDBusInterface> deviceIface(createDeviceInterface(devicePath));
    if (!deviceIface || !deviceIface->isValid()) {
        throw NetworkManagerDBusError("Failed to create D-Bus interface for device " + devicePath + ": " +
                                      (deviceIface ? deviceIface->lastError().message() : "Interface creation failed"));
    }

    QVariant स्थायीHwAddressVar = deviceIface->property("PermHwAddress"); // Try PermHwAddress first
    if (स्थायीHwAddressVar.isValid() && !स्थायीHwAddressVar.toString().isEmpty()) {
         details.macAddress = स्थायीHwAddressVar.toString();
    } else {
        QVariant hwAddressVar = deviceIface->property("HwAddress");
        if (hwAddressVar.isValid()) details.macAddress = hwAddressVar.toString();
        else qWarning() << "Could not read HwAddress or PermHwAddress for" << interfaceName << ":" << deviceIface->lastError().message();
    }


    QVariant stateVar = deviceIface->property("State");
    if (stateVar.isValid()) {
        quint32 state = stateVar.toUInt();
        details.isUp = (state == NM_DEVICE_STATE_ACTIVATED || state == NM_DEVICE_STATE_IP_CONFIG || state == NM_DEVICE_STATE_IP_CHECK || state == NM_DEVICE_STATE_SECONDARIES);
    } else {
        qWarning() << "Could not read State for" << interfaceName << ":" << deviceIface->lastError().message();
    }

    QVariant speedVar = deviceIface->property("Speed");
    qDebug() << "Attempting to read Speed property for" << interfaceName;
    qDebug() << "  speedVar.isValid():" << speedVar.isValid();
    if (speedVar.isValid()) {
        qDebug() << "  speedVar.metaType().id():" << speedVar.metaType().id();
        qDebug() << "  speedVar.metaType().name():" << speedVar.metaType().name();
        qDebug() << "  speedVar.userType():" << speedVar.userType();
        qDebug() << "  Expected QMetaType for quint32: id" << QMetaType::fromType<quint32>().id()
                 << "name" << QMetaType::fromType<quint32>().name();
        qDebug() << "  Is speedVar.metaType() == QMetaType::fromType<quint32>() ?" << (speedVar.metaType() == QMetaType::fromType<quint32>());
    } else {
        qDebug() << "  speedVar is invalid. D-Bus error:" << deviceIface->lastError().message();
    }
    if (speedVar.isValid() && speedVar.canConvert<quint32>()) {
        details.speed = speedVar.toUInt();
        if (details.speed == 0) {
            // NM reports 0 for unknown speed (e.g. virtual devices, or if speed detection failed)
            // This is not necessarily an error, but good to be aware of.
            qDebug() << "Speed for" << interfaceName << "is reported as 0 kbit/s.";
        }
    } else {
        if (!speedVar.isValid()) {
            qWarning() << "Could not read Speed for" << interfaceName << "(property invalid):" << deviceIface->lastError().message();
        } else {
            // Property is valid, but maybe not the expected type or value is out of range for quint32 (unlikely for kbit/s speed)
            qWarning() << "Speed property for" << interfaceName << "is valid, but not convertible to quint32. Value:" << speedVar;
        }
        details.speed = 0; // Default to 0 if unable to read or convert
    }

    QVariant ip4ConfigPathVar = deviceIface->property("Ip4Config");
    if (!ip4ConfigPathVar.isValid() || !ip4ConfigPathVar.canConvert<QDBusObjectPath>()) {
        qWarning() << "Could not read Ip4Config path for" << interfaceName << ":" << deviceIface->lastError().message();
    } else {
        QDBusObjectPath ip4ConfigPath = ip4ConfigPathVar.value<QDBusObjectPath>();
        if (!ip4ConfigPath.path().isEmpty() && ip4ConfigPath.path() != "/") {
            QScopedPointer<QDBusInterface> ip4ConfigIface(createIp4ConfigInterface(ip4ConfigPath.path()));
            if (ip4ConfigIface && ip4ConfigIface->isValid()) {
                QVariant addressesVar = ip4ConfigIface->property("AddressData");
                if (addressesVar.isValid()) {
                    qDebug() << "AddressData property (addressesVar) is valid for interface:" << interfaceName;
                    qDebug() << "  addressesVar.metaType().id():" << addressesVar.metaType().id();
                    qDebug() << "  addressesVar.metaType().name():" << addressesVar.metaType().name();
                    qDebug() << "  addressesVar.userType():" << addressesVar.userType(); // Useful if it's a custom type
                    qDebug() << "  Expected QMetaType for QList<QVariantMap>: id" << QMetaType::fromType<QList<QVariantMap>>().id()
                             << "name" << QMetaType::fromType<QList<QVariantMap>>().name();
                    qDebug() << "  Is addressesVar.metaType() == QMetaType::fromType<QList<QVariantMap>>() ?" << (addressesVar.metaType() == QMetaType::fromType<QList<QVariantMap>>());
                    qDebug() << "  Can convert to QList<QVariantMap>?" << addressesVar.canConvert<QList<QVariantMap>>();

                    QDBusArgument arg = addressesVar.value<QDBusArgument>();
                    arg.beginArray(); // For aa{sv}
                    if (!arg.atEnd()) { // Typically take the first address configuration
                        arg.beginStructure(); // For a{sv}
                        QVariantMap addressMap;
                        // This part is tricky for aa{sv} directly. Let's assume it's QList<QVariantMap>
                        // as qvariant_cast is often used for this.
                        QList<QVariantMap> addressDataList = qvariant_cast<QList<QVariantMap>>(addressesVar);
                        if (!addressDataList.isEmpty()) {
                            QVariantMap firstAddressMap = addressDataList.first();
                            if (firstAddressMap.contains("address")) {
                                details.currentIpAddress.address = firstAddressMap.value("address").toString();
                            }
                            if (firstAddressMap.contains("prefix")) {
                                details.currentPrefix.prefixLength = firstAddressMap.value("prefix").toUInt();
                            }
                        } else {
                             qWarning() << "AddressData list is empty for" << interfaceName;
                        }
                        // arg.endStructure(); // If we were manually iterating QDBusArgument
                    }
                    // arg.endArray(); // If we were manually iterating QDBusArgument

                } else {
                     qWarning() << "Could not read AddressData for" << interfaceName << "from" << ip4ConfigPath.path() << ":" << ip4ConfigIface->lastError().message();
                }

                QVariant gatewayVar = ip4ConfigIface->property("Gateway");
                if (gatewayVar.isValid()) details.currentGateway.address = gatewayVar.toString();
                else qWarning() << "Could not read Gateway for" << interfaceName << "from" << ip4ConfigPath.path() << ":" << ip4ConfigIface->lastError().message();

                QVariant dnsVar = ip4ConfigIface->property("NameserverData");
                 if (dnsVar.isValid()) {
                    QList<QVariantMap> dnsDataList = qvariant_cast<QList<QVariantMap>>(dnsVar);
                    for (const QVariantMap &dnsMap : dnsDataList) {
                        if (dnsMap.contains("address")) {
                            details.currentDnsServers.append(IpAddress{dnsMap.value("address").toString()});
                        }
                    }
                } else {
                    qWarning() << "Could not read NameserverData for" << interfaceName << "from" << ip4ConfigPath.path() << ":" << ip4ConfigIface->lastError().message();
                }

            } else {
                qWarning() << "Could not create valid interface for IP4Config path" << ip4ConfigPath.path() << ":" << (ip4ConfigIface ? ip4ConfigIface->lastError().message() : "Interface creation failed");
            }
        } else {
             qDebug() << interfaceName << "has no valid Ip4Config path:" << ip4ConfigPath.path();
        }
    }

    details.configuration.mode = InterfaceConfigurationMode::Unknown; // To be implemented
    // details.staticRoutes; // To be implemented

    return details;
}

// --- Signal Subscription Helpers ---
void QtNetworkManager::subscribeToSignalsForInterface(const QString &interfaceName) {
    if (interfaceName.isEmpty()) {
        qWarning() << "subscribeToSignalsForInterface: Interface name is empty, cannot subscribe.";
        return;
    }
    try {
        QString devicePath = getDevicePath(interfaceName); // Can throw
        if (!devicePath.isEmpty()) {
            m_devicePathToNameMap.insert(devicePath, interfaceName); // Populate map
            subscribeToDeviceSignals(devicePath, interfaceName);
        } else {
            qWarning() << "subscribeToSignalsForInterface: Could not get device path for" << interfaceName;
        }
    } catch (const NetworkManagerDBusError &e) {
        qWarning() << "subscribeToSignalsForInterface: Error getting device path for" << interfaceName << ":" << e.what();
    }
}

void QtNetworkManager::subscribeToDeviceSignals(const QString &devicePath, const QString &interfaceName) {
    if (m_trackedDeviceInterfaces.contains(devicePath)) {
        qDebug() << "Already subscribed to signals for device path" << devicePath;
        return;
    }

    QDBusInterface* deviceInterface = createDeviceInterface(devicePath);
    if (!deviceInterface || !deviceInterface->isValid()) {
        qWarning() << "Failed to create D-Bus interface for device" << devicePath << "for signal subscription.";
        delete deviceInterface;
        return;
    }

    // Connection for org.freedesktop.NetworkManager.Device.StateChanged
    bool stateChangedConnected = connect(deviceInterface, SIGNAL(StateChanged(uint, uint, uint)),
                                       this, SLOT(onDeviceStateChanged(uint, uint, uint)));
    if (!stateChangedConnected) {
        qWarning() << "Failed to connect to StateChanged signal for device" << devicePath << ":" << deviceInterface->lastError().message();
    }

    // Connection for org.freedesktop.DBus.Properties.PropertiesChanged
    // The actual signal is on "org.freedesktop.DBus.Properties" but emitted by the device object.
    bool propsChangedConnected = QDBusConnection::systemBus().connect(
        NM_SERVICE, devicePath, "org.freedesktop.DBus.Properties", "PropertiesChanged",
        this, SLOT(onDeviceDBusPropertiesChanged(QString, QVariantMap, QStringList))
    );
    if (!propsChangedConnected) {
        qWarning() << "Failed to connect to org.freedesktop.DBus.Properties.PropertiesChanged signal for device" << devicePath;
        // Note: QDBusInterface::lastError() might not be relevant here as connect is static.
    }

    m_trackedDeviceInterfaces.insert(devicePath, deviceInterface);
    m_devicePathToNameMap.insert(devicePath, interfaceName); // Ensure map is up-to-date

    // Subscribe to IP4Config signals
    QVariant ip4ConfigPathVar = deviceInterface->property("Ip4Config");
    if (ip4ConfigPathVar.isValid() && ip4ConfigPathVar.canConvert<QDBusObjectPath>()) {
        QDBusObjectPath ip4ConfigPath = ip4ConfigPathVar.value<QDBusObjectPath>();
        if (!ip4ConfigPath.path().isEmpty() && ip4ConfigPath.path() != "/") {
            subscribeToIp4ConfigSignals(ip4ConfigPath.path(), interfaceName);
            m_ip4ConfigPathToDevicePathMap.insert(ip4ConfigPath.path(), devicePath);
        }
    }
}

void QtNetworkManager::subscribeToIp4ConfigSignals(const QString &ip4ConfigPath, const QString &associatedInterfaceName) {
    if (m_trackedIp4ConfigInterfaces.contains(ip4ConfigPath)) {
        qDebug() << "Already subscribed to signals for IP4Config path" << ip4ConfigPath;
        return;
    }

    QDBusInterface* ip4ConfigInterface = createIp4ConfigInterface(ip4ConfigPath);
    if (!ip4ConfigInterface || !ip4ConfigInterface->isValid()) {
        qWarning() << "Failed to create D-Bus interface for IP4Config" << ip4ConfigPath << "for signal subscription.";
        delete ip4ConfigInterface;
        return;
    }

    // Connect org.freedesktop.DBus.Properties.PropertiesChanged for IP4Config
    bool propsChangedConnected = QDBusConnection::systemBus().connect(
        NM_SERVICE, ip4ConfigPath, "org.freedesktop.DBus.Properties", "PropertiesChanged",
        this, SLOT(onIp4ConfigPropertiesChanged(QString, QVariantMap, QStringList))
    );

    if (!propsChangedConnected) {
        qWarning() << "Failed to connect to PropertiesChanged signal for IP4Config" << ip4ConfigPath;
        // ip4ConfigInterface->lastError() is not useful here as it's a static connect call
        delete ip4ConfigInterface; // Don't store it if connection failed
        return;
    }
    m_trackedIp4ConfigInterfaces.insert(ip4ConfigPath, ip4ConfigInterface);
}

void QtNetworkManager::cleanupDeviceSubscriptions(const QString &devicePath) {
    // Disconnect and delete device interface
    if (m_trackedDeviceInterfaces.contains(devicePath)) {
        QDBusInterface* devIface = m_trackedDeviceInterfaces.take(devicePath);
        disconnect(devIface, nullptr, this, nullptr); // Disconnect all signals from this device to this QtNetworkManager
        // Also disconnect the static QDBusConnection::connect for PropertiesChanged
        QDBusConnection::systemBus().disconnect(NM_SERVICE, devicePath, "org.freedesktop.DBus.Properties", "PropertiesChanged",
                                            this, SLOT(onDeviceDBusPropertiesChanged(QString, QVariantMap, QStringList)));
        devIface->deleteLater();
    }
    m_devicePathToNameMap.remove(devicePath);

    // Find and cleanup associated IP4Config interface
    QString ip4ConfigPathToRemove;
    for (auto it = m_ip4ConfigPathToDevicePathMap.begin(); it != m_ip4ConfigPathToDevicePathMap.end(); ++it) {
        if (it.value() == devicePath) {
            ip4ConfigPathToRemove = it.key();
            break;
        }
    }
    if (!ip4ConfigPathToRemove.isEmpty() && m_trackedIp4ConfigInterfaces.contains(ip4ConfigPathToRemove)) {
        QDBusInterface* ip4Iface = m_trackedIp4ConfigInterfaces.take(ip4ConfigPathToRemove);
        // The lambda connection for PropertiesChanged on IP4Config should auto-disconnect when ip4Iface is deleted.
        // Or, more explicitly:
        disconnect(ip4Iface, SIGNAL(PropertiesChanged(QVariantMap,QStringList)), this, nullptr);
        ip4Iface->deleteLater();
        m_ip4ConfigPathToDevicePathMap.remove(ip4ConfigPathToRemove);
    }
     qDebug() << "Cleaned up subscriptions for device path:" << devicePath;
}


// --- D-Bus Signal Handler Slots ---
void QtNetworkManager::onDeviceAdded(const QDBusObjectPath &devicePath) {
    qDebug() << "Device added (D-Bus signal):" << devicePath.path();
    // We need to get the interface name for this device path to call subscribeToSignalsForInterface.
    // This might involve a direct D-Bus call to get the "Interface" property.
    QString interfaceName = getInterfaceNameFromDevicePath(devicePath.path());
    if (!interfaceName.isEmpty()) {
        subscribeToSignalsForInterface(interfaceName);
    } else {
        qWarning() << "Could not determine interface name for added device" << devicePath.path() << ". Cannot subscribe to its signals yet.";
        // It's possible the device is not fully initialized; properties might arrive later.
        // For now, we might miss signals if name resolution fails here.
    }
}

void QtNetworkManager::onDeviceRemoved(const QDBusObjectPath &devicePath) {
    qDebug() << "Device removed (D-Bus signal):" << devicePath.path();
    QString interfaceName = m_devicePathToNameMap.value(devicePath.path(), QString("UnknownIfRemoved"));
    cleanupDeviceSubscriptions(devicePath.path());
    emit interfaceChanged(interfaceName);
}

void QtNetworkManager::onDeviceStateChanged(uint newState, uint oldState, uint reason) {
    Q_UNUSED(newState); Q_UNUSED(oldState); Q_UNUSED(reason);
    QObject* rawSender = sender();
    QDBusInterface* deviceInterface = qobject_cast<QDBusInterface*>(rawSender);
    if (deviceInterface) {
        QString devicePath = deviceInterface->path();
        QString interfaceName = getInterfaceNameFromDevicePath(devicePath);
        if (!interfaceName.isEmpty()) {
            qDebug() << "Device" << interfaceName << "(path" << devicePath << ") state changed.";
            emit interfaceChanged(interfaceName);
        } else {
            qWarning() << "onDeviceStateChanged: Received signal from unknown device path" << devicePath;
        }
    } else {
        qWarning() << "onDeviceStateChanged: Could not get sender interface.";
    }
}

void QtNetworkManager::onDeviceDBusPropertiesChanged(const QString &dbusInterfaceName,
                                                  const QVariantMap &changedProperties,
                                                  const QStringList &invalidatedProperties) {
    Q_UNUSED(dbusInterfaceName); // Should be "org.freedesktop.NetworkManager.Device" or the specific one if PropertiesChanged is not from org.freedesktop.DBus.Properties
    Q_UNUSED(changedProperties);
    Q_UNUSED(invalidatedProperties);

    QObject* rawSender = sender(); // This is the QDBusInterface object for the *device* itself
    if (rawSender) {
        // The path of rawSender (which is a QDBusInterface representing the device) IS the device path.
        QDBusAbstractInterface* dbusSender = qobject_cast<QDBusAbstractInterface*>(rawSender);
        if (!dbusSender) {
            qWarning() << "onDeviceDBusPropertiesChanged: Sender is not a QDBusAbstractInterface.";
            return;
        }
        QString devicePath = dbusSender->path();
        QString interfaceName = getInterfaceNameFromDevicePath(devicePath);
        if (!interfaceName.isEmpty()) {
            qDebug() << "Device properties for" << interfaceName << "(path" << devicePath << ") changed:" << changedProperties;
            emit interfaceChanged(interfaceName);

            // If Ip4Config path changed, we might need to update subscriptions
            if (changedProperties.contains("Ip4Config")) {
                 qDebug() << "Ip4Config path may have changed for" << interfaceName << ". Re-evaluating IP config signal subscriptions.";
                 // Simplified: cleanup existing IP config subs and re-subscribe
                 // Find old ip4config path to remove from m_trackedIp4ConfigInterfaces and m_ip4ConfigPathToDevicePathMap
                 QString oldIp4ConfigPath;
                 for(auto it = m_ip4ConfigPathToDevicePathMap.begin(); it != m_ip4ConfigPathToDevicePathMap.end(); ++it) {
                     if (it.value() == devicePath) {
                         oldIp4ConfigPath = it.key();
                         break;
                     }
                 }
                 if (!oldIp4ConfigPath.isEmpty() && m_trackedIp4ConfigInterfaces.contains(oldIp4ConfigPath)) {
                     QDBusInterface* ip4Iface = m_trackedIp4ConfigInterfaces.take(oldIp4ConfigPath);
                     disconnect(ip4Iface, SIGNAL(PropertiesChanged(QVariantMap,QStringList)), this, nullptr);
                     ip4Iface->deleteLater();
                     m_ip4ConfigPathToDevicePathMap.remove(oldIp4ConfigPath);
                 }

                 QVariant newIp4ConfigPathVar = changedProperties.value("Ip4Config");
                 if (newIp4ConfigPathVar.isValid() && newIp4ConfigPathVar.canConvert<QDBusObjectPath>()) {
                     QDBusObjectPath newIp4Path = newIp4ConfigPathVar.value<QDBusObjectPath>();
                     if (!newIp4Path.path().isEmpty() && newIp4Path.path() != "/") {
                         subscribeToIp4ConfigSignals(newIp4Path.path(), interfaceName);
                         m_ip4ConfigPathToDevicePathMap.insert(newIp4Path.path(), devicePath);
                     }
                 }
            }
        } else {
            qWarning() << "onDeviceDBusPropertiesChanged: Received signal from unknown device path" << devicePath;
        }
    } else {
         qWarning() << "onDeviceDBusPropertiesChanged: Could not get sender.";
    }
}

void QtNetworkManager::onIp4ConfigPropertiesChanged(const QString &dbusInterfaceName,
                                                 const QVariantMap &changedProperties,
                                                 const QStringList &invalidatedProperties) {
    Q_UNUSED(dbusInterfaceName); // Expected to be "org.freedesktop.NetworkManager.IP4Config"
    Q_UNUSED(changedProperties);
    Q_UNUSED(invalidatedProperties);

    QObject* rawSender = sender();
    QDBusAbstractInterface* dbusSender = qobject_cast<QDBusAbstractInterface*>(rawSender);
    if (!dbusSender) {
        qWarning() << "onIp4ConfigPropertiesChanged: Sender is not a QDBusAbstractInterface.";
        return;
    }

    QString ip4ConfigPath = dbusSender->path();
    QString devicePath = m_ip4ConfigPathToDevicePathMap.value(ip4ConfigPath);
    if (devicePath.isEmpty()) {
        qWarning() << "onIp4ConfigPropertiesChanged: Could not find device path for IP4Config path" << ip4ConfigPath;
        return;
    }

    QString interfaceName = m_devicePathToNameMap.value(devicePath);
    if (!interfaceName.isEmpty()) {
        qDebug() << "IP4Config for" << interfaceName << "(path" << ip4ConfigPath << ") changed:" << changedProperties;
        emit interfaceChanged(interfaceName);
    } else {
        qWarning() << "onIp4ConfigPropertiesChanged: Received signal for IP4Config path" << ip4ConfigPath
                   << "but could not resolve to an interface name via device path" << devicePath;
    }
}


// --- Helper method implementations ---
QString QtNetworkManager::findConnectionPathForInterface(const QString &interfaceName) const {
    QScopedPointer<QDBusInterface> settingsInterface(createSettingsInterface());
    if (!settingsInterface || !settingsInterface->isValid()) {
        throw NetworkManagerDBusError("Failed to create D-Bus interface for NetworkManager settings: " +
                                      (settingsInterface ? settingsInterface->lastError().message() : "Interface creation failed"));
    }

    QDBusReply<QList<QDBusObjectPath>> connectionsReply = settingsInterface->call("ListConnections");
    if (!connectionsReply.isValid()) {
        throw NetworkManagerDBusError("ListConnections call failed: " + connectionsReply.error().message());
    }

    for (const QDBusObjectPath &connPath : connectionsReply.value()) {
        QScopedPointer<QDBusInterface> connInterface(createSettingsConnectionInterface(connPath.path()));
        if (!connInterface || !connInterface->isValid()) {
            qWarning() << "Could not create D-Bus interface for connection" << connPath.path() << ":" << (connInterface ? connInterface->lastError().message() : "Interface creation failed");
            continue;
        }
        QDBusReply<QVariantMap> settingsMapReply = connInterface->call("GetSettings");
        if (!settingsMapReply.isValid()) {
            qWarning() << "GetSettings call failed for connection" << connPath.path() << ":" << settingsMapReply.error().message();
            continue;
        }
        QVariantMap settingsMap = settingsMapReply.value();
        if (settingsMap.contains("connection")) {
            QVariantMap connectionSettings = qvariant_cast<QVariantMap>(settingsMap.value("connection"));
            if (connectionSettings.value("interface-name").toString() == interfaceName) {
                return connPath.path();
            }
        }
    }
    throw NetworkManagerDBusError(QString("No connection profile found for interface '%1'.").arg(interfaceName));
}


QVariantMap QtNetworkManager::convertManualIpConfigurationToDBus(const ManualIpConfiguration &manualConfig) const {
    QVariantMap ipv4Map;
    QList<QVariant> addresses;
    QVariantMap addressEntry;
    addressEntry.insert("address", manualConfig.address.address);
    addressEntry.insert("prefix", manualConfig.prefix.prefixLength);
    addresses.append(QVariant::fromValue(addressEntry));
    ipv4Map.insert("address-data", QVariant::fromValue(addresses));

    if (!manualConfig.gateway.address.isEmpty()) {
        ipv4Map.insert("gateway", manualConfig.gateway.address);
    }
    // NM uses "dns" for an array of DNS server IPs (as uin32), and "dns-search" for search domains.
    // For simplicity, assuming DNS servers are passed as strings and need conversion if NM expects uint32.
    // However, the property is actually NameserverData which is aa{sv} like AddressData.
    // Let's stick to what is simple to set. Direct "dns" as a string array is often supported.
    QStringList dnsServers;
    for(const auto& dns : manualConfig.dnsServers) {
        dnsServers.append(dns.address);
    }
    if (!dnsServers.isEmpty()) {
        ipv4Map.insert("dns", QVariant::fromValue(dnsServers));
    }
    ipv4Map.insert("method", "manual");
    return ipv4Map;
}


// --- Method Implementations ---

bool QtNetworkManager::setInterfaceConfiguration(const QString &interfaceName, const InterfaceConfiguration &config) {
    QString connectionPath;
    QString devicePath;

    try {
        devicePath = getDevicePath(interfaceName);
        connectionPath = findConnectionPathForInterface(interfaceName);
    } catch (const NetworkManagerDBusError &e) {
        qWarning() << "setInterfaceConfiguration: Could not find connection or device for interface" << interfaceName << ":" << e.what();
        throw; // Re-throw if we can't even find the connection/device
    }

    QScopedPointer<QDBusInterface> connSettingsInterface(createSettingsConnectionInterface(connectionPath));
    if (!connSettingsInterface || !connSettingsInterface->isValid()) {
        throw NetworkManagerDBusError("Failed to create D-Bus interface for connection settings " + connectionPath);
    }

    QDBusReply<QVariantMap> settingsReply = connSettingsInterface->call("GetSettings");
    if (!settingsReply.isValid()) {
        throw NetworkManagerDBusError("GetSettings call failed for " + connectionPath + ": " + settingsReply.error().message());
    }

    QVariantMap currentSettings = settingsReply.value();
    QVariantMap ipv4Settings; // Start with a fresh map for ipv4 settings

    // Preserve existing ipv6 settings if any
    if (currentSettings.contains("ipv6")) {
        ipv4Settings.insert("ipv6", currentSettings.value("ipv6"));
    }
    // Preserve other settings like "connection", "proxy", etc. by starting from currentSettings
    // and only modifying the "ipv4" part.
    // currentSettings will be used for Update()

    if (config.mode == InterfaceConfigurationMode::Manual) {
        ipv4Settings.insert("method", "manual");

        // address-data (aa{sv}) - primary modern format
        QList<QVariantMap> addressDataList;
        if (config.manualSettings.address.isValid()) {
            QVariantMap addressEntry;
            addressEntry.insert("address", config.manualSettings.address.address);
            addressEntry.insert("prefix", static_cast<quint32>(config.manualSettings.prefix.prefixLength));
            // NM's aa{sv} for address-data can also include "gateway", but it's usually separate in ipv4 setting map
            addressDataList.append(addressEntry);
        }
        ipv4Settings.insert("address-data", QVariant::fromValue(addressDataList));

        // addresses (aau) - older format
        if (config.manualSettings.address.isValid()) {
            bool conversionOk = false;
            QList<QVariant> aauAddressEntry = CppManualIpToAauVariant(config.manualSettings, conversionOk);
            if (conversionOk) {
                QVariantList aauAddressList; // This is a list containing one entry for NM's aau
                aauAddressList.append(QVariant::fromValue(aauAddressEntry));
                ipv4Settings.insert("addresses", QVariant::fromValue(aauAddressList));
            } else {
                qWarning() << "setInterfaceConfiguration: Failed to convert manual IP to AAU format.";
                // Decide if this is a fatal error for the operation
            }
        } else {
            ipv4Settings.insert("addresses", QVariant::fromValue(QVariantList())); // Empty list
        }

        if (config.manualSettings.gateway.isValid()) {
            ipv4Settings.insert("gateway", config.manualSettings.gateway.address);
        } else {
            ipv4Settings.remove("gateway"); // Or set to null/empty string if API requires
        }

        // DNS handling (simplified for now, only using 'dns' property with string IPs)
        QStringList dnsServers;
        for (const auto& dnsIp : config.manualSettings.dnsServers) {
            dnsServers.append(dnsIp.address);
        }
        if (!dnsServers.isEmpty()) {
            ipv4Settings.insert("dns", QVariant::fromValue(dnsServers));
            // For aa{sv} 'dns-data', one would convert IPs to QVariantMap with "address" key.
            // For aau 'dns', one would convert IPs to quint32.
        } else {
            ipv4Settings.remove("dns");
        }
        // TODO: Handle static routes from config.staticRoutes for both formats (aa{sv} and aau)

    } else if (config.mode == InterfaceConfigurationMode::DHCP) {
        ipv4Settings.insert("method", "auto");
        // Clear out manual/static properties
        ipv4Settings.remove("address-data");
        ipv4Settings.remove("addresses");
        ipv4Settings.remove("gateway");
        ipv4Settings.remove("dns"); // NM typically gets DNS from DHCP
        ipv4Settings.remove("route-data");
        ipv4Settings.remove("routes");
        // Other properties like 'dns-search', 'dns-options', 'dns-priority' might also need clearing.

    } else if (config.mode == InterfaceConfigurationMode::Disabled || config.mode == InterfaceConfigurationMode::LinkLocal) {
        // "disabled" means NM won't touch IPv4. "link-local" means only link-local addresses.
        ipv4Settings.insert("method", config.mode == InterfaceConfigurationMode::Disabled ? "disabled" : "link-local");
        ipv4Settings.remove("address-data");
        ipv4Settings.remove("addresses");
        ipv4Settings.remove("gateway");
        ipv4Settings.remove("dns");
        ipv4Settings.remove("route-data");
        ipv4Settings.remove("routes");
    }

    currentSettings["ipv4"] = QVariant::fromValue(ipv4Settings);

    QDBusMessage updateReply = connSettingsInterface->call("Update", currentSettings);
    if (updateReply.type() == QDBusMessage::ErrorMessage) {
        throw NetworkManagerDBusError("Update call failed for " + connectionPath + ": " + updateReply.errorMessage());
    }

    QScopedPointer<QDBusInterface> nmInterface(createNetworkManagerInterface());
    if (!nmInterface || !nmInterface->isValid()) {
         throw NetworkManagerDBusError(QString("Failed to create NetworkManager main interface for activating connection."));
    }
    QDBusMessage activateReply = nmInterface->call("ActivateConnection", QVariant::fromValue(QDBusObjectPath(connectionPath)), QVariant::fromValue(QDBusObjectPath(devicePath)), QVariant::fromValue(QDBusObjectPath("/")));
    if (activateReply.type() == QDBusMessage::ErrorMessage) {
        throw NetworkManagerDBusError("ActivateConnection call failed for " + connectionPath + " on device " + devicePath + ": " + activateReply.errorMessage());
    }

    return true;
}

bool QtNetworkManager::addStaticRoute(const QString &interfaceName, const StaticRoute &route) {
    QString connectionPath;
    try {
        connectionPath = findConnectionPathForInterface(interfaceName);
    } catch (const NetworkManagerDBusError &e) {
        qWarning() << "addStaticRoute: Could not find connection for interface" << interfaceName << ":" << e.what();
        throw; // Re-throw to allow test to catch specific error
    }

    QScopedPointer<QDBusInterface> connSettingsInterface(createSettingsConnectionInterface(connectionPath));
    if (!connSettingsInterface || !connSettingsInterface->isValid()) {
        throw NetworkManagerDBusError("Failed to create D-Bus interface for connection settings " + connectionPath + ": " +
                                      (connSettingsInterface ? connSettingsInterface->lastError().message() : "Interface creation failed"));
    }

    QDBusReply<QVariantMap> settingsReply = connSettingsInterface->call("GetSettings");
    if (!settingsReply.isValid()) {
        throw NetworkManagerDBusError("GetSettings call failed for " + connectionPath + ": " + settingsReply.error().message());
    }

    QVariantMap currentSettings = settingsReply.value();
    QVariantMap ipv4Settings;

    if (currentSettings.contains("ipv4")) {
        ipv4Settings = qvariant_cast<QVariantMap>(currentSettings.value("ipv4"));
    } else {
        ipv4Settings.insert("method", "auto");
    }

    QList<StaticRoute> currentCppRoutes;
    bool sourceIsAasv = false; // Flag to indicate if we read from route-data (aa{sv})

    if (ipv4Settings.contains("route-data")) {
        QList<QVariantMap> routesAasv = qvariant_cast<QList<QVariantMap>>(ipv4Settings.value("route-data"));
        if (!routesAasv.isEmpty()) { // Only parse if not empty, NM might send empty list
            sourceIsAasv = true;
            for (const QVariantMap &routeMap : routesAasv) {
                StaticRoute sr;
                sr.destination.address = routeMap.value("dest").toString();
                sr.prefix.prefixLength = routeMap.value("prefix").toUInt();
                sr.gateway.address = routeMap.value("next-hop").toString();
                sr.metric = routeMap.value("metric").toUInt();
                currentCppRoutes.append(sr);
            }
        }
    }

    if (!sourceIsAasv && ipv4Settings.contains("routes")) { // Fallback to 'routes' (aau) if 'route-data' wasn't used
        QVariantList routesAauOuter = qvariant_cast<QVariantList>(ipv4Settings.value("routes"));
        for (const QVariant &routeEntryVar : routesAauOuter) {
            if (routeEntryVar.canConvert<QVariantList>()) {
                QList<QVariant> routeEntryAau = routeEntryVar.toList();
                bool conversionOk = false;
                StaticRoute sr = AauVariantToCppRoute(routeEntryAau, conversionOk);
                if (conversionOk) {
                    currentCppRoutes.append(sr);
                } else {
                    qWarning() << "addStaticRoute: Skipping AAU route due to conversion error:" << routeEntryAau;
                }
            }
        }
    }

    // Check for duplicates in the C++ list
    for (const StaticRoute &existingRoute : currentCppRoutes) {
        if (existingRoute == route) { // Assumes StaticRoute has operator==
            qWarning() << "Static route already exists for" << interfaceName;
            return false; // Or true, if considered success
        }
    }

    // Add the new route to the C++ list
    currentCppRoutes.append(route);

    // --- Write back both formats ---
    // 1. Convert complete C++ list to aa{sv} format for "route-data"
    QList<QVariantMap> routesAasvOutput;
    for (const StaticRoute &sr : currentCppRoutes) {
        QVariantMap routeMap;
        routeMap.insert("dest", sr.destination.address);
        routeMap.insert("prefix", sr.prefix.prefixLength);
        if (sr.gateway.isValid() && !sr.gateway.address.isEmpty()) {
            routeMap.insert("next-hop", sr.gateway.address);
        }
        if (sr.metric > 0) { // Only add metric if it's non-default
            routeMap.insert("metric", sr.metric);
        }
        // NM D-Bus API for 'route-data' expects metric to be uint32.
        // If sr.metric is 0, it can be omitted or included as 0.
        // For consistency with NM internal representation, let's include it if > 0.
        // If it's 0, omitting it is fine as NM defaults unspecified metrics to values like 0 or system defaults.
        // However, explicitly setting 0 if sr.metric is 0 might also be valid.
        // Let's stick to: add metric if > 0.
        routesAasvOutput.append(routeMap);
    }
    ipv4Settings["route-data"] = QVariant::fromValue(routesAasvOutput);

    // 2. Convert complete C++ list to aau format for "routes"
    QVariantList routesAauOutput;
    for (const StaticRoute &sr : currentCppRoutes) {
        bool conversionOk = false;
        QList<QVariant> aauEntry = CppRouteToAauVariant(sr, conversionOk);
        if (conversionOk) {
            routesAauOutput.append(QVariant::fromValue(aauEntry));
        } else {
            qWarning() << "addStaticRoute: Failed to convert C++ route to AAU, skipping for 'routes' property:" << sr.destination.address;
            // Potentially throw an error here or decide how to handle partial failure
        }
    }
    ipv4Settings["routes"] = QVariant::fromValue(routesAauOutput);

    currentSettings["ipv4"] = QVariant::fromValue(ipv4Settings);

    QDBusMessage updateReply = connSettingsInterface->call("Update", currentSettings);
    if (updateReply.type() == QDBusMessage::ErrorMessage) {
        throw NetworkManagerDBusError("Update call failed for " + connectionPath + ": " + updateReply.errorMessage());
    }

    // After updating, re-apply the connection settings.
    // Some NM versions might require Deactivate then Activate, others just Activate.
    // For simplicity, let's try Activate. If the connection is already active, this might do nothing or re-evaluate.
    QScopedPointer<QDBusInterface> nmInterface(createNetworkManagerInterface());
    if (!nmInterface || !nmInterface->isValid()) {
         throw NetworkManagerDBusError(QString("Failed to create NetworkManager main interface for activating connection."));
    }

    // Find the device path again (or pass it around) to use in ActivateConnection
    QString devicePath;
    try {
        devicePath = getDevicePath(interfaceName);
    } catch (const NetworkManagerDBusError &e) {
        // This shouldn't happen if findConnectionPathForInterface succeeded, but as a safeguard:
        qWarning() << "Could not get device path for" << interfaceName << "when trying to activate connection:" << e.what();
        // The settings were updated, but activation might fail.
        // Depending on requirements, this might still be considered a partial success or a full failure.
        return false;
    }

    // ActivateConnection takes: service_name (not used here), connection_object_path, device_object_path, specific_object_path ("/")
    QDBusMessage activateReply = nmInterface->call("ActivateConnection", QVariant::fromValue(QDBusObjectPath(connectionPath)), QVariant::fromValue(QDBusObjectPath(devicePath)), QVariant::fromValue(QDBusObjectPath("/")));
    if (activateReply.type() == QDBusMessage::ErrorMessage) {
        // If activation fails, the settings are updated but not live.
        // This could be due to various reasons (e.g., invalid settings that passed Update but failed activation).
        throw NetworkManagerDBusError("ActivateConnection call failed for " + connectionPath + " on device " + devicePath + ": " + activateReply.errorMessage());
    }

    return true;
}

bool QtNetworkManager::removeStaticRoute(const QString &interfaceName, const StaticRoute &routeToRemove) {
    QString connectionPath;
    QString devicePath; // Needed for ActivateConnection later

    try {
        devicePath = getDevicePath(interfaceName);
        connectionPath = findConnectionPathForInterface(interfaceName);
    } catch (const NetworkManagerDBusError &e) {
        // If we can't even get device/connection path due to D-Bus error (e.g. service down), re-throw.
        // This allows the caller (test) to see that a fundamental D-Bus issue occurred.
        qWarning() << "removeStaticRoute: Failed to get device/connection path for" << interfaceName << ":" << e.what();
        throw;
    }

    QScopedPointer<QDBusInterface> connSettingsInterface(createSettingsConnectionInterface(connectionPath));
    if (!connSettingsInterface || !connSettingsInterface->isValid()) {
        throw NetworkManagerDBusError("Failed to create D-Bus interface for connection settings " + connectionPath + ": " +
                                      (connSettingsInterface ? connSettingsInterface->lastError().message() : "Interface creation failed"));
    }

    QDBusReply<QVariantMap> settingsReply = connSettingsInterface->call("GetSettings");
    if (!settingsReply.isValid()) {
        throw NetworkManagerDBusError("GetSettings call failed for " + connectionPath + ": " + settingsReply.error().message());
    }

    QVariantMap currentSettings = settingsReply.value();
    QVariantMap ipv4Settings;

    if (currentSettings.contains("ipv4")) {
        ipv4Settings = qvariant_cast<QVariantMap>(currentSettings.value("ipv4"));
    } else {
        return true; // No IPv4 settings, route cannot exist.
    }

    QList<StaticRoute> currentCppRoutes;
    bool sourceIsAasv = false;

    if (ipv4Settings.contains("route-data")) {
        QList<QVariantMap> routesAasv = qvariant_cast<QList<QVariantMap>>(ipv4Settings.value("route-data"));
        if(!routesAasv.isEmpty()){
            sourceIsAasv = true;
            for (const QVariantMap &routeMap : routesAasv) {
                StaticRoute sr;
                sr.destination.address = routeMap.value("dest").toString();
                sr.prefix.prefixLength = routeMap.value("prefix").toUInt();
                sr.gateway.address = routeMap.value("next-hop").toString();
                sr.metric = routeMap.value("metric").toUInt();
                currentCppRoutes.append(sr);
            }
        }
    }

    if (!sourceIsAasv && ipv4Settings.contains("routes")) { // Fallback if 'route-data' not used or was empty
        QVariantList routesAauOuter = qvariant_cast<QVariantList>(ipv4Settings.value("routes"));
        for (const QVariant &routeEntryVar : routesAauOuter) {
            if (routeEntryVar.canConvert<QVariantList>()) {
                QList<QVariant> routeEntryAau = routeEntryVar.toList();
                bool conversionOk = false;
                StaticRoute sr = AauVariantToCppRoute(routeEntryAau, conversionOk);
                if (conversionOk) {
                    currentCppRoutes.append(sr);
                } else {
                    qWarning() << "removeStaticRoute: Skipping AAU route due to conversion error:" << routeEntryAau;
                }
            }
        }
    }

    if (currentCppRoutes.isEmpty()) {
        return true; // No routes to remove.
    }

    bool routeActuallyRemoved = false;
    int initialRouteCount = currentCppRoutes.size();
    currentCppRoutes.removeAll(routeToRemove); // Uses StaticRoute::operator==
    routeActuallyRemoved = (currentCppRoutes.size() < initialRouteCount);

    if (!routeActuallyRemoved) {
        return true; // Route to remove was not found.
    }

    // --- Write back both formats ---
    // 1. Convert complete C++ list to aa{sv} format for "route-data"
    QList<QVariantMap> routesAasvOutput;
    for (const StaticRoute &sr : currentCppRoutes) {
        QVariantMap routeMap;
        routeMap.insert("dest", sr.destination.address);
        routeMap.insert("prefix", sr.prefix.prefixLength);
        if (sr.gateway.isValid() && !sr.gateway.address.isEmpty()) {
            routeMap.insert("next-hop", sr.gateway.address);
        }
        if (sr.metric > 0) {
            routeMap.insert("metric", sr.metric);
        }
        routesAasvOutput.append(routeMap);
    }
    ipv4Settings["route-data"] = QVariant::fromValue(routesAasvOutput);

    // 2. Convert complete C++ list to aau format for "routes"
    QVariantList routesAauOutput;
    for (const StaticRoute &sr : currentCppRoutes) {
        bool conversionOk = false;
        QList<QVariant> aauEntry = CppRouteToAauVariant(sr, conversionOk);
        if (conversionOk) {
            routesAauOutput.append(QVariant::fromValue(aauEntry));
        } else {
            qWarning() << "removeStaticRoute: Failed to convert C++ route to AAU, skipping for 'routes' property:" << sr.destination.address;
        }
    }
    ipv4Settings["routes"] = QVariant::fromValue(routesAauOutput);

    currentSettings["ipv4"] = QVariant::fromValue(ipv4Settings);

    QDBusMessage updateReply = connSettingsInterface->call("Update", currentSettings);
    if (updateReply.type() == QDBusMessage::ErrorMessage) {
        throw NetworkManagerDBusError("Update call failed for " + connectionPath + " after removing route: " + updateReply.errorMessage());
    }

    // Reactivate connection
    QScopedPointer<QDBusInterface> nmInterface(createNetworkManagerInterface());
    if (!nmInterface || !nmInterface->isValid()) {
         throw NetworkManagerDBusError(QString("Failed to create NetworkManager main interface for activating connection after removing route."));
    }

    QDBusMessage activateReply = nmInterface->call("ActivateConnection", QVariant::fromValue(QDBusObjectPath(connectionPath)), QVariant::fromValue(QDBusObjectPath(devicePath)), QVariant::fromValue(QDBusObjectPath("/")));
    if (activateReply.type() == QDBusMessage::ErrorMessage) {
        throw NetworkManagerDBusError("ActivateConnection call failed for " + connectionPath + " on device " + devicePath + " after removing route: " + activateReply.errorMessage());
    }

    return true;
}
