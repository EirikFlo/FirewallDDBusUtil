#include "MockNetworkManagerService.h"
#include "MockNMDevice.h"    // Added include
#include "MockNMIp4Config.h" // Added include
#include <QDebug>
#include <QDBusError> // Added for QDBusConnection::lastError()

// --- MockNetworkManagerService Implementation ---

MockNetworkManagerService::~MockNetworkManagerService() {
    // Assuming clearDevices (or similar) is called by the test fixture for proper D-Bus unregistration.
    // This destructor will clean up any remaining QObject children.
    qDeleteAll(m_mockDevices.values()); // MockNMDevice are children
    m_mockDevices.clear();
    qDeleteAll(m_mockIp4Configs.values()); // MockNMIp4Config are children
    m_mockIp4Configs.clear();
    m_devicePaths.clear();
}

QList<QDBusObjectPath> MockNetworkManagerService::GetDevices() {
    qDebug() << "MockNetworkManagerService::GetDevices called, returning" << m_devicePaths.size() << "devices.";
    return m_devicePaths;
}

bool MockNetworkManagerService::addDevice(const QString &objPath,
                                      const QString &ifaceName,
                                      const QString &hwAddr,
                                      quint32 state,
                                      quint32 speed,
                                      const QDBusObjectPath &ip4ConfigObjPath,
                                      QDBusConnection &busToRegisterOn) {
    if (m_mockDevices.contains(objPath)) {
        qWarning() << "Mock device with path" << objPath << "already exists.";
        return false;
    }

    MockNMDevice* device = new MockNMDevice(objPath, ifaceName, hwAddr, state, speed, ip4ConfigObjPath, this);

    // Register the MockNMDevice object on the D-Bus
    // This makes its D-Bus properties (like 'Interface') queryable.
    if (!busToRegisterOn.registerObject(objPath, device, QDBusConnection::ExportAllProperties)) {
        qWarning() << "Failed to register MockNMDevice object at path" << objPath << "on D-Bus:" << busToRegisterOn.lastError().message();
        delete device; // Clean up if registration failed
        return false;
    }

    m_mockDevices.insert(objPath, device);
    m_devicePaths.append(QDBusObjectPath(objPath));
    qDebug() << "MockNetworkManagerService: Added and registered device" << ifaceName << "at" << objPath;
    return true;
}

bool MockNetworkManagerService::addIp4Config(const QString &objPath,
                                           const QList<QVariantMap>& addresses,
                                           const QString& gw,
                                           const QList<QVariantMap>& dns,
                                           QDBusConnection &busToRegisterOn) {
    if (m_mockIp4Configs.contains(objPath)) {
        qWarning() << "Mock IP4Config with path" << objPath << "already exists.";
        return false;
    }

    MockNMIp4Config* ip4Config = new MockNMIp4Config(objPath, addresses, gw, dns, this); // Parent to service

    // ExportAllSlots will make Get, Set, GetAll available. ExportAllProperties for any remaining Q_PROPERTY (like Gateway).
    // For this manual implementation of Properties, ExportAllSlots is key for Get/Set/GetAll.
    // If Gateway Q_PROPERTY is to be kept, use ExportAllSlots | ExportAllProperties.
    // Since Get now handles Gateway, ExportAllSlots should be enough.
    if (!busToRegisterOn.registerObject(objPath, ip4Config, QDBusConnection::ExportAllSlots /* | QDBusConnection::ExportAllProperties */ )) {
        qWarning() << "Failed to register MockNMIp4Config object at path" << objPath << "on D-Bus:" << busToRegisterOn.lastError().message();
        delete ip4Config;
        return false;
    }
    m_mockIp4Configs.insert(objPath, ip4Config);
    qDebug() << "MockNetworkManagerService: Added and registered IP4Config at" << objPath;
    return true;
}


void MockNetworkManagerService::clearDevices(QDBusConnection &busToUnregisterOn) {
    for (MockNMDevice* device : m_mockDevices.values()) {
        busToUnregisterOn.unregisterObject(device->path());
    }
    qDeleteAll(m_mockDevices.values());
    m_mockDevices.clear();
    m_devicePaths.clear();

    for (MockNMIp4Config* ip4config : m_mockIp4Configs.values()) {
        busToUnregisterOn.unregisterObject(ip4config->path());
    }
    qDeleteAll(m_mockIp4Configs.values());
    m_mockIp4Configs.clear();

    qDebug() << "MockNetworkManagerService: All mock devices and IP4Configs cleared and unregistered.";
}
