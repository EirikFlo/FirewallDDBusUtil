#pragma once

#include <QObject>
#include <QString>
#include <QList>
#include <QDBusObjectPath>
#include <QDBusConnection> // Required for registerObject
#include <QVariantMap>
// Only include headers for types actually used in this header's declarations directly
// For QMap members with pointers, forward declarations are sufficient.
// Full definitions will be in MockNetworkManagerService.cpp

// Forward declarations
class MockNMDevice;
class MockNMIp4Config;

// --- MockNetworkManagerService ---
class MockNetworkManagerService : public QObject {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.NetworkManager")

public:
    explicit MockNetworkManagerService(QObject* parent = nullptr) : QObject(parent) {}
    ~MockNetworkManagerService() override;

public slots: // Make GetDevices a public slot
    QList<QDBusObjectPath> GetDevices();

public:
    // Test setup method
    bool addDevice(const QString &objPath,
                   const QString &ifaceName,
                   const QString &hwAddr,
                   quint32 state,
                   quint32 speed,
                   const QDBusObjectPath &ip4ConfigObjPath, // Path for its IP4Config
                   QDBusConnection &busToRegisterOn);
    void clearDevices(QDBusConnection &busToUnregisterOn);

    // Method to add and register an IP4Config object
    bool addIp4Config(const QString &objPath, const QList<QVariantMap>& addresses, const QString& gw, const QList<QVariantMap>& dns, QDBusConnection &busToRegisterOn);


private:
    QMap<QString, MockNMDevice*> m_mockDevices; // Key: device object path
    QMap<QString, MockNMIp4Config*> m_mockIp4Configs; // Key: ip4config object path
    QList<QDBusObjectPath> m_devicePaths;
};
