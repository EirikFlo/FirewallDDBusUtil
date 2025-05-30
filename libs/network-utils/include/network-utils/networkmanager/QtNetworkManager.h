#pragma once

#include "network-utils/networkmanager/INetworkManager.h"
#include "network-utils/types/interface_details.h"
#include "network-utils/types/interface_configuration.h"
#include "network-utils/types/static_route.h"

#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QVariantMap>
#include <QStringList>
#include <QDBusObjectPath> // Added for QDBusObjectPath usage
#include <stdexcept> // For runtime_error

// Define NM_DEVICE_STATE constants if not available from system headers
// These values are standard for NetworkManager's DeviceState enum.
// See: https://developer-old.gnome.org/NetworkManager/stable/nm-dbus-types.html#NMDeviceState
#ifndef NM_DEVICE_STATE_UNKNOWN
#define NM_DEVICE_STATE_UNKNOWN 0
#endif
#ifndef NM_DEVICE_STATE_UNMANAGED
#define NM_DEVICE_STATE_UNMANAGED 10
#endif
#ifndef NM_DEVICE_STATE_UNAVAILABLE
#define NM_DEVICE_STATE_UNAVAILABLE 20
#endif
#ifndef NM_DEVICE_STATE_DISCONNECTED
#define NM_DEVICE_STATE_DISCONNECTED 30
#endif
#ifndef NM_DEVICE_STATE_PREPARE
#define NM_DEVICE_STATE_PREPARE 40
#endif
#ifndef NM_DEVICE_STATE_CONFIG
#define NM_DEVICE_STATE_CONFIG 50
#endif
#ifndef NM_DEVICE_STATE_NEED_AUTH
#define NM_DEVICE_STATE_NEED_AUTH 60
#endif
#ifndef NM_DEVICE_STATE_IP_CONFIG
#define NM_DEVICE_STATE_IP_CONFIG 70
#endif
#ifndef NM_DEVICE_STATE_IP_CHECK
#define NM_DEVICE_STATE_IP_CHECK 80
#endif
#ifndef NM_DEVICE_STATE_SECONDARIES
#define NM_DEVICE_STATE_SECONDARIES 90
#endif
#ifndef NM_DEVICE_STATE_ACTIVATED
#define NM_DEVICE_STATE_ACTIVATED 100
#endif
#ifndef NM_DEVICE_STATE_DEACTIVATING
#define NM_DEVICE_STATE_DEACTIVATING 110
#endif
#ifndef NM_DEVICE_STATE_FAILED
#define NM_DEVICE_STATE_FAILED 120
#endif


class QtNetworkManager : public INetworkManager {
    Q_OBJECT
public:
    class NetworkManagerDBusError : public std::runtime_error {
    public:
        NetworkManagerDBusError(const QString &message)
            : std::runtime_error(message.toStdString()) {}
        NetworkManagerDBusError(const std::string &message)
            : std::runtime_error(message) {}
    };

    explicit QtNetworkManager(QDBusConnection connection = QDBusConnection::systemBus());
    ~QtNetworkManager() override = default;

    QStringList listInterfaceNames() const override;
    InterfaceDetails getInterfaceDetails(const QString &interfaceName) const override;

    bool setInterfaceConfiguration(const QString &interfaceName, const InterfaceConfiguration &config) override;
    bool addStaticRoute(const QString &interfaceName, const StaticRoute &route) override;
    bool removeStaticRoute(const QString &interfaceName, const StaticRoute &route) override;

private:
    QDBusConnection m_dbusConnection;
    QDBusInterface* m_nmDbusInterface = nullptr; // For global NM signals like DeviceAdded/Removed

    // Trackers for device-specific signal connections
    QMap<QString, QDBusInterface*> m_trackedDeviceInterfaces;       // Key: Device Object Path
    QMap<QString, QDBusInterface*> m_trackedIp4ConfigInterfaces;  // Key: IP4Config Object Path
    QMap<QString, QString> m_devicePathToNameMap;                 // Key: Device Object Path, Value: Interface Name
    QMap<QString, QString> m_ip4ConfigPathToDevicePathMap;        // Key: IP4Config Object Path, Value: Device Object Path


    QString getDevicePath(const QString &interfaceName) const;
    QString getInterfaceNameFromDevicePath(const QString &devicePath) const; // Helper
    QString findConnectionPathForInterface(const QString &interfaceName) const;
    QVariantMap convertManualIpConfigurationToDBus(const ManualIpConfiguration &manualConfig) const;

    void subscribeToSignalsForInterface(const QString &interfaceName);
    void subscribeToDeviceSignals(const QString &devicePath, const QString &interfaceName);
    void subscribeToIp4ConfigSignals(const QString &ip4ConfigPath, const QString &associatedInterfaceName);
    void cleanupDeviceSubscriptions(const QString &devicePath);


private slots:
    // Slots for global NetworkManager signals
    void onDeviceAdded(const QDBusObjectPath &devicePath);
    void onDeviceRemoved(const QDBusObjectPath &devicePath);

    // Slots for device specific signals
    void onDeviceStateChanged(uint newState, uint oldState, uint reason);
    // Slot for org.freedesktop.DBus.Properties.PropertiesChanged on a Device object
    void onDeviceDBusPropertiesChanged(const QString &dbusInterfaceName, const QVariantMap &changedProperties, const QStringList &invalidatedProperties);

    // Handler for IP4Config PropertiesChanged (connected via SLOT)
    // Signature matches org.freedesktop.DBus.Properties.PropertiesChanged
    void onIp4ConfigPropertiesChanged(const QString &dbusInterfaceName, const QVariantMap &changedProperties, const QStringList &invalidatedProperties);


    // Helpers to create QDBusInterface, ensuring parent is null for const methods if needed
    QDBusInterface* createNetworkManagerInterface() const;
    QDBusInterface* createDeviceInterface(const QString& devicePath) const;
    QDBusInterface* createIp4ConfigInterface(const QString& ip4ConfigPath) const;
    QDBusInterface* createIp6ConfigInterface(const QString& ip6ConfigPath) const; // For future use
    QDBusInterface* createSettingsInterface() const; // Helper for NM Settings
    QDBusInterface* createSettingsConnectionInterface(const QString& connectionPath) const; // Helper for NM Connection Settings
};
