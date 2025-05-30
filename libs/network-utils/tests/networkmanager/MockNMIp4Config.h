#pragma once

#include <QObject>
#include <QString>
#include <QList>
#include <QVariantMap>
#include <QDBusObjectPath> // Not strictly needed here but often related

class MockNMIp4Config : public QObject {
    Q_OBJECT
    // Primary D-Bus interface for its properties
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.NetworkManager.IP4Config")
    // Also needs to respond to org.freedesktop.DBus.Properties

    // Remove Q_PROPERTY for complex types if direct exposure is problematic
    // Q_PROPERTY(QList<QVariantMap> AddressData READ addressData CONSTANT)
    Q_PROPERTY(QString Gateway READ gateway CONSTANT) // Simple property can stay
    // Q_PROPERTY(QList<QVariantMap> NameserverData READ nameserverData CONSTANT)

public:
    MockNMIp4Config(QString path,
                    const QList<QVariantMap>& addresses,
                    const QString& gw,
                    const QList<QVariantMap>& dns,
                    QObject* parent = nullptr);
    ~MockNMIp4Config() override;

    QString path() const { return m_path; }
    // C++ getters remain
    QList<QVariantMap> addressData() const { return m_addressData; }
    QString gateway() const { return m_gateway; } // Q_PROPERTY uses this
    QList<QVariantMap> nameserverData() const { return m_nameserverData; }

public slots:
    // Slot for org.freedesktop.DBus.Properties.Get
    QDBusVariant Get(const QString &interface_name, const QString &property_name);
    // Implement Set and GetAll if needed for more complex tests (returning empty for now)
    void Set(const QString &interface_name, const QString &property_name, const QDBusVariant &value);
    QVariantMap GetAll(const QString &interface_name); // Standard D-Bus Properties.GetAll returns a{sv} -> QMap<QString, QVariant>


private:
    QString m_path;
    QList<QVariantMap> m_addressData;
    QString m_gateway;
    QList<QVariantMap> m_nameserverData;
};
