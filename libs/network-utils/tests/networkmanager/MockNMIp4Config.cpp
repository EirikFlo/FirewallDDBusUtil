#include "MockNMIp4Config.h"
#include <QDebug>
#include <QDBusArgument> // Added missing include

MockNMIp4Config::MockNMIp4Config(QString path,
                                 const QList<QVariantMap>& addresses,
                                 const QString& gw,
                                 const QList<QVariantMap>& dns,
                                 QObject* parent)
    : QObject(parent),
      m_path(path),
      m_addressData(addresses),
      m_gateway(gw),
      m_nameserverData(dns) {
    qDebug() << "MockNMIp4Config created at" << m_path;
}

MockNMIp4Config::~MockNMIp4Config() {
    qDebug() << "MockNMIp4Config destroyed at" << m_path;
}

QDBusVariant MockNMIp4Config::Get(const QString &interface_name, const QString &property_name) {
    Q_UNUSED(interface_name); // We assume the call is for our main interface if not "org.freedesktop.DBus.Properties"
    // qDebug() << "MockNMIp4Config::Get called for interface" << interface_name << "property" << property_name;

    if (property_name == "AddressData") {
        return QDBusVariant(QVariant::fromValue(m_addressData));
    } else if (property_name == "NameserverData") {
        return QDBusVariant(QVariant::fromValue(m_nameserverData));
    } else if (property_name == "Gateway") {
        return QDBusVariant(QVariant::fromValue(m_gateway));
    }
    qWarning() << "MockNMIp4Config::Get: Unknown property" << property_name << "for interface" << interface_name;
    return QDBusVariant(); // Invalid variant
}

void MockNMIp4Config::Set(const QString &interface_name, const QString &property_name, const QDBusVariant &value) {
    Q_UNUSED(interface_name);
    Q_UNUSED(value);
    qWarning() << "MockNMIp4Config::Set called for property" << property_name << "- Not implemented.";
    // In a more complex mock, you might handle property setting here.
}

QVariantMap MockNMIp4Config::GetAll(const QString &interface_name) {
    Q_UNUSED(interface_name);
    // qDebug() << "MockNMIp4Config::GetAll called for interface" << interface_name;
    QVariantMap properties; // This is QMap<QString, QVariant>

    properties.insert("AddressData", QVariant::fromValue(m_addressData));
    properties.insert("NameserverData", QVariant::fromValue(m_nameserverData));
    properties.insert("Gateway", QVariant::fromValue(m_gateway));

    // Add other Q_PROPERTY items if they were kept and need to be included in GetAll
    return properties;
}
