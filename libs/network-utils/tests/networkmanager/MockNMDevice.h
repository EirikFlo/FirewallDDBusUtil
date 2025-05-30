#pragma once

#include <QObject>
#include <QString>
#include <QDBusObjectPath>
#include <QVariantMap> // For Q_PROPERTY to work with QDBusObjectPath

class MockNMDevice : public QObject {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.freedesktop.NetworkManager.Device")

    Q_PROPERTY(QString Interface READ interfaceName CONSTANT)
    Q_PROPERTY(QString HwAddress READ hwAddress CONSTANT)
    Q_PROPERTY(quint32 State READ state CONSTANT)
    Q_PROPERTY(quint32 Speed READ speed CONSTANT)
    Q_PROPERTY(QDBusObjectPath Ip4Config READ ip4ConfigPath CONSTANT)

public:
    MockNMDevice(QString path, QString ifaceName, QString hwAddr, quint32 state, quint32 speed, QDBusObjectPath ip4ConfigPath, QObject* parent = nullptr);
    ~MockNMDevice() override;

    QString interfaceName() const { return m_interfaceName; }
    QString path() const { return m_path; }
    QString hwAddress() const { return m_hwAddress; }
    quint32 state() const { return m_state; }
    quint32 speed() const { return m_speed; }
    QDBusObjectPath ip4ConfigPath() const { return m_ip4ConfigPath; }

private:
    QString m_path;
    QString m_interfaceName;
    QString m_hwAddress;
    quint32 m_state;
    quint32 m_speed;
    QDBusObjectPath m_ip4ConfigPath;
};
