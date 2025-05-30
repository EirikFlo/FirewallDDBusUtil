#ifndef MOCK_FIREWALLD_SERVICE_H
#define MOCK_FIREWALLD_SERVICE_H

#include <QObject>
#include <QStringList>
#include <QDBusContext> // Required for Q_CLASSINFO("D-Bus Interface", ...)
#include <QVariantMap>
#include <QList>
#include <QPair> // For QList<QPair<...>>

#include "network-utils/types/port.h"    // For Port type
#include "network-utils/types/service.h" // For Service type
#include "network-utils/types/rich_rule.h"// For RichRule type

// Forward declaration for the zone mock object
class MockFirewallDZone : public QObject {
    Q_OBJECT
    // This Q_CLASSINFO is critical for QtDBus to know what interface this object implements.
    Q_CLASSINFO("D-Bus Interface", "org.fedoraproject.FirewallD1.zone")
    Q_PROPERTY(QStringList services READ services CONSTANT)
    Q_PROPERTY(QList<QVariant> ports READ ports CONSTANT) // Each QVariant is a QList<QVariant> of [port, protocol]
    Q_PROPERTY(QStringList richRules READ richRules CONSTANT)
    Q_PROPERTY(QStringList icmpBlocks READ icmpBlocks CONSTANT)
public:
    explicit MockFirewallDZone(const QString& zoneName, QObject *parent = nullptr);

public Q_SLOTS: // DBus methods
    QStringList services() const;
    QList<QVariant> ports() const;
    QStringList richRules() const;
    QStringList icmpBlocks() const;


private:
    QString m_zoneName;
    // Store mock data for this zone
    QStringList m_services_data;
    QList<QPair<quint16, QString>> m_ports_data; // Internal storage for ports
    QStringList m_richRules_data;
    QStringList m_icmpBlocks_data;
};


class MockFirewallDService : public QObject {
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.fedoraproject.FirewallD1")

public:
    explicit MockFirewallDService(QObject *parent = nullptr);
    ~MockFirewallDService() override;

    bool init(); // To register objects

public Q_SLOTS: // DBus methods
    QStringList getZones();
    // Add other org.fedoraproject.FirewallD1 methods here

private:
    MockFirewallDZone* m_mockPublicZone;
    // Store other mock data if necessary
};

#endif // MOCK_FIREWALLD_SERVICE_H
