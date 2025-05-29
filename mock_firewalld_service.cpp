#include "mock_firewalld_service.h"
#include <QDBusConnection>
#include <QDebug>
#include <QVariant> // Required for QVariant::fromValue

// --- MockFirewallDZone Implementation ---
MockFirewallDZone::MockFirewallDZone(const QString& zoneName, QObject *parent)
    : QObject(parent), m_zoneName(zoneName) {
    qDebug() << "MockFirewallDZone constructor for zone:" << zoneName;
    // Predefined data for the mock zone
    if (m_zoneName == "mockPublic") {
        m_services_data << "http" << "ssh";
        m_ports_data.append({8080, "tcp"});
        m_ports_data.append({53, "udp"});
        m_richRules_data.append("rule family='ipv4' source address='1.2.3.4' accept");
        // m_icmpBlocks_data; // Initially empty, can be modified by mock add/remove icmp block methods later
    } else if (m_zoneName == "mockWork") {
        m_services_data << "ssh" << "samba-client";
        // No ports, rules, or icmp blocks for this zone by default
    }
}

// Slots that mimic readable properties
QStringList MockFirewallDZone::services() {
    qDebug() << "MockFirewallDZone (" << m_zoneName << ")::services() called. Returning:" << m_services_data;
    return m_services_data;
}

QList<QList<QVariant>> MockFirewallDZone::ports() {
    qDebug() << "MockFirewallDZone (" << m_zoneName << ")::ports() called. Returning:" << m_ports_data.size() << "ports.";
    QList<QList<QVariant>> qvariantPorts;
    for(const auto& portPair : m_ports_data) {
        QList<QVariant> p;
        p << QVariant(portPair.first) << QVariant(portPair.second);
        qvariantPorts.append(p);
    }
    return qvariantPorts;
}

QStringList MockFirewallDZone::richRules() {
    qDebug() << "MockFirewallDZone (" << m_zoneName << ")::richRules() called. Returning:" << m_richRules_data;
    return m_richRules_data;
}

QStringList MockFirewallDZone::icmpBlocks() {
    qDebug() << "MockFirewallDZone (" << m_zoneName << ")::icmpBlocks() called. Returning:" << m_icmpBlocks_data;
    return m_icmpBlocks_data;
}


// --- MockFirewallDService Implementation ---
MockFirewallDService::MockFirewallDService(QObject *parent) 
    : QObject(parent), m_mockPublicZone(nullptr) {
    qDebug() << "MockFirewallDService constructor";
}

bool MockFirewallDService::init() {
    qDebug() << "MockFirewallDService::init() called";
    // Create and register the mock zone object
    // Path for zones is typically /org/fedoraproject/FirewallD1/zones/<zone_name>
    // This matches how QtFirewalldManager constructs zone paths.
    
    // Note: The object path here MUST match what QtFirewalldManager constructs.
    // QtFirewalldManager::objectPathForZone uses CORE_PATH which is "/org/fedoraproject/FirewallD1"
    m_mockPublicZone = new MockFirewallDZone("mockPublic", this);
    if (!QDBusConnection::sessionBus().registerObject("/org/fedoraproject/FirewallD1/zones/mockPublic", m_mockPublicZone, QDBusConnection::ExportAllSlots)) {
        qWarning() << "Failed to register mockPublicZone object:" << QDBusConnection::sessionBus().lastError().message();
        return false;
    }
    qDebug() << "MockFirewallDZone 'mockPublic' registered on session bus at /org/fedoraproject/FirewallD1/zones/mockPublic";

    // Example for a second zone, if needed by getZones()
    MockFirewallDZone* mockWorkZone = new MockFirewallDZone("mockWork", this);
     if (!QDBusConnection::sessionBus().registerObject("/org/fedoraproject/FirewallD1/zones/mockWork", mockWorkZone, QDBusConnection::ExportAllSlots)) {
        qWarning() << "Failed to register mockWorkZone object:" << QDBusConnection::sessionBus().lastError().message();
        // continue, not fatal for all tests
    } else {
        qDebug() << "MockFirewallDZone 'mockWork' registered on session bus at /org/fedoraproject/FirewallD1/zones/mockWork";
    }

    return true;
}

MockFirewallDService::~MockFirewallDService() {
    qDebug() << "MockFirewallDService destructor";
    // Unregister objects if necessary.
    // QDBusConnection::sessionBus().unregisterObject("/org/fedoraproject/FirewallD1/zones/mockPublic");
    // QDBusConnection::sessionBus().unregisterObject("/org/fedoraproject/FirewallD1/zones/mockWork");
    // Child QObjects (m_mockPublicZone, mockWorkZone) should be deleted by QObject parent/child relationship.
}

QStringList MockFirewallDService::getZones() {
    qDebug() << "MockFirewallDService D-Bus method getZones() called";
    return QStringList() << "mockPublic" << "mockWork"; // Return a predefined list
}

// Implement other org.fedoraproject.FirewallD1 methods if needed by tests
// For example, to make addService work with the mock:
// void addService(const QString& zone, const QString& service) { ... }
// However, these would typically be on the zone interface, not the core.
// The core interface has methods like addZone, removeZone, etc.
// For methods like addService on a zone, they'd be slots in MockFirewallDZone.
// e.g. MockFirewallDZone::addService(const QString& serviceName, int timeout)
// The actual firewalld addService is on org.fedoraproject.FirewallD1.zone
// void addService(in s service, in u timeout)
// So slots for these would go into MockFirewallDZone.
// For this PoC, we are focusing on read-only operations for getZones and zoneDetails.
