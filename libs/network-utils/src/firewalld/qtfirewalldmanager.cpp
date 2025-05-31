#include "network-utils/types/dbus_types.h" // Ensure operator declarations are seen first
#include "network-utils/firewalld/qtfirewalldmanager.h" // Updated include path
#include <QDebug>

// Include new type headers
#include "network-utils/types/service.h"
#include "network-utils/types/port.h"
#include "network-utils/types/rich_rule.h"
#include "network-utils/types/icmp_block.h"
#include "network-utils/types/zone_details.h"

// Constructor implementation
QtFirewalldManager::QtFirewalldManager(QDBusConnection connection)
    : m_dbusConnection(connection) {}

static constexpr auto SERVICE_NAME = "org.fedoraproject.FirewallD1";
static constexpr auto CORE_PATH    = "/org/fedoraproject/FirewallD1";
static constexpr auto CORE_IFACE   = "org.fedoraproject.FirewallD1";
static constexpr auto ZONE_IFACE   = "org.fedoraproject.FirewallD1.zone";

QDBusInterface QtFirewalldManager::coreIface() const {
    // Use the member D-Bus connection
    return {SERVICE_NAME, CORE_PATH, CORE_IFACE, m_dbusConnection};
}

QString QtFirewalldManager::objectPathForZone(const QString &zone) const {
    // This helper method remains the same as it doesn't directly use the connection.
    return QStringLiteral("%1/zones/%2").arg(CORE_PATH, zone);
}

QDBusInterface QtFirewalldManager::zoneIface(const QString &zone) const {
    // Use the member D-Bus connection
    return {SERVICE_NAME, objectPathForZone(zone), ZONE_IFACE, m_dbusConnection};
}

QStringList QtFirewalldManager::zoneNames() {
    QDBusInterface zoneSpecificIface(SERVICE_NAME, CORE_PATH, ZONE_IFACE, m_dbusConnection);
    if (!zoneSpecificIface.isValid()) { // Check after attempting to use it
        throw FirewalldDBusError(QString("Failed to create D-Bus interface for getZones. Service running? Error: %1")
                                 .arg(zoneSpecificIface.lastError().message()));
    }
    qDebug() << "Calling DBus method:" << zoneSpecificIface.service() << zoneSpecificIface.path() << zoneSpecificIface.interface() << "getZones";
    auto reply = zoneSpecificIface.call("getZones");
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call getZones failed: %1. Interface error: %2").arg(reply.errorMessage()).arg(zoneSpecificIface.lastError().message());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call getZones successful.";
    return reply.arguments().at(0).value<QStringList>();
}

ZoneDetails QtFirewalldManager::zoneDetails(const QString &zone) {
    auto iface = zoneIface(zone);
    if (!iface.isValid()) { // This check is crucial
        throw FirewalldDBusError(QString("Failed to create D-Bus interface for zone '%1'. Service running? Zone exists? Error: %2").arg(zone).arg(iface.lastError().message()));
    }
    ZoneDetails details;

    // Read 'services' property
    QVariant servicesPropertyVariant = iface.property("services");
    if (servicesPropertyVariant.isValid() && servicesPropertyVariant.canConvert<QDBusArgument>()) {
        QDBusArgument servicesArg = servicesPropertyVariant.value<QDBusArgument>();
        servicesArg >> details.services; // Use custom operator>> for QList<Service>
    } else if (servicesPropertyVariant.isValid()) { // Fallback for real firewalld if types differ (e.g. QStringList)
        qWarning() << "Could not convert 'services' property as QDBusArgument for zone" << zone << ". Type is: " << servicesPropertyVariant.typeName() << ". Attempting manual parse from QStringList.";
        for (const QString &svcName : servicesPropertyVariant.toStringList())
            details.services.append(Service{svcName});
    } else {
        qWarning() << "Warning: Could not read 'services' property for zone" << zone << ". Error:" << iface.lastError().message();
    }

    // Read 'ports' property
    QVariant portsPropertyVariant = iface.property("ports");
    if (portsPropertyVariant.isValid() && portsPropertyVariant.canConvert<QDBusArgument>()) {
        QDBusArgument portsArg = portsPropertyVariant.value<QDBusArgument>();
        portsArg >> details.ports; // Use custom operator>> for QList<Port>
    } else if (portsPropertyVariant.isValid()) { // Fallback for real firewalld
        qWarning() << "Could not convert 'ports' property as QDBusArgument for zone" << zone << ". Type is: " << portsPropertyVariant.typeName() << ". Attempting manual parse from QList<QVariantList>.";
        for (const QVariant &entryVariant : portsPropertyVariant.toList()) {
            QList<QVariant> entryList = entryVariant.toList();
            if (entryList.count() == 2) {
                bool ok;
                quint16 portVal = entryList.at(0).toUInt(&ok);
                if (ok) {
                    details.ports.append(Port{portVal, entryList.at(1).toString()});
                } else {
                    qWarning() << "Warning: Invalid port number format in variant list for zone" << zone << ":" << entryList.at(0);
                }
            } else {
                qWarning() << "Warning: Invalid port entry structure in variant list for zone" << zone << ":" << entryVariant;
            }
        }
    } else {
        qWarning() << "Warning: Could not read 'ports' property for zone" << zone << ". Error:" << iface.lastError().message();
    }

    // Read 'richRules' property
    QVariant richRulesPropertyVariant = iface.property("richRules");
    if (richRulesPropertyVariant.isValid() && richRulesPropertyVariant.canConvert<QDBusArgument>()) {
        QDBusArgument richRulesArg = richRulesPropertyVariant.value<QDBusArgument>();
        richRulesArg >> details.richRules; // Use custom operator>> for QList<RichRule>
    } else if (richRulesPropertyVariant.isValid()) { // Fallback for real firewalld (likely QStringList)
         qWarning() << "Could not convert 'richRules' property as QDBusArgument for zone" << zone << ". Type is: " << richRulesPropertyVariant.typeName() << ". Attempting manual parse from QStringList.";
        for (const QString &ruleStr : richRulesPropertyVariant.toStringList())
            details.richRules.append(RichRule{ruleStr});
    } else {
         // If 'richRules' is invalid or empty, try falling back to 'rules_str' (older firewalld versions)
        qWarning() << "Could not read 'richRules' property for zone" << zone << ". Error:" << iface.lastError().message() << ". Trying 'rules_str'.";
        QVariant rulesStrPropertyVariant = iface.property("rules_str");
        if (rulesStrPropertyVariant.isValid() && rulesStrPropertyVariant.canConvert<QDBusArgument>()) {
             QDBusArgument richRulesArg = rulesStrPropertyVariant.value<QDBusArgument>();
             richRulesArg >> details.richRules;
        } else if (rulesStrPropertyVariant.isValid()) {
            qWarning() << "Could not convert 'rules_str' property as QDBusArgument for zone" << zone << ". Type is: " << rulesStrPropertyVariant.typeName() << ". Attempting manual parse from QStringList.";
            for (const QString &ruleStr : rulesStrPropertyVariant.toStringList())
                details.richRules.append(RichRule{ruleStr});
        } else {
            qWarning() << "Property 'rules_str' is also invalid or unreadable for zone" << zone << ". Error:" << iface.lastError().message();
        }
    }
    // Read 'icmpBlocks' property
    QVariant icmpBlocksProperty = iface.property("icmpBlocks");
    if (iface.lastError().type() != QDBusError::NoError && !icmpBlocksProperty.isValid()){ // Check if property read itself failed critically
         qWarning() << "Failed to read 'icmpBlocks' property for zone '" << zone << "'. Error: " << iface.lastError().message();
         // Depending on strictness, could throw here or allow partial data
    } else if (icmpBlocksProperty.isValid()) {
        for (auto &icmp : icmpBlocksProperty.toStringList()) {
            // Currently, only 'echo-request' (ping) is explicitly handled by IcmpBlock enum.
            if (icmp == QStringLiteral("echo-request"))
                details.icmpBlocks.append(IcmpBlock::EchoRequest);
            // Other ICMP block types could be added here if needed.
        }
    } else {
        // Log a warning if the property is invalid. ICMP blocks list remains empty.
        qWarning() << "Warning: Could not read 'icmpBlocks' property for zone" << zone << ". Error:" << iface.lastError().message();
    }

    return details;
}

void QtFirewalldManager::addService(const QString &zone, const Service &service) {
    qDebug() << "Calling DBus method:" << zoneIface(zone).service() << zoneIface(zone).path() << zoneIface(zone).interface() << "addService" << service.name;
    auto reply = zoneIface(zone).call("addService", service.name);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call addService failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call addService successful.";
}

void QtFirewalldManager::removeService(const QString &zone, const Service &service) {
    qDebug() << "Calling DBus method:" << zoneIface(zone).service() << zoneIface(zone).path() << zoneIface(zone).interface() << "removeService" << service.name;
    auto reply = zoneIface(zone).call("removeService", service.name);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call removeService failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call removeService successful.";
}

void QtFirewalldManager::addRichRule(const QString &zone, const RichRule &rule) {
    qDebug() << "Calling DBus method:" << zoneIface(zone).service() << zoneIface(zone).path() << zoneIface(zone).interface() << "addRichRule" << rule.rule;
    auto reply = zoneIface(zone).call("addRichRule", rule.rule);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call addRichRule failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call addRichRule successful.";
}

void QtFirewalldManager::removeRichRule(const QString &zone, const RichRule &rule) {
    qDebug() << "Calling DBus method:" << zoneIface(zone).service() << zoneIface(zone).path() << zoneIface(zone).interface() << "removeRichRule" << rule.rule;
    auto reply = zoneIface(zone).call("removeRichRule", rule.rule);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call removeRichRule failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call removeRichRule successful.";
}

void QtFirewalldManager::addPort(const QString &zone, const Port &port) {
    qDebug() << "Calling DBus method:" << zoneIface(zone).service() << zoneIface(zone).path() << zoneIface(zone).interface() << "addPort" << port.port << port.protocol;
    auto reply = zoneIface(zone).call("addPort", port.port, port.protocol);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call addPort failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call addPort successful.";
}

void QtFirewalldManager::removePort(const QString &zone, const Port &port) {
    qDebug() << "Calling DBus method:" << zoneIface(zone).service() << zoneIface(zone).path() << zoneIface(zone).interface() << "removePort" << port.port << port.protocol;
    auto reply = zoneIface(zone).call("removePort", port.port, port.protocol);
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call removePort failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call removePort successful.";
}

void QtFirewalldManager::enablePing(const QString &zone) {
    qDebug() << "Calling DBus method:" << zoneIface(zone).service() << zoneIface(zone).path() << zoneIface(zone).interface() << "removeICMPBlock" << toString(IcmpBlock::EchoRequest);
    auto reply = zoneIface(zone).call("removeICMPBlock", toString(IcmpBlock::EchoRequest));
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call removeICMPBlock failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call removeICMPBlock successful.";
}

void QtFirewalldManager::disablePing(const QString &zone) {
    qDebug() << "Calling DBus method:" << zoneIface(zone).service() << zoneIface(zone).path() << zoneIface(zone).interface() << "addICMPBlock" << toString(IcmpBlock::EchoRequest);
    auto reply = zoneIface(zone).call("addICMPBlock", toString(IcmpBlock::EchoRequest));
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call addICMPBlock failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call addICMPBlock successful.";
}
