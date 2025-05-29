#include "qtfirewalldmanager.h"
#include <QDebug>

static constexpr auto SERVICE_NAME = "org.fedoraproject.FirewallD1";
static constexpr auto CORE_PATH    = "/org/fedoraproject/FirewallD1";
static constexpr auto CORE_IFACE   = "org.fedoraproject.FirewallD1";
static constexpr auto ZONE_IFACE   = "org.fedoraproject.FirewallD1.zone";

QDBusInterface QtFirewalldManager::coreIface() const {
    return {SERVICE_NAME, CORE_PATH, CORE_IFACE, QDBusConnection::systemBus()};
}

QString QtFirewalldManager::objectPathForZone(const QString &zone) const {
    return QStringLiteral("%1/zones/%2").arg(CORE_PATH, zone);
}

QDBusInterface QtFirewalldManager::zoneIface(const QString &zone) const {
    return {SERVICE_NAME, objectPathForZone(zone), ZONE_IFACE, QDBusConnection::systemBus()};
}

QStringList QtFirewalldManager::zoneNames() {
    qDebug() << "Calling DBus method:" << coreIface().service() << coreIface().path() << coreIface().interface() << "getZones";
    auto reply = coreIface().call("getZones");
    if (reply.type() == QDBusMessage::ErrorMessage) {
        QString errorMsg = QString("DBus call getZones failed: %1").arg(reply.errorMessage());
        qWarning() << errorMsg;
        throw FirewalldDBusError(errorMsg);
    }
    qDebug() << "DBus call getZones successful.";
    return reply.arguments().at(0).value<QStringList>();
}

ZoneDetails QtFirewalldManager::zoneDetails(const QString &zone) {
    auto iface = zoneIface(zone);
    ZoneDetails details;

    // Read 'services' property
    QVariant servicesProperty = iface.property("services");
    if (servicesProperty.isValid()) {
        for (auto &svc : servicesProperty.toStringList())
            details.services.append(Service{svc});
    } else {
        // Log a warning if the property is invalid, but continue processing other properties.
        // The services list in ZoneDetails will remain empty.
        qWarning() << "Warning: Could not read 'services' property for zone" << zone;
    }

    // Read 'ports' property
    // Ports are represented as a list of lists/variants, e.g., [[port, protocol], [port, protocol]]
    QVariant portsProperty = iface.property("ports");
    if (portsProperty.isValid()) {
        for (auto entry : portsProperty.toList()) { // Each entry is a QVariant wrapping a QList<QVariant>
            auto lst = entry.toList(); // This should be [port_number_variant, protocol_string_variant]
            if (lst.count() == 2) { // Basic validation for [port, protocol] structure
                bool ok;
                quint16 portVal = lst.at(0).toUInt(&ok);
                if (ok) {
                    details.ports.append(Port{portVal, lst.at(1).toString()});
                } else {
                    qWarning() << "Warning: Invalid port number format for zone" << zone << ":" << lst.at(0);
                }
            } else {
                qWarning() << "Warning: Invalid port entry structure for zone" << zone << ":" << entry;
            }
        }
    } else {
        // Log a warning if the property is invalid. Ports list in ZoneDetails remains empty.
        qWarning() << "Warning: Could not read 'ports' property for zone" << zone;
    }

    // Read 'richRules' property
    // Firewalld versions might use 'richRules' or 'rules_str' (older).
    // Prefer 'richRules' if available and valid.
    QVariant richRulesProperty = iface.property("richRules");
    if (richRulesProperty.isValid() && !richRulesProperty.toStringList().isEmpty()) {
        qDebug() << "Using 'richRules' property for zone" << zone;
        for (auto &rr : richRulesProperty.toStringList())
            details.richRules.append(RichRule{rr});
    } else {
        // If 'richRules' is invalid or empty, try falling back to 'rules_str'.
        qWarning() << "Property 'richRules' is invalid or empty for zone" << zone << ". Trying 'rules_str'.";
        QVariant rulesStrProperty = iface.property("rules_str");
        if (rulesStrProperty.isValid()) {
            qDebug() << "Using 'rules_str' property for zone" << zone;
            for (auto &rr : rulesStrProperty.toStringList())
                details.richRules.append(RichRule{rr});
        } else {
            // If 'rules_str' is also invalid, log it. Rich rules list remains empty.
            qWarning() << "Property 'rules_str' is also invalid for zone" << zone;
        }
    }

    // Read 'icmpBlocks' property
    QVariant icmpBlocksProperty = iface.property("icmpBlocks");
    if (icmpBlocksProperty.isValid()) {
        for (auto &icmp : icmpBlocksProperty.toStringList()) {
            // Currently, only 'echo-request' (ping) is explicitly handled by IcmpBlock enum.
            if (icmp == QStringLiteral("echo-request"))
                details.icmpBlocks.append(IcmpBlock::EchoRequest);
            // Other ICMP block types could be added here if needed.
        }
    } else {
        // Log a warning if the property is invalid. ICMP blocks list remains empty.
        qWarning() << "Warning: Could not read 'icmpBlocks' property for zone" << zone;
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
