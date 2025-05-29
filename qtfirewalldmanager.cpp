#include "qtfirewalldmanager.h"

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
    auto reply = coreIface().call("getZones");
    if (reply.type() == QDBusMessage::ErrorMessage)
        throw std::runtime_error(reply.errorMessage().toStdString());
    return reply.arguments().at(0).value<QStringList>();
}

ZoneDetails QtFirewalldManager::zoneDetails(const QString &zone) {
    auto iface = zoneIface(zone);
    ZoneDetails details;

    for (auto &svc : iface.property("services").toStringList())
        details.services.append(Service{svc});

    for (auto entry : iface.property("ports").toList()) {
        auto lst = entry.toList();
        details.ports.append(Port{quint16(lst.at(0).toUInt()), lst.at(1).toString()});
    }

    for (auto &rr : iface.property("richRules").toStringList())
        details.richRules.append(RichRule{rr});

    for (auto &icmp : iface.property("icmpBlocks").toStringList()) {
        if (icmp == QStringLiteral("echo-request"))
            details.icmpBlocks.append(IcmpBlock::EchoRequest);
    }

    return details;
}

void QtFirewalldManager::addService(const QString &zone, const Service &service) {
    zoneIface(zone).call("addService", service.name);
}

void QtFirewalldManager::removeService(const QString &zone, const Service &service) {
    zoneIface(zone).call("removeService", service.name);
}

void QtFirewalldManager::addRichRule(const QString &zone, const RichRule &rule) {
    zoneIface(zone).call("addRichRule", rule.rule);
}

void QtFirewalldManager::removeRichRule(const QString &zone, const RichRule &rule) {
    zoneIface(zone).call("removeRichRule", rule.rule);
}

void QtFirewalldManager::addPort(const QString &zone, const Port &port) {
    zoneIface(zone).call("addPort", port.port, port.protocol);
}

void QtFirewalldManager::removePort(const QString &zone, const Port &port) {
    zoneIface(zone).call("removePort", port.port, port.protocol);
}

void QtFirewalldManager::enablePing(const QString &zone) {
    zoneIface(zone).call("removeICMPBlock", toString(IcmpBlock::EchoRequest));
}

void QtFirewalldManager::disablePing(const QString &zone) {
    zoneIface(zone).call("addICMPBlock", toString(IcmpBlock::EchoRequest));
}
