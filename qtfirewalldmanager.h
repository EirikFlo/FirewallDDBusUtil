#pragma once
#include "ifirewalldmanager.h"
#include <QDBusInterface>
#include <QDBusReply>
#include <QVariant>
#include <QDBusConnection>

class QtFirewalldManager : public IFirewalldManager {
public:
    QtFirewalldManager() = default;
    ~QtFirewalldManager() override = default;

    QStringList zoneNames() override;
    ZoneDetails zoneDetails(const QString &zone) override;

    void addService(const QString &zone, const Service &service) override;
    void removeService(const QString &zone, const Service &service) override;

    void addRichRule(const QString &zone, const RichRule &rule) override;
    void removeRichRule(const QString &zone, const RichRule &rule) override;

    void addPort(const QString &zone, const Port &port) override;
    void removePort(const QString &zone, const Port &port) override;

    void enablePing(const QString &zone) override;
    void disablePing(const QString &zone) override;

private:
    QDBusInterface coreIface() const;
    QDBusInterface zoneIface(const QString &zone) const;
    QString objectPathForZone(const QString &zone) const;
};
