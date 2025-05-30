#pragma once

#include <QString>
#include <QStringList>
#include <QList>
// Removed <compare> as it's now in individual type headers

// --- Domain Types ---
#include "network-utils/types/service.h"
#include "network-utils/types/port.h"
#include "network-utils/types/rich_rule.h"
#include "network-utils/types/icmp_block.h"
#include "network-utils/types/zone_details.h"

// --- Interface ---

class IFirewalldManager {
public:
    virtual ~IFirewalldManager() = default;

    // List all zone names
    virtual QStringList zoneNames() = 0;

    // Detailed information about a zone
    virtual ZoneDetails zoneDetails(const QString &zone) = 0;

    // Services
    virtual void addService(const QString &zone, const Service &service) = 0;
    virtual void removeService(const QString &zone, const Service &service) = 0;

    // Rich rules
    virtual void addRichRule(const QString &zone, const RichRule &rule) = 0;
    virtual void removeRichRule(const QString &zone, const RichRule &rule) = 0;

    // Ports
    virtual void addPort(const QString &zone, const Port &port) = 0;
    virtual void removePort(const QString &zone, const Port &port) = 0;

    // ICMP ping
    virtual void enablePing(const QString &zone) = 0;
    virtual void disablePing(const QString &zone) = 0;
};
