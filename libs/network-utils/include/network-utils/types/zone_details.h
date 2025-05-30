#pragma once
#include "network-utils/types/service.h"
#include "network-utils/types/port.h"
#include "network-utils/types/rich_rule.h"
#include "network-utils/types/icmp_block.h"
#include <QList> // Ensure QList is included

struct ZoneDetails {
    QList<Service> services;
    QList<Port> ports;
    QList<RichRule> richRules;
    QList<IcmpBlock> icmpBlocks;
};
