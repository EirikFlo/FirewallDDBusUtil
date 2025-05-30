#pragma once

#include <QObject>
#include <QStringList>
#include <QString>

// Forward declarations for types to be defined in separate headers
// This avoids circular dependencies if these types also need to know about INetworkManager (unlikely here)
// Or, include them directly if they are stable and self-contained.
// For now, direct includes will be used as these are data structures.

#include "network-utils/types/interface_details.h"       // To be created
#include "network-utils/types/interface_configuration.h" // To be created
#include "network-utils/types/static_route.h"            // To be created

class INetworkManager : public QObject {
    Q_OBJECT
public:
    ~INetworkManager() override = default;

    virtual QStringList listInterfaceNames() const = 0;
    virtual InterfaceDetails getInterfaceDetails(const QString &interfaceName) const = 0;
    virtual bool setInterfaceConfiguration(const QString &interfaceName, const InterfaceConfiguration &config) = 0;
    virtual bool addStaticRoute(const QString &interfaceName, const StaticRoute &route) = 0;
    virtual bool removeStaticRoute(const QString &interfaceName, const StaticRoute &route) = 0;
    // Add more methods as necessary based on exact DBus capabilities, e.g., for managing connections vs devices.

signals:
    void interfaceChanged(const QString &interfaceName); // Emitted when any detail of an interface changes.
                                                      // Consider a more detailed signal if needed:
                                                      // void interfacePropertiesChanged(const QString &interfaceName, const InterfaceDetails &newDetails);
};
