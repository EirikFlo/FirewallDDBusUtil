#include <QCoreApplication>
#include <QDebug>

#include "network-utils/firewalld/qtfirewalldmanager.h" // Updated include path
#include "network-utils/types/dbus_types.h" // For D-Bus type registration
#include "network-utils/networkmanager/QtNetworkManager.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    NetworkUtils::registerDbusTypes(); // Register custom types

    QtFirewalldManager man;
    const auto zones = man.zoneNames();
    qDebug() << zones;

    QtNetworkManager nMan;
    const auto interfaces = nMan.listInterfaceNames();
    qDebug() << interfaces;

    auto test = nMan.getInterfaceDetails( "ens160" );
    qDebug() << test.currentIpAddress.toString() << "/" << test.currentPrefix.toString();

    return a.exec();
}
