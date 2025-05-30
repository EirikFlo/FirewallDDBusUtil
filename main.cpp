#include <QCoreApplication>
#include <QDebug>

#include "network-utils/firewalld/qtfirewalldmanager.h" // Updated include path
#include "network-utils/types/dbus_types.h" // For D-Bus type registration

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    NetworkUtils::registerDbusTypes(); // Register custom types

    QtFirewalldManager man;
    const auto zones = man.zoneNames();

    qDebug() << zones;

    return a.exec();
}
