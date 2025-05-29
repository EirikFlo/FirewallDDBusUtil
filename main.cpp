#include <QCoreApplication>
#include <QDebug>

#include "qtfirewalldmanager.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    QtFirewalldManager man;
    const auto zones = man.zoneNames();

    qDebug() << zones;

    return a.exec();
}
