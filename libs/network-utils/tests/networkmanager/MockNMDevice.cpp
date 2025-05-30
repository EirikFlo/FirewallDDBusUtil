#include "MockNMDevice.h"
#include <QDebug>

MockNMDevice::MockNMDevice(QString path, QString ifaceName, QString hwAddr, quint32 state, quint32 speed, QDBusObjectPath ip4ConfigPath, QObject* parent)
    : QObject(parent),
      m_path(path),
      m_interfaceName(ifaceName),
      m_hwAddress(hwAddr),
      m_state(state),
      m_speed(speed),
      m_ip4ConfigPath(ip4ConfigPath) {
    qDebug() << "MockNMDevice created:" << m_interfaceName << "at" << m_path;
}

MockNMDevice::~MockNMDevice() {
    qDebug() << "MockNMDevice destroyed:" << m_interfaceName << "at" << m_path;
}
