#define BOOST_TEST_MODULE QtNetworkManagerBoostTests
#include <boost/test/unit_test.hpp>

#include "network-utils/networkmanager/QtNetworkManager.h"
#include "MockNetworkManagerService.h"
#include "network-utils/types/dbus_types.h" // For NetworkUtils::registerDbusTypes()

#include <QCoreApplication> // Required for Qt event loop and D-Bus
#include <QDBusConnection>
#include <QTest> // For QSignalSpy, if used later for signal testing

// Test fixture for QtNetworkManager tests
struct NetworkManagerTestFixture {
    QDBusConnection sessionBus;
    QtNetworkManager* nm = nullptr;
    MockNetworkManagerService* mockService = nullptr;
    QString mockServiceDbusName = "org.freedesktop.NetworkManager"; // Use actual NM name on session bus for tests
    QString mockServicePath = "/org/freedesktop/NetworkManager";

    // Keep track of registered mock device object paths to unregister them
    QStringList registeredDeviceObjectPaths; // Renamed for clarity
    QStringList registeredIp4ConfigObjectPaths;


    NetworkManagerTestFixture() : sessionBus(QDBusConnection::sessionBus()) {
        // Ensure a QCoreApplication exists for D-Bus communication
        // Boost test might not create one.
        int argc = 0; // Dummy argc, argv
        char *argv[] = {nullptr};
        if (!QCoreApplication::instance()) {
            // Store and restore the original command line arguments
            // if they are ever needed by other parts of the application.
            // For now, just creating a dummy one.
            new QCoreApplication(argc, argv); // NOSONAR
             qDebug() << "Created dummy QCoreApplication for testing.";
        }


        NetworkUtils::registerDbusTypes(); // Register custom types

        // 1. Register the Mock Service Name
        if (!sessionBus.registerService(mockServiceDbusName)) {
            BOOST_FAIL("Could not register mock D-Bus service name: " << mockServiceDbusName.toStdString()
                      << " Error: " << sessionBus.lastError().message().toStdString());
            return;
        }
        qDebug() << "Mock D-Bus service name registered:" << mockServiceDbusName;

        // 2. Create and Register the Mock Service Object
        mockService = new MockNetworkManagerService();
        if (!sessionBus.registerObject(mockServicePath, mockService, QDBusConnection::ExportAllSlots | QDBusConnection::ExportAllProperties)) {
            BOOST_FAIL("Could not register mock NetworkManager service object at path " << mockServicePath.toStdString()
                      << " Error: " << sessionBus.lastError().message().toStdString());
            delete mockService; // Clean up
            mockService = nullptr;
            sessionBus.unregisterService(mockServiceDbusName); // Clean up service name
            return;
        }
        qDebug() << "Mock NetworkManager service object registered at path:" << mockServicePath;

        // 3. Instantiate QtNetworkManager with the session bus
        // The constructor of QtNetworkManager already takes QDBusConnection
        nm = new QtNetworkManager(sessionBus);

        // NM_SERVICE and NM_PATH constants in QtNetworkManager.cpp are global.
        // For testing with a mock on session bus using the *real* service name,
        // QtNetworkManager should just work provided it uses the QDBusConnection passed to it.
    }

    ~NetworkManagerTestFixture() {
        if (mockService) {
            // MockNetworkManagerService::clearDevices now handles unregistering device and ip4config objects
            // that were created *through it* and are its children.
            // However, the D-Bus registration is done by the fixture, so it should unregister.

            for(const QString& ip4Path : registeredIp4ConfigObjectPaths) {
                sessionBus.unregisterObject(ip4Path);
                 qDebug() << "Unregistered MockNMIp4Config from path:" << ip4Path;
            }
            registeredIp4ConfigObjectPaths.clear();

            for(const QString& devicePath : registeredDeviceObjectPaths) {
                sessionBus.unregisterObject(devicePath);
                qDebug() << "Unregistered MockNMDevice from path:" << devicePath;
            }
            registeredDeviceObjectPaths.clear();

            // clearDevices in mockService will delete the QObject children (MockNMDevice, MockNMIp4Config)
            // if they were parented to it.
            mockService->clearDevices(sessionBus);

            sessionBus.unregisterObject(mockServicePath);
            delete mockService;
            mockService = nullptr;
        }
        // Attempt to unregister service name. It's okay if it fails (e.g., if never registered or already gone).
        sessionBus.unregisterService(mockServiceDbusName);
        qDebug() << "Attempted to unregister mock D-Bus service name:" << mockServiceDbusName;

        delete nm;
        nm = nullptr;

        // Do not delete QCoreApplication::instance() here if it was created by this fixture,
        // as other tests might still need it or it might be managed elsewhere.
        // Typically, QCoreApplication lives for the duration of the test executable.
    }

    // Helper to add devices and their IP configs to the mock service
    void addMockDeviceWithIp4Config(
        const QString& devObjPath, const QString& ifaceName, const QString& hwAddr,
        quint32 state, quint32 speed,
        const QString& ip4ConfigObjPath,
        const QList<QVariantMap>& ip4Addresses, const QString& ip4Gw, const QList<QVariantMap>& ip4Dns
    ) {
        if (!mockService) {
            BOOST_FAIL("Mock service not initialized.");
            return;
        }

        // Add and register Ip4Config first
        if (!ip4ConfigObjPath.isEmpty()) {
            if (mockService->addIp4Config(ip4ConfigObjPath, ip4Addresses, ip4Gw, ip4Dns, sessionBus)) {
                registeredIp4ConfigObjectPaths.append(ip4ConfigObjPath);
            } else {
                BOOST_FAIL("Failed to add/register MockNMIp4Config at " + ip4ConfigObjPath.toStdString());
                return; // Don't proceed to add device if its config failed
            }
        }

        // Add and register Device
        // If ip4ConfigObjPath is empty, pass an empty QDBusObjectPath to MockNMDevice
        QDBusObjectPath ip4Path = ip4ConfigObjPath.isEmpty() ? QDBusObjectPath() : QDBusObjectPath(ip4ConfigObjPath);
        if (mockService->addDevice(devObjPath, ifaceName, hwAddr, state, speed, ip4Path, sessionBus)) {
            registeredDeviceObjectPaths.append(devObjPath);
        } else {
            BOOST_FAIL("Failed to add/register MockNMDevice " + ifaceName.toStdString() + " at " + devObjPath.toStdString());
            // If device add failed, we might have an orphaned ip4config registration.
            // Test fixture destructor will attempt cleanup.
        }
    }
};

BOOST_FIXTURE_TEST_SUITE(QtNetworkManagerTests, NetworkManagerTestFixture)

BOOST_AUTO_TEST_CASE(listInterfaceNames_Mocked) {
    BOOST_REQUIRE(nm != nullptr);
    BOOST_REQUIRE(mockService != nullptr);

    // Add mock devices
    addMockDeviceWithIp4Config("/org/freedesktop/NetworkManager/Devices/0", "mock-eth0", "00:11:22:33:44:55", 100, 1000, "/org/freedesktop/NetworkManager/IP4Config/0", {}, "", {});
    addMockDeviceWithIp4Config("/org/freedesktop/NetworkManager/Devices/1", "mock-lo", "00:00:00:00:00:00", 100, 0, "/org/freedesktop/NetworkManager/IP4Config/1", {}, "", {});
    addMockDeviceWithIp4Config("/org/freedesktop/NetworkManager/Devices/2", "mock-wlan0", "AA:BB:CC:DD:EE:FF", 100, 54, "/org/freedesktop/NetworkManager/IP4Config/2", {}, "", {});

    QStringList interfaceNames;
    BOOST_REQUIRE_NO_THROW(interfaceNames = nm->listInterfaceNames());

    BOOST_CHECK_EQUAL(interfaceNames.size(), 3);
    BOOST_CHECK(interfaceNames.contains("mock-eth0"));
    BOOST_CHECK(interfaceNames.contains("mock-lo"));
    BOOST_CHECK(interfaceNames.contains("mock-wlan0"));
}

BOOST_AUTO_TEST_CASE(getInterfaceDetails_Mocked) {
    BOOST_REQUIRE(nm != nullptr);
    BOOST_REQUIRE(mockService != nullptr);

    QString devPath = "/org/freedesktop/NetworkManager/Devices/3";
    QString ifaceName = "mock-eth1";
    QString hwAddr = "12:34:56:78:9A:BC";
    quint32 state = 100; // NM_DEVICE_STATE_ACTIVATED
    quint32 speed = 1000; // Mbps
    QString ip4ConfigPath = "/org/freedesktop/NetworkManager/IP4Config/3";

    QList<QVariantMap> addrDataList;
    QVariantMap addrEntry;
    addrEntry.insert("address", "192.168.1.10");
    addrEntry.insert("prefix", 24U);
    addrDataList.append(addrEntry);

    QString gateway = "192.168.1.1";

    QList<QVariantMap> dnsDataList;
    QVariantMap dnsEntry1, dnsEntry2;
    dnsEntry1.insert("address", "8.8.8.8");
    dnsEntry2.insert("address", "8.8.4.4");
    dnsDataList.append(dnsEntry1);
    dnsDataList.append(dnsEntry2);

    addMockDeviceWithIp4Config(devPath, ifaceName, hwAddr, state, speed, ip4ConfigPath, addrDataList, gateway, dnsDataList);

    InterfaceDetails details;
    BOOST_REQUIRE_NO_THROW(details = nm->getInterfaceDetails(ifaceName));

    BOOST_CHECK_EQUAL(details.name.toStdString(), ifaceName.toStdString());
    BOOST_CHECK_EQUAL(details.macAddress.toStdString(), hwAddr.toStdString());
    BOOST_CHECK_EQUAL(details.isUp, true); // Derived from state 100
    BOOST_CHECK_EQUAL(details.speed, speed);

    BOOST_CHECK_EQUAL(details.currentIpAddress.address.toStdString(), "192.168.1.10");
    BOOST_CHECK_EQUAL(details.currentPrefix.prefixLength, 24U);
    BOOST_CHECK_EQUAL(details.currentGateway.address.toStdString(), gateway.toStdString());

    BOOST_CHECK_EQUAL(details.currentDnsServers.size(), 2);
    if (details.currentDnsServers.size() == 2) {
        BOOST_CHECK(details.currentDnsServers.contains(IpAddress{"8.8.8.8"}));
        BOOST_CHECK(details.currentDnsServers.contains(IpAddress{"8.8.4.4"}));
    }
}


BOOST_AUTO_TEST_SUITE_END()
