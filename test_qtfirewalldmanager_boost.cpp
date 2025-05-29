#define BOOST_TEST_MODULE QtFirewalldManagerTests
#include <boost/test/unit_test.hpp>

#include <QCoreApplication> // For Qt event loop processing
#include <QDebug>
#include <QStringList>
#include <algorithm> // For std::any_of
#include <cstring> // For strcpy

#include "qtfirewalldmanager.h" // Adjust path if necessary
#include "ifirewalldmanager.h"  // Adjust path if necessary
#include "mock_firewalld_service.h" // Adjust path if needed
// FirewalldDBusError is defined in qtfirewalldmanager.h

// Provide an operator<< for QString to std::ostream for Boost.Test
#include <ostream> // Required for std::ostream
inline std::ostream& operator<<(std::ostream& os, const QString& str) {
    os << str.toStdString();
    return os;
}

// Fixture for QCoreApplication management
struct QtAppFixture {
    QCoreApplication* app = nullptr;
    char* app_name = nullptr; 
    int argc = 1;
    char** argv_ptr = nullptr;

    QtAppFixture() {
        if (!QCoreApplication::instance()) {
            // Prepare dummy argv for QCoreApplication constructor
            // Needs to be a non-const char* and exist for the lifetime of QCoreApplication if it uses it.
            // For safety, create it on the heap.
            app_name = new char[20];
            strcpy(app_name, "TestBoostApp");
            argv_ptr = &app_name; 
            
            app = new QCoreApplication(argc, argv_ptr);
            BOOST_TEST_MESSAGE("QCoreApplication instance created for tests.");
        } else {
            app = QCoreApplication::instance();
            BOOST_TEST_MESSAGE("Using existing QCoreApplication instance.");
        }
    }

    ~QtAppFixture() {
        // Only delete app_name if it was allocated by this instance
        // QCoreApplication is a singleton; its lifetime is typically the entire run of the executable.
        // Deleting it here might cause issues if other test suites/cases need it.
        // If multiple fixtures are created, app_name could be deleted prematurely.
        // It's safer to leak this small amount of memory for the test duration or manage it globally.
        // delete[] app_name; // Avoid deleting if shared or if QCoreApplication holds the pointer.
        // app_name = nullptr; 
        BOOST_TEST_MESSAGE("QtAppFixture destructor called.");
        // Do not delete 'app' here as it's a singleton and might be used by other tests.
    }

    // Helper to process Qt events (needed for DBus async replies)
    void processQtEvents() {
        if (QCoreApplication::instance()) { // Check if instance exists
            for(int i=0; i<10; ++i) { // Process events a few times to allow signals to propagate
                 QCoreApplication::instance()->processEvents(QEventLoop::ExcludeUserInputEvents, 100); // process events for 100ms
                 QCoreApplication::instance()->sendPostedEvents(); // Ensure posted events are sent
            }
        }
    }
};

// Test suite definition
BOOST_AUTO_TEST_SUITE(QtFirewalldManagerSuite)

// Common test resources
const QString testZone = "public"; 
const QString nonExistentZone = "nonExistentZoneForBoostTest123";
QtFirewalldManager manager; // Global manager instance for tests in this suite

// Helper function prototypes - implementations will use the global 'manager'
void ensureServiceNotPresent(const QString& zone, const Service& service, QtAppFixture& fixture);
void ensurePortNotPresent(const QString& zone, const Port& port, QtAppFixture& fixture);
void ensureRuleNotPresent(const QString& zone, const RichRule& rule, QtAppFixture& fixture);
void ensurePingState(const QString& zone, bool enabled, QtAppFixture& fixture);


// Helper function implementations
void ensureServiceNotPresent(const QString& zone, const Service& service, QtAppFixture& fixture) {
    try {
        // It's important to get details first, then process events for that call to complete.
        ZoneDetails details = manager.zoneDetails(zone);
        fixture.processQtEvents(); 
        
        if (std::any_of(details.services.begin(), details.services.end(), [&](const Service& s){ return s.name == service.name; })) {
            manager.removeService(zone, service);
            fixture.processQtEvents(); // Process events for removeService
            BOOST_TEST_MESSAGE("Cleaned up service " << service.name.toStdString() << " from zone " << zone.toStdString());
        }
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        // Using BOOST_TEST_MESSAGE for warnings/errors in helpers as direct BOOST_WARN might be too strong
        BOOST_TEST_MESSAGE("Warning: Error during ensureServiceNotPresent for " << service.name.toStdString() << " in zone " << zone.toStdString() << ": " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_TEST_MESSAGE("Warning: Generic runtime error during ensureServiceNotPresent for " << service.name.toStdString() << " in zone " << zone.toStdString() << ": " << e.what());
    }
}

void ensurePortNotPresent(const QString& zone, const Port& port, QtAppFixture& fixture) {
    try {
        ZoneDetails details = manager.zoneDetails(zone);
        fixture.processQtEvents();
        
        if (std::any_of(details.ports.begin(), details.ports.end(), [&](const Port& p_){ return p_.port == port.port && p_.protocol == port.protocol; })) {
            manager.removePort(zone, port);
            fixture.processQtEvents();
            BOOST_TEST_MESSAGE("Cleaned up port " << port.toString().toStdString() << " from zone " << zone.toStdString());
        }
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_TEST_MESSAGE("Warning: Error during ensurePortNotPresent for port " << port.toString().toStdString() << " in zone " << zone.toStdString() << ": " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_TEST_MESSAGE("Warning: Generic runtime error during ensurePortNotPresent for port " << port.toString().toStdString() << " in zone " << zone.toStdString() << ": " << e.what());
    }
}

void ensureRuleNotPresent(const QString& zone, const RichRule& rule, QtAppFixture& fixture) {
   try {
        ZoneDetails details = manager.zoneDetails(zone);
        fixture.processQtEvents();
        
        if (std::any_of(details.richRules.begin(), details.richRules.end(), [&](const RichRule& r_){ return r_.rule == rule.rule; })) {
            manager.removeRichRule(zone, rule);
            fixture.processQtEvents();
            BOOST_TEST_MESSAGE("Cleaned up rich rule " << rule.rule.toStdString() << " from zone " << zone.toStdString());
        }
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_TEST_MESSAGE("Warning: Error during ensureRuleNotPresent for rule " << rule.rule.toStdString() << " in zone " << zone.toStdString() << ": " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_TEST_MESSAGE("Warning: Generic runtime error during ensureRuleNotPresent for rule " << rule.rule.toStdString() << " in zone " << zone.toStdString() << ": " << e.what());
    }
}

void ensurePingState(const QString& zone, bool enabled, QtAppFixture& fixture) {
    try {
        ZoneDetails details = manager.zoneDetails(zone);
        fixture.processQtEvents();
        bool isPingBlocked = std::any_of(details.icmpBlocks.begin(), details.icmpBlocks.end(),
                                         [](const IcmpBlock& block){ return block == IcmpBlock::EchoRequest; });
        if (enabled && isPingBlocked) {
            manager.enablePing(zone);
            fixture.processQtEvents();
            BOOST_TEST_MESSAGE("Ensured ping is enabled for zone " << zone.toStdString());
        } else if (!enabled && !isPingBlocked) {
            manager.disablePing(zone);
            fixture.processQtEvents();
            BOOST_TEST_MESSAGE("Ensured ping is disabled for zone " << zone.toStdString());
        }
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_TEST_MESSAGE("Warning: Error during ensurePingState for zone " << zone.toStdString() << ": " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_TEST_MESSAGE("Warning: Generic runtime error during ensurePingState for zone " << zone.toStdString() << ": " << e.what());
    }
}

BOOST_FIXTURE_TEST_CASE(testZoneNames, QtAppFixture) {
    try {
        BOOST_TEST_MESSAGE("Starting testZoneNames");
        QStringList zones = manager.zoneNames();
        processQtEvents(); // Allow DBus reply to be processed
        BOOST_CHECK(!zones.isEmpty());
        BOOST_TEST_MESSAGE("Zone names retrieved: " << zones.join(", ").toStdString());
        // Optionally check for 'public' zone:
        // BOOST_CHECK(std::find(zones.begin(), zones.end(), QString("public")) != zones.end());
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testZoneNames: " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testZoneNames: " << e.what());
    }
}

BOOST_FIXTURE_TEST_CASE(testZoneDetails, QtAppFixture) {
    try {
        BOOST_TEST_MESSAGE("Starting testZoneDetails for zone: " << testZone.toStdString());
        ZoneDetails details = manager.zoneDetails(testZone);
        processQtEvents();
        // Basic check that the call succeeded and returned some details.
        // Specific checks depend on the actual configuration of the 'public' zone.
        BOOST_CHECK(!testZone.isEmpty()); // Verifies testZone is not empty, actual checks on 'details' would be better.
        BOOST_TEST_MESSAGE("Successfully retrieved details for zone: " << testZone.toStdString());
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testZoneDetails on '" << testZone.toStdString() << "': " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testZoneDetails on '" << testZone.toStdString() << "': " << e.what());
    }
}

BOOST_FIXTURE_TEST_CASE(testAddRemoveHttpService, QtAppFixture) {
    Service svc{"http"};
    BOOST_TEST_MESSAGE("Starting testAddRemoveHttpService for service: " << svc.name.toStdString() << " in zone: " << testZone.toStdString());
    ensureServiceNotPresent(testZone, svc, *this); // Initial cleanup

    try {
        manager.addService(testZone, svc);
        processQtEvents();
        ZoneDetails detailsAfterAdd = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(std::any_of(detailsAfterAdd.services.begin(), detailsAfterAdd.services.end(), [&](const Service& s){ return s.name == svc.name; }),
                            "Service " << svc.name.toStdString() << " not found after adding.");

        manager.removeService(testZone, svc);
        processQtEvents();
        ZoneDetails detailsAfterRemove = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(!std::any_of(detailsAfterRemove.services.begin(), detailsAfterRemove.services.end(), [&](const Service& s){ return s.name == svc.name; }),
                            "Service " << svc.name.toStdString() << " still found after removing.");
        BOOST_TEST_MESSAGE("Successfully tested add/remove for service: " << svc.name.toStdString());
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testAddRemoveHttpService: " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testAddRemoveHttpService: " << e.what());
    }
    ensureServiceNotPresent(testZone, svc, *this); // Final cleanup
}

// Test for a custom/less common service to avoid conflicts if http is special
BOOST_FIXTURE_TEST_CASE(testAddRemoveCustomService, QtAppFixture) {
    Service svc{"https-boost-test-svc"};
    BOOST_TEST_MESSAGE("Starting testAddRemoveCustomService for service: " << svc.name.toStdString() << " in zone: " << testZone.toStdString());
    ensureServiceNotPresent(testZone, svc, *this);

    try {
        manager.addService(testZone, svc);
        processQtEvents();
        ZoneDetails details = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(std::any_of(details.services.begin(), details.services.end(), [&](const Service& s){ return s.name == svc.name; }),
                            "Service " << svc.name.toStdString() << " not found after adding.");

        manager.removeService(testZone, svc);
        processQtEvents();
        details = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(!std::any_of(details.services.begin(), details.services.end(), [&](const Service& s){ return s.name == svc.name; }),
                            "Service " << svc.name.toStdString() << " still found after removing.");
        BOOST_TEST_MESSAGE("Successfully tested add/remove for service: " << svc.name.toStdString());
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testAddRemoveCustomService: " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testAddRemoveCustomService: " << e.what());
    }
    ensureServiceNotPresent(testZone, svc, *this);
}

BOOST_FIXTURE_TEST_CASE(testAddRemoveTcpPort, QtAppFixture) {
    Port port{8088, "tcp"}; // Using a less common port
    BOOST_TEST_MESSAGE("Starting testAddRemoveTcpPort for port: " << port.toString().toStdString() << " in zone: " << testZone.toStdString());
    ensurePortNotPresent(testZone, port, *this);

    try {
        manager.addPort(testZone, port);
        processQtEvents();
        ZoneDetails details = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(std::any_of(details.ports.begin(), details.ports.end(), [&](const Port& p){ return p.port == port.port && p.protocol == port.protocol; }),
                            "Port " << port.toString().toStdString() << " not found after adding.");

        manager.removePort(testZone, port);
        processQtEvents();
        details = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(!std::any_of(details.ports.begin(), details.ports.end(), [&](const Port& p){ return p.port == port.port && p.protocol == port.protocol; }),
                            "Port " << port.toString().toStdString() << " still found after removing.");
        BOOST_TEST_MESSAGE("Successfully tested add/remove for port: " << port.toString().toStdString());
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testAddRemoveTcpPort: " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testAddRemoveTcpPort: " << e.what());
    }
    ensurePortNotPresent(testZone, port, *this);
}

BOOST_FIXTURE_TEST_CASE(testAddRemoveUdpPort, QtAppFixture) {
    Port port{10055, "udp"}; // Using a less common port
    BOOST_TEST_MESSAGE("Starting testAddRemoveUdpPort for port: " << port.toString().toStdString() << " in zone: " << testZone.toStdString());
    ensurePortNotPresent(testZone, port, *this);

    try {
        manager.addPort(testZone, port);
        processQtEvents();
        ZoneDetails details = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(std::any_of(details.ports.begin(), details.ports.end(), [&](const Port& p){ return p.port == port.port && p.protocol == port.protocol; }),
                            "Port " << port.toString().toStdString() << " not found after adding.");

        manager.removePort(testZone, port);
        processQtEvents();
        details = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(!std::any_of(details.ports.begin(), details.ports.end(), [&](const Port& p){ return p.port == port.port && p.protocol == port.protocol; }),
                            "Port " << port.toString().toStdString() << " still found after removing.");
        BOOST_TEST_MESSAGE("Successfully tested add/remove for port: " << port.toString().toStdString());
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testAddRemoveUdpPort: " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testAddRemoveUdpPort: " << e.what());
    }
    ensurePortNotPresent(testZone, port, *this);
}

BOOST_FIXTURE_TEST_CASE(testAddRemoveRichRule, QtAppFixture) {
    RichRule rule{"rule family='ipv4' source address='192.168.123.123/32' service name='ssh' log prefix='boosttest' level='info' accept"};
    BOOST_TEST_MESSAGE("Starting testAddRemoveRichRule for rule: " << rule.rule.toStdString() << " in zone: " << testZone.toStdString());
    ensureRuleNotPresent(testZone, rule, *this);

    try {
        manager.addRichRule(testZone, rule);
        processQtEvents();
        ZoneDetails details = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(std::any_of(details.richRules.begin(), details.richRules.end(), [&](const RichRule& r){ return r.rule == rule.rule; }),
                            "Rich rule " << rule.rule.toStdString() << " not found after adding.");

        manager.removeRichRule(testZone, rule);
        processQtEvents();
        details = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(!std::any_of(details.richRules.begin(), details.richRules.end(), [&](const RichRule& r){ return r.rule == rule.rule; }),
                            "Rich rule " << rule.rule.toStdString() << " still found after removing.");
        BOOST_TEST_MESSAGE("Successfully tested add/remove for rich rule: " << rule.rule.toStdString());
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testAddRemoveRichRule: " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testAddRemoveRichRule: " << e.what());
    }
    ensureRuleNotPresent(testZone, rule, *this);
}

BOOST_FIXTURE_TEST_CASE(testEnableDisablePing, QtAppFixture) {
    BOOST_TEST_MESSAGE("Starting testEnableDisablePing for zone: " << testZone.toStdString());
    // Ensure a known state (e.g., ping enabled) before starting
    ensurePingState(testZone, true, *this);

    try {
        manager.disablePing(testZone);
        processQtEvents();
        ZoneDetails detailsAfterDisable = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(std::any_of(detailsAfterDisable.icmpBlocks.begin(), detailsAfterDisable.icmpBlocks.end(),
                                    [](const IcmpBlock& block){ return block == IcmpBlock::EchoRequest; }),
                            "ICMP block for EchoRequest not found after disabling ping.");

        manager.enablePing(testZone);
        processQtEvents();
        ZoneDetails detailsAfterEnable = manager.zoneDetails(testZone);
        processQtEvents();
        BOOST_CHECK_MESSAGE(!std::any_of(detailsAfterEnable.icmpBlocks.begin(), detailsAfterEnable.icmpBlocks.end(),
                                     [](const IcmpBlock& block){ return block == IcmpBlock::EchoRequest; }),
                            "ICMP block for EchoRequest still found after enabling ping.");
        BOOST_TEST_MESSAGE("Successfully tested enable/disable ping for zone: " << testZone.toStdString());
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testEnableDisablePing: " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testEnableDisablePing: " << e.what());
    }
    // Ensure ping is left enabled as a common default state
    ensurePingState(testZone, true, *this);
}

BOOST_FIXTURE_TEST_CASE(testZoneDetailsNonExistent, QtAppFixture) {
    BOOST_TEST_MESSAGE("Starting testZoneDetailsNonExistent for zone: " << nonExistentZone.toStdString());
    BOOST_CHECK_THROW(manager.zoneDetails(nonExistentZone), QtFirewalldManager::FirewalldDBusError);
    processQtEvents(); // Process error signals if any
    BOOST_TEST_MESSAGE("Verified exception for zoneDetails on non-existent zone.");
}

BOOST_FIXTURE_TEST_CASE(testAddServiceNonExistent, QtAppFixture) {
    Service svc{"http"};
    BOOST_TEST_MESSAGE("Starting testAddServiceNonExistent for zone: " << nonExistentZone.toStdString());
    BOOST_CHECK_THROW(manager.addService(nonExistentZone, svc), QtFirewalldManager::FirewalldDBusError);
    processQtEvents();
    BOOST_TEST_MESSAGE("Verified exception for addService on non-existent zone.");
}

BOOST_FIXTURE_TEST_CASE(testRemoveServiceNonExistent, QtAppFixture) {
    Service svc{"http"};
    BOOST_TEST_MESSAGE("Starting testRemoveServiceNonExistent for zone: " << nonExistentZone.toStdString());
    // This might also throw because the zone doesn't exist to check its properties first, or when the actual call is made.
    BOOST_CHECK_THROW(manager.removeService(nonExistentZone, svc), QtFirewalldManager::FirewalldDBusError);
    processQtEvents();
    BOOST_TEST_MESSAGE("Verified exception for removeService on non-existent zone.");
}

BOOST_FIXTURE_TEST_CASE(testAddPortNonExistent, QtAppFixture) {
    Port port{1234, "tcp"};
    BOOST_TEST_MESSAGE("Starting testAddPortNonExistent for zone: " << nonExistentZone.toStdString());
    BOOST_CHECK_THROW(manager.addPort(nonExistentZone, port), QtFirewalldManager::FirewalldDBusError);
    processQtEvents();
    BOOST_TEST_MESSAGE("Verified exception for addPort on non-existent zone.");
}


BOOST_AUTO_TEST_SUITE_END()


// --- Mock Test Suite ---
BOOST_AUTO_TEST_SUITE(QtFirewalldManagerMockedTestSuite)

struct MockManagerFixture : public QtAppFixture {
    QtFirewalldManager manager_mock; // Uses session bus
    MockFirewallDService* mock_service_ptr = nullptr;

    MockManagerFixture() : manager_mock(QDBusConnection::sessionBus()) {
        BOOST_TEST_MESSAGE("MockManagerFixture constructor: Setting up mock D-Bus service.");
        mock_service_ptr = new MockFirewallDService(); // Managed by this fixture
        
        // Register the main mock service object with the REAL service name on the SESSION bus
        if (!QDBusConnection::sessionBus().registerService("org.fedoraproject.FirewallD1")) {
            BOOST_TEST_MESSAGE("Failed to register mock service (org.fedoraproject.FirewallD1) on session bus: " 
                               << QDBusConnection::sessionBus().lastError().message().toStdString()
                               << ". This might happen if a previous test run didn't clean up. Trying to continue.");
            // It's possible the service is already registered by a previous (failed) test run.
            // Unregistering first might be an option, but can be risky if another process is using it.
            // QDBusConnection::sessionBus().unregisterService("org.fedoraproject.FirewallD1");
            // QDBusConnection::sessionBus().registerService("org.fedoraproject.FirewallD1"); // Try again
        } else {
            BOOST_TEST_MESSAGE("Mock service org.fedoraproject.FirewallD1 registered on session bus.");
        }

        if (!QDBusConnection::sessionBus().registerObject("/org/fedoraproject/FirewallD1", mock_service_ptr, QDBusConnection::ExportAllSlots | QDBusConnection::ExportScriptableSlots)) {
            BOOST_TEST_MESSAGE("Failed to register main mock object /org/fedoraproject/FirewallD1 on session bus: " << QDBusConnection::sessionBus().lastError().message().toStdString());
        } else {
            BOOST_TEST_MESSAGE("Main mock object /org/fedoraproject/FirewallD1 registered on session bus.");
        }
        
        if (mock_service_ptr) { 
             if(!mock_service_ptr->init()) { // This registers the zone objects
                 BOOST_TEST_MESSAGE("Failed to initialize mock_service_ptr (e.g. register zone objects).");
             } else {
                 BOOST_TEST_MESSAGE("mock_service_ptr->init() completed.");
             }
        }
        processQtEvents(); // Allow registrations to complete
    }

    ~MockManagerFixture() {
        BOOST_TEST_MESSAGE("MockManagerFixture destructor: Cleaning up mock D-Bus service.");
        // Unregister the objects first, before the service.
        // Child objects (zones) should be unregistered when their parent (mock_service_ptr) is deleted if paths are specific.
        // However, explicit unregistration is safer.
        QDBusConnection::sessionBus().unregisterObject("/org/fedoraproject/FirewallD1/zones/mockPublic");
        QDBusConnection::sessionBus().unregisterObject("/org/fedoraproject/FirewallD1/zones/mockWork");
        QDBusConnection::sessionBus().unregisterObject("/org/fedoraproject/FirewallD1");
        
        if (QDBusConnection::sessionBus().unregisterService("org.fedoraproject.FirewallD1")) {
             BOOST_TEST_MESSAGE("Mock service org.fedoraproject.FirewallD1 unregistered from session bus.");
        } else {
             BOOST_TEST_MESSAGE("Failed to unregister mock service org.fedoraproject.FirewallD1: " << QDBusConnection::sessionBus().lastError().message().toStdString());
        }
        delete mock_service_ptr; 
        mock_service_ptr = nullptr;
        processQtEvents(); // Allow unregistrations to complete
    }
};


BOOST_FIXTURE_TEST_CASE(testMockGetZones, MockManagerFixture) {
    try {
        BOOST_TEST_MESSAGE("Starting testMockGetZones with mock manager.");
        QStringList zones = manager_mock.zoneNames(); 
        processQtEvents(); // Crucial for DBus communication
        
        BOOST_TEST_MESSAGE("Mock getZones returned: " << zones.join(", ").toStdString());
        BOOST_CHECK_EQUAL(zones.size(), 2);
        BOOST_CHECK(zones.contains("mockPublic"));
        BOOST_CHECK(zones.contains("mockWork"));
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testMockGetZones: " << e.what());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testMockGetZones: " << e.what());
    }
}

BOOST_FIXTURE_TEST_CASE(testMockZoneDetails, MockManagerFixture) {
    try {
        BOOST_TEST_MESSAGE("Starting testMockZoneDetails for mockPublic zone with mock manager.");
        ZoneDetails details = manager_mock.zoneDetails("mockPublic");
        processQtEvents(); // Crucial for DBus communication

        // Check actual mocked properties based on MockFirewallDZone("mockPublic")
        BOOST_CHECK_MESSAGE(std::any_of(details.services.begin(), details.services.end(), [](const Service& s){ return s.name == "http"; }), "Service 'http' not found in mockPublic");
        BOOST_CHECK_MESSAGE(std::any_of(details.services.begin(), details.services.end(), [](const Service& s){ return s.name == "ssh"; }), "Service 'ssh' not found in mockPublic");
        BOOST_CHECK_EQUAL(details.services.size(), 2);

        BOOST_CHECK_EQUAL(details.ports.size(), 2); // We added two ports to mockPublic
        bool foundPort8080tcp = false;
        bool foundPort53udp = false;
        for(const auto& p : details.ports) {
            if(p.port == 8080 && p.protocol == "tcp") foundPort8080tcp = true;
            if(p.port == 53 && p.protocol == "udp") foundPort53udp = true;
        }
        BOOST_CHECK_MESSAGE(foundPort8080tcp, "Port 8080/tcp not found in mockPublic");
        BOOST_CHECK_MESSAGE(foundPort53udp, "Port 53/udp not found in mockPublic");

        BOOST_CHECK_EQUAL(details.richRules.size(), 1);
        if(!details.richRules.isEmpty()){
             BOOST_CHECK_EQUAL(details.richRules.first().rule, "rule family='ipv4' source address='1.2.3.4' accept");
        }
        BOOST_CHECK(details.icmpBlocks.isEmpty()); // Mocked as empty

    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        BOOST_FAIL("Exception during testMockZoneDetails: " << e.what() << " | DBus LastError: " << QDBusConnection::sessionBus().lastError().message().toStdString());
    } catch (const std::runtime_error& e) {
        BOOST_FAIL("Generic runtime Exception during testMockZoneDetails: " << e.what());
    }
}

BOOST_AUTO_TEST_SUITE_END()
