#include <QtTest>
#include <QObject>
#include "network-utils/firewalld/qtfirewalldmanager.h" // Updated path
#include "network-utils/firewalld/ifirewalldmanager.h"  // Updated path
#include <QDebug>
#include <QStringList>
#include <stdexcept> // For FirewalldDBusError
#include <algorithm> // For std::any_of
#include "network-utils/types/dbus_types.h" // For D-Bus type registration

class TestQtFirewalldManager : public QObject {
    Q_OBJECT

public:
    TestQtFirewalldManager();
    ~TestQtFirewalldManager() override;

private slots:
    void initTestCase();    // Called before the first test function is executed
    void cleanupTestCase(); // Called after the last test function was executed
    void init();            // Called before each test function is executed
    void cleanup();         // Called after each test function is executed

    // Test methods
    void testZoneNames();
    void testZoneDetails_data();
    void testZoneDetails();
    void testAddRemoveService_data();
    void testAddRemoveService();
    void testAddRemovePort_data();
    void testAddRemovePort();
    void testAddRemoveRichRule_data();
    void testAddRemoveRichRule();
    void testEnableDisablePing_data();
    void testEnableDisablePing();
    
    void testInvalidZoneOperations_data();
    void testInvalidZoneOperations();

private:
    QtFirewalldManager m_manager;
    const QString m_testZone = "public"; // A common, usually existing zone.
    const QString m_nonExistentZone = "nonExistentZoneForTesting123";

    // Helper to ensure a service is not present
    void ensureServiceNotPresent(const QString& zone, const Service& service);
    // Helper to ensure a port is not present
    void ensurePortNotPresent(const QString& zone, const Port& port);
    // Helper to ensure a rich rule is not present
    void ensureRuleNotPresent(const QString& zone, const RichRule& rule);
    // Helper to ensure ping (ICMP echo request) is in a specific state
    void ensurePingState(const QString& zone, bool enabled);
};

// Constructor, Destructor, init/cleanup methods implementation
TestQtFirewalldManager::TestQtFirewalldManager() {
    NetworkUtils::registerDbusTypes(); // Register custom types
}
TestQtFirewalldManager::~TestQtFirewalldManager() {}

void TestQtFirewalldManager::initTestCase() {
    qDebug() << "Starting test case execution. Ensure firewalld service is running and accessible.";
    // For tests that modify state, it's better to create/delete a dedicated test zone.
    // However, firewalld's API for creating/deleting zones is usually permanent.
    // For now, rely on cleaning up changes in the existing m_testZone.
    // Initial cleanup of known test entities in m_testZone to avoid interference from previous failed runs.
    ensureServiceNotPresent(m_testZone, Service{"http"}); // Example service used in tests
    ensureServiceNotPresent(m_testZone, Service{"https-test-svc"}); // Example service
    ensurePortNotPresent(m_testZone, Port{8080, "tcp"}); // Example port
    ensureRuleNotPresent(m_testZone, RichRule{"rule family='ipv4' source address='192.168.1.100/32' service name='http' accept"}); // Example rule
    ensurePingState(m_testZone, true); // Ensure pings are enabled initially
}
void TestQtFirewalldManager::cleanupTestCase() {
    qDebug() << "Finished test case execution.";
    // Final cleanup of known test entities in m_testZone
    ensureServiceNotPresent(m_testZone, Service{"http"});
    ensureServiceNotPresent(m_testZone, Service{"https-test-svc"});
    ensurePortNotPresent(m_testZone, Port{8080, "tcp"});
    ensureRuleNotPresent(m_testZone, RichRule{"rule family='ipv4' source address='192.168.1.100/32' service name='http' accept"});
    ensurePingState(m_testZone, true); // Restore pings to enabled state
}
void TestQtFirewalldManager::init() {
    // Runs before each test function.
    // Could be used to ensure a clean state for m_testZone if needed.
}
void TestQtFirewalldManager::cleanup() {
    // Runs after each test function.
    // This is crucial to make tests idempotent.
    // The specific cleanup for items added during a test should be in that test or its _data function.
    // General cleanup of potentially leftover items is good here and in cleanupTestCase.
}

// Implement helper methods
void TestQtFirewalldManager::ensureServiceNotPresent(const QString& zone, const Service& service) {
    try {
        ZoneDetails details = m_manager.zoneDetails(zone);
        if (std::any_of(details.services.begin(), details.services.end(), [&](const Service& s){ return s.name == service.name; })) {
            m_manager.removeService(zone, service);
            qDebug() << "Cleaned up service" << service.name << "from zone" << zone;
        }
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        // If zone doesn't exist, or other D-Bus error, service is effectively not present in a valid zone's details
        qWarning() << "Error during ensureServiceNotPresent for" << service.name << "in zone" << zone << ":" << e.what();
    } catch (const std::runtime_error& e) { // Catch other potential runtime errors from D-Bus calls
        qWarning() << "Generic runtime error during ensureServiceNotPresent for" << service.name << "in zone" << zone << ":" << e.what();
    }
}

void TestQtFirewalldManager::testZoneDetails_data() {
    QTest::addColumn<QString>("zoneName");
    QTest::newRow("public-zone") << m_testZone;
    // You could add more rows for other known zones if necessary
    // QTest::newRow("another-zone") << "anotherExistingZone";
}

void TestQtFirewalldManager::testZoneDetails() {
    QFETCH(QString, zoneName);
    QVERIFY(!zoneName.isEmpty());

    try {
        ZoneDetails details = m_manager.zoneDetails(zoneName);
        qDebug() << "Details for zone" << zoneName << ":"
                 << "Services:" << details.services.count()
                 << "Ports:" << details.ports.count()
                 << "Rich Rules:" << details.richRules.count()
                 << "ICMP Blocks:" << details.icmpBlocks.count();
        // Basic check: the object was created. More specific checks depend on known zone state.
        QVERIFY(true); // Implicitly, no exception means success for this basic test
    } catch (const QtFirewalldManager::FirewalldDBusError &e) {
        QFAIL(QString("testZoneDetails for zone %1 failed with FirewalldDBusError: %2").arg(zoneName, e.what()).toStdString().c_str());
    } catch (const std::runtime_error &e) {
        QFAIL(QString("testZoneDetails for zone %1 failed with std::runtime_error: %2").arg(zoneName, e.what()).toStdString().c_str());
    }
}

void TestQtFirewalldManager::testZoneNames() {
    try {
        QStringList zoneNames = m_manager.zoneNames();
        QVERIFY(!zoneNames.isEmpty()); // Assuming there's at least one zone

        // Optional: Check for common zones. This makes the test more specific
        // to typical firewalld setups but might fail in minimal environments.
        // QVERIFY(zoneNames.contains("public"));
        // QVERIFY(zoneNames.contains("block"));
        // QVERIFY(zoneNames.contains("drop"));

        qDebug() << "Available zones:" << zoneNames;
    } catch (const QtFirewalldManager::FirewalldDBusError &e) {
        QFAIL(QString("testZoneNames failed with FirewalldDBusError: %1").arg(e.what()).toStdString().c_str());
    } catch (const std::runtime_error &e) {
        QFAIL(QString("testZoneNames failed with std::runtime_error: %1").arg(e.what()).toStdString().c_str());
    }
}

void TestQtFirewalldManager::ensurePortNotPresent(const QString& zone, const Port& port) {
    try {
        ZoneDetails details = m_manager.zoneDetails(zone);
        if (std::any_of(details.ports.begin(), details.ports.end(), [&](const Port& p){ return p.port == port.port && p.protocol == port.protocol; })) {
            m_manager.removePort(zone, port);
            qDebug() << "Cleaned up port" << port.port << "/" << port.protocol << "from zone" << zone;
        }
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        qWarning() << "Error during ensurePortNotPresent for port" << port.port << "/" << port.protocol << "in zone" << zone << ":" << e.what();
    } catch (const std::runtime_error& e) {
        qWarning() << "Generic runtime error during ensurePortNotPresent for port" << port.port << "/" << port.protocol << "in zone" << zone << ":" << e.what();
    }
}

void TestQtFirewalldManager::ensureRuleNotPresent(const QString& zone, const RichRule& rule) {
    try {
        ZoneDetails details = m_manager.zoneDetails(zone);
        if (std::any_of(details.richRules.begin(), details.richRules.end(), [&](const RichRule& rr){ return rr.rule == rule.rule; })) {
            m_manager.removeRichRule(zone, rule);
            qDebug() << "Cleaned up rich rule" << rule.rule << "from zone" << zone;
        }
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        qWarning() << "Error during ensureRuleNotPresent for rule" << rule.rule << "in zone" << zone << ":" << e.what();
    } catch (const std::runtime_error& e) {
        qWarning() << "Generic runtime error during ensureRuleNotPresent for rule" << rule.rule << "in zone" << zone << ":" << e.what();
    }
}

void TestQtFirewalldManager::ensurePingState(const QString& zone, bool enabled) {
    try {
        ZoneDetails details = m_manager.zoneDetails(zone);
        bool isPingBlocked = std::any_of(details.icmpBlocks.begin(), details.icmpBlocks.end(),
                                         [](const IcmpBlock& block){ return block == IcmpBlock::EchoRequest; });
        if (enabled && isPingBlocked) {
            m_manager.enablePing(zone);
            qDebug() << "Ensured ping is enabled for zone" << zone;
        } else if (!enabled && !isPingBlocked) {
            m_manager.disablePing(zone);
            qDebug() << "Ensured ping is disabled for zone" << zone;
        }
    } catch (const QtFirewalldManager::FirewalldDBusError& e) {
        qWarning() << "Error during ensurePingState for zone" << zone << ":" << e.what();
    } catch (const std::runtime_error& e) {
        qWarning() << "Generic runtime error during ensurePingState for zone" << zone << ":" << e.what();
    }
}

void TestQtFirewalldManager::testAddRemoveService_data() {
    QTest::addColumn<QString>("zoneName");
    QTest::addColumn<QString>("serviceName");
    QTest::newRow("public-http") << m_testZone << "http"; // Common service
    QTest::newRow("public-https-test") << m_testZone << "https-test-svc"; // A more unique test service
}

void TestQtFirewalldManager::testAddRemoveService() {
    QFETCH(QString, zoneName);
    QFETCH(QString, serviceName);
    Service svc{serviceName};

    ensureServiceNotPresent(zoneName, svc); // Cleanup from previous potentially failed runs

    try {
        // Add service
        m_manager.addService(zoneName, svc);
        ZoneDetails detailsAfterAdd = m_manager.zoneDetails(zoneName);
        QVERIFY2(std::any_of(detailsAfterAdd.services.begin(), detailsAfterAdd.services.end(),
                             [&](const Service& s){ return s.name == svc.name; }),
                 QString("Service %1 not found after adding to zone %2").arg(svc.name, zoneName).toStdString().c_str());
        qDebug() << "Service" << svc.name << "added to zone" << zoneName;

        // Remove service
        m_manager.removeService(zoneName, svc);
        ZoneDetails detailsAfterRemove = m_manager.zoneDetails(zoneName);
        QVERIFY2(!std::any_of(detailsAfterRemove.services.begin(), detailsAfterRemove.services.end(),
                              [&](const Service& s){ return s.name == svc.name; }),
                 QString("Service %1 still found after removing from zone %2").arg(svc.name, zoneName).toStdString().c_str());
        qDebug() << "Service" << svc.name << "removed from zone" << zoneName;

    } catch (const QtFirewalldManager::FirewalldDBusError &e) {
        // Clean up before failing, in case the error happened after adding but before/during removing
        ensureServiceNotPresent(zoneName, svc);
        QFAIL(QString("testAddRemoveService for %1 in zone %2 failed with FirewalldDBusError: %3")
              .arg(serviceName, zoneName, e.what()).toStdString().c_str());
    } catch (const std::runtime_error &e) {
        ensureServiceNotPresent(zoneName, svc);
        QFAIL(QString("testAddRemoveService for %1 in zone %2 failed with std::runtime_error: %3")
              .arg(serviceName, zoneName, e.what()).toStdString().c_str());
    }
    // Final cleanup to ensure the service is removed, even if asserts failed
    ensureServiceNotPresent(zoneName, svc);
}

void TestQtFirewalldManager::testAddRemovePort_data() {
    QTest::addColumn<QString>("zoneName");
    QTest::addColumn<quint16>("portNumber");
    QTest::addColumn<QString>("protocol");
    QTest::newRow("public-tcp-8080") << m_testZone << static_cast<quint16>(8080) << "tcp";
    QTest::newRow("public-udp-5353") << m_testZone << static_cast<quint16>(5353) << "udp";
}

void TestQtFirewalldManager::testAddRemovePort() {
    QFETCH(QString, zoneName);
    QFETCH(quint16, portNumber);
    QFETCH(QString, protocol);
    Port port{portNumber, protocol};

    ensurePortNotPresent(zoneName, port); // Cleanup from previous potentially failed runs

    try {
        // Add port
        m_manager.addPort(zoneName, port);
        ZoneDetails detailsAfterAdd = m_manager.zoneDetails(zoneName);
        QVERIFY2(std::any_of(detailsAfterAdd.ports.begin(), detailsAfterAdd.ports.end(),
                             [&](const Port& p){ return p.port == port.port && p.protocol == port.protocol; }),
                 QString("Port %1/%2 not found after adding to zone %3").arg(QString::number(port.port), port.protocol, zoneName).toStdString().c_str());
        qDebug() << "Port" << port.port << "/" << port.protocol << "added to zone" << zoneName;

        // Remove port
        m_manager.removePort(zoneName, port);
        ZoneDetails detailsAfterRemove = m_manager.zoneDetails(zoneName);
        QVERIFY2(!std::any_of(detailsAfterRemove.ports.begin(), detailsAfterRemove.ports.end(),
                              [&](const Port& p){ return p.port == port.port && p.protocol == port.protocol; }),
                 QString("Port %1/%2 still found after removing from zone %3").arg(QString::number(port.port), port.protocol, zoneName).toStdString().c_str());
        qDebug() << "Port" << port.port << "/" << port.protocol << "removed from zone" << zoneName;

    } catch (const QtFirewalldManager::FirewalldDBusError &e) {
        ensurePortNotPresent(zoneName, port);
        QFAIL(QString("testAddRemovePort for %1/%2 in zone %3 failed with FirewalldDBusError: %4")
              .arg(QString::number(port.port), port.protocol, zoneName, e.what()).toStdString().c_str());
    } catch (const std::runtime_error &e) {
        ensurePortNotPresent(zoneName, port);
        QFAIL(QString("testAddRemovePort for %1/%2 in zone %3 failed with std::runtime_error: %4")
              .arg(QString::number(port.port), port.protocol, zoneName, e.what()).toStdString().c_str());
    }
    ensurePortNotPresent(zoneName, port);
}

void TestQtFirewalldManager::testAddRemoveRichRule_data() {
    QTest::addColumn<QString>("zoneName");
    QTest::addColumn<QString>("ruleString");
    QTest::newRow("public-rich-rule") << m_testZone << "rule family='ipv4' source address='192.168.1.100/32' service name='tftp' accept";
    // Add another more complex or different type of rule if desired
    QTest::newRow("public-rich-rule-log") << m_testZone << "rule family='ipv4' source address='192.168.5.0/24' log prefix='TESTFW:' level='info' limit value='1/m' accept";
}

void TestQtFirewalldManager::testAddRemoveRichRule() {
    QFETCH(QString, zoneName);
    QFETCH(QString, ruleString);
    RichRule rule{ruleString};

    ensureRuleNotPresent(zoneName, rule); // Cleanup from previous potentially failed runs

    try {
        // Add rich rule
        m_manager.addRichRule(zoneName, rule);
        ZoneDetails detailsAfterAdd = m_manager.zoneDetails(zoneName);
        QVERIFY2(std::any_of(detailsAfterAdd.richRules.begin(), detailsAfterAdd.richRules.end(),
                             [&](const RichRule& rr){ return rr.rule == rule.rule; }),
                 QString("Rich rule '%1' not found after adding to zone %2").arg(rule.rule, zoneName).toStdString().c_str());
        qDebug() << "Rich rule" << rule.rule << "added to zone" << zoneName;

        // Remove rich rule
        m_manager.removeRichRule(zoneName, rule);
        ZoneDetails detailsAfterRemove = m_manager.zoneDetails(zoneName);
        QVERIFY2(!std::any_of(detailsAfterRemove.richRules.begin(), detailsAfterRemove.richRules.end(),
                              [&](const RichRule& rr){ return rr.rule == rule.rule; }),
                 QString("Rich rule '%1' still found after removing from zone %2").arg(rule.rule, zoneName).toStdString().c_str());
        qDebug() << "Rich rule" << rule.rule << "removed from zone" << zoneName;

    } catch (const QtFirewalldManager::FirewalldDBusError &e) {
        ensureRuleNotPresent(zoneName, rule);
        QFAIL(QString("testAddRemoveRichRule for '%1' in zone %2 failed with FirewalldDBusError: %3")
              .arg(rule.rule, zoneName, e.what()).toStdString().c_str());
    } catch (const std::runtime_error &e) {
        ensureRuleNotPresent(zoneName, rule);
        QFAIL(QString("testAddRemoveRichRule for '%1' in zone %2 failed with std::runtime_error: %3")
              .arg(rule.rule, zoneName, e.what()).toStdString().c_str());
    }
    ensureRuleNotPresent(zoneName, rule);
}

void TestQtFirewalldManager::testEnableDisablePing_data() {
    QTest::addColumn<QString>("zoneName");
    QTest::newRow("public-ping") << m_testZone;
}

void TestQtFirewalldManager::testEnableDisablePing() {
    QFETCH(QString, zoneName);

    // Ensure a known starting state (e.g., ping enabled)
    ensurePingState(zoneName, true);

    try {
        // Disable Ping
        m_manager.disablePing(zoneName);
        ZoneDetails detailsAfterDisable = m_manager.zoneDetails(zoneName);
        QVERIFY2(std::any_of(detailsAfterDisable.icmpBlocks.begin(), detailsAfterDisable.icmpBlocks.end(),
                             [](const IcmpBlock& block){ return block == IcmpBlock::EchoRequest; }),
                 QString("ICMP block for EchoRequest not found after disabling ping in zone %1").arg(zoneName).toStdString().c_str());
        qDebug() << "Ping (ICMP EchoRequest) disabled for zone" << zoneName;

        // Enable Ping
        m_manager.enablePing(zoneName);
        ZoneDetails detailsAfterEnable = m_manager.zoneDetails(zoneName);
        QVERIFY2(!std::any_of(detailsAfterEnable.icmpBlocks.begin(), detailsAfterEnable.icmpBlocks.end(),
                              [](const IcmpBlock& block){ return block == IcmpBlock::EchoRequest; }),
                 QString("ICMP block for EchoRequest still found after enabling ping in zone %1").arg(zoneName).toStdString().c_str());
        qDebug() << "Ping (ICMP EchoRequest) enabled for zone" << zoneName;

    } catch (const QtFirewalldManager::FirewalldDBusError &e) {
        // Attempt to restore a sane state (ping enabled) before failing
        ensurePingState(zoneName, true);
        QFAIL(QString("testEnableDisablePing for zone %1 failed with FirewalldDBusError: %2")
              .arg(zoneName, e.what()).toStdString().c_str());
    } catch (const std::runtime_error &e) {
        ensurePingState(zoneName, true);
        QFAIL(QString("testEnableDisablePing for zone %1 failed with std::runtime_error: %2")
              .arg(zoneName, e.what()).toStdString().c_str());
    }
    // Ensure ping is left enabled as a common default state
    ensurePingState(zoneName, true);
}

void TestQtFirewalldManager::testInvalidZoneOperations_data() {
    QTest::addColumn<QString>("methodName");
    QTest::addColumn<QString>("targetZone");

    QTest::newRow("zoneDetails-nonExistent") << "zoneDetails" << m_nonExistentZone;
    QTest::newRow("addService-nonExistent") << "addService" << m_nonExistentZone;
    QTest::newRow("removeService-nonExistent") << "removeService" << m_nonExistentZone;
    QTest::newRow("addPort-nonExistent") << "addPort" << m_nonExistentZone;
    QTest::newRow("removePort-nonExistent") << "removePort" << m_nonExistentZone;
    QTest::newRow("addRichRule-nonExistent") << "addRichRule" << m_nonExistentZone;
    QTest::newRow("removeRichRule-nonExistent") << "removeRichRule" << m_nonExistentZone;
    QTest::newRow("enablePing-nonExistent") << "enablePing" << m_nonExistentZone;
    QTest::newRow("disablePing-nonExistent") << "disablePing" << m_nonExistentZone;
}

void TestQtFirewalldManager::testInvalidZoneOperations() {
    QFETCH(QString, methodName);
    QFETCH(QString, targetZone);

    qDebug() << "Testing invalid operation:" << methodName << "on zone" << targetZone;

    if (methodName == "zoneDetails") {
        QVERIFY_EXCEPTION_THROWN(m_manager.zoneDetails(targetZone), QtFirewalldManager::FirewalldDBusError);
    } else if (methodName == "addService") {
        QVERIFY_EXCEPTION_THROWN(m_manager.addService(targetZone, Service{"http"}), QtFirewalldManager::FirewalldDBusError);
    } else if (methodName == "removeService") {
        // removeService might not throw if service isn't there, but should throw if zone itself is invalid for query
        // For non-existent zone, the zoneIface() will likely be invalid, causing property read or call to fail.
        QVERIFY_EXCEPTION_THROWN(m_manager.removeService(targetZone, Service{"http"}), QtFirewalldManager::FirewalldDBusError);
    } else if (methodName == "addPort") {
        QVERIFY_EXCEPTION_THROWN(m_manager.addPort(targetZone, Port{1234, "tcp"}), QtFirewalldManager::FirewalldDBusError);
    } else if (methodName == "removePort") {
        QVERIFY_EXCEPTION_THROWN(m_manager.removePort(targetZone, Port{1234, "tcp"}), QtFirewalldManager::FirewalldDBusError);
    } else if (methodName == "addRichRule") {
        QVERIFY_EXCEPTION_THROWN(m_manager.addRichRule(targetZone, RichRule{"rule service name='ftp' accept"}), QtFirewalldManager::FirewalldDBusError);
    } else if (methodName == "removeRichRule") {
        QVERIFY_EXCEPTION_THROWN(m_manager.removeRichRule(targetZone, RichRule{"rule service name='ftp' accept"}), QtFirewalldManager::FirewalldDBusError);
    } else if (methodName == "enablePing") {
        QVERIFY_EXCEPTION_THROWN(m_manager.enablePing(targetZone), QtFirewalldManager::FirewalldDBusError);
    } else if (methodName == "disablePing") {
        QVERIFY_EXCEPTION_THROWN(m_manager.disablePing(targetZone), QtFirewalldManager::FirewalldDBusError);
    } else {
        QFAIL(QString("Unknown method name %1 in testInvalidZoneOperations").arg(methodName).toStdString().c_str());
    }
}


#include "test_qtfirewalldmanager.moc"
QTEST_MAIN(TestQtFirewalldManager)
