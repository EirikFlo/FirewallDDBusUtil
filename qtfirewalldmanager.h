#pragma once
#include "ifirewalldmanager.h"
#include <QDBusInterface>
#include <QDBusReply>
#include <QVariant>
#include <QDBusConnection>
#include <stdexcept>
#include <QString>

/**
 * @brief Manages interactions with the firewalld D-Bus interface.
 *
 * This class provides methods to query and modify firewalld zones,
 * services, ports, rich rules, and ICMP blocks. It communicates
 * with firewalld via its D-Bus API.
 */
class QtFirewalldManager : public IFirewalldManager {
public:
    /**
     * @brief Custom exception class for firewalld D-Bus errors.
     *
     * This exception is thrown when a D-Bus call to firewalld
     * results in an error, or when expected data is not returned correctly.
     */
    class FirewalldDBusError : public std::runtime_error {
    public:
        /**
         * @brief Constructs a FirewalldDBusError with a QString message.
         * @param message The error message.
         */
        FirewalldDBusError(const QString &message)
            : std::runtime_error(message.toStdString()) {}
        /**
         * @brief Constructs a FirewalldDBusError with a std::string message.
         * @param message The error message.
         */
        FirewalldDBusError(const std::string &message)
            : std::runtime_error(message) {}
    };

    /**
     * @brief Constructs a QtFirewalldManager with a specific D-Bus connection.
     * @param connection The QDBusConnection to use for D-Bus communication.
     *                   Defaults to QDBusConnection::systemBus().
     */
    explicit QtFirewalldManager(QDBusConnection connection = QDBusConnection::systemBus());
    ~QtFirewalldManager() override = default;

    /**
     * @brief Retrieves a list of all available zone names.
     * @return QStringList A list of zone names.
     * @throw FirewalldDBusError if the DBus call fails.
     */
    QStringList zoneNames() override;

    /**
     * @brief Retrieves detailed information for a specific zone.
     * @param zone The name of the zone to query.
     * @return ZoneDetails An object containing the details of the zone.
     * @throw FirewalldDBusError if the DBus call fails or if essential properties cannot be read.
     */
    ZoneDetails zoneDetails(const QString &zone) override;

    /**
     * @brief Adds a service to a specified zone.
     * @param zone The name of the zone.
     * @param service The Service object representing the service to add.
     * @throw FirewalldDBusError if the DBus call fails.
     */
    void addService(const QString &zone, const Service &service) override;

    /**
     * @brief Removes a service from a specified zone.
     * @param zone The name of the zone.
     * @param service The Service object representing the service to remove.
     * @throw FirewalldDBusError if the DBus call fails.
     */
    void removeService(const QString &zone, const Service &service) override;

    /**
     * @brief Adds a rich rule to a specified zone.
     * @param zone The name of the zone.
     * @param rule The RichRule object representing the rule to add.
     * @throw FirewalldDBusError if the DBus call fails.
     */
    void addRichRule(const QString &zone, const RichRule &rule) override;

    /**
     * @brief Removes a rich rule from a specified zone.
     * @param zone The name of the zone.
     * @param rule The RichRule object representing the rule to remove.
     * @throw FirewalldDBusError if the DBus call fails.
     */
    void removeRichRule(const QString &zone, const RichRule &rule) override;

    /**
     * @brief Adds a port to a specified zone.
     * @param zone The name of the zone.
     * @param port The Port object representing the port to add (number and protocol).
     * @throw FirewalldDBusError if the DBus call fails.
     */
    void addPort(const QString &zone, const Port &port) override;

    /**
     * @brief Removes a port from a specified zone.
     * @param zone The name of the zone.
     * @param port The Port object representing the port to remove (number and protocol).
     * @throw FirewalldDBusError if the DBus call fails.
     */
    void removePort(const QString &zone, const Port &port) override;

    /**
     * @brief Enables ICMP echo requests (ping) for a specified zone.
     * This is achieved by removing the ICMP block for 'echo-request'.
     * @param zone The name of the zone.
     * @throw FirewalldDBusError if the DBus call fails.
     */
    void enablePing(const QString &zone) override;

    /**
     * @brief Disables ICMP echo requests (ping) for a specified zone.
     * This is achieved by adding an ICMP block for 'echo-request'.
     * @param zone The name of the zone.
     * @throw FirewalldDBusError if the DBus call fails.
     */
    void disablePing(const QString &zone) override;

private:
    QDBusInterface coreIface() const;
    QDBusInterface zoneIface(const QString &zone) const;
    QString objectPathForZone(const QString &zone) const;

    QDBusConnection m_dbusConnection;
};
