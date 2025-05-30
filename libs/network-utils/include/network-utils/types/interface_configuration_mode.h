#pragma once

#include <QString>
#include <QMetaType> // For Q_DECLARE_METATYPE

enum class InterfaceConfigurationMode {
    Unknown,
    Disabled,
    LinkLocal, // Added
    DHCP,      // Auto
    Manual
};

Q_DECLARE_METATYPE(InterfaceConfigurationMode)

inline QString toString(InterfaceConfigurationMode mode) {
    switch(mode) {
        case InterfaceConfigurationMode::Disabled: return QStringLiteral("Disabled");
        case InterfaceConfigurationMode::LinkLocal: return QStringLiteral("LinkLocal");
        case InterfaceConfigurationMode::DHCP: return QStringLiteral("DHCP");
        case InterfaceConfigurationMode::Manual: return QStringLiteral("Manual");
        default: return QStringLiteral("Unknown");
    }
}
