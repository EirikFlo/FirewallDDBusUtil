#pragma once

#include "interface_configuration_mode.h"
#include "manual_ip_configuration.h"
#include <QMetaType> // For Q_DECLARE_METATYPE

struct InterfaceConfiguration {
    InterfaceConfigurationMode mode = InterfaceConfigurationMode::Unknown;
    ManualIpConfiguration manualSettings; // Only relevant if mode is Manual

    bool operator==(const InterfaceConfiguration &other) const noexcept {
        if (mode != other.mode) return false;
        if (mode == InterfaceConfigurationMode::Manual) {
            return manualSettings == other.manualSettings;
        }
        return true; // For other modes, if mode is same, they are considered equal without checking manualSettings
    }
};

Q_DECLARE_METATYPE(InterfaceConfiguration)
