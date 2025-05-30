#include "network-utils/networkmanager/INetworkManager.h"

// This file primarily exists to ensure that INetworkManager.h,
// which contains Q_OBJECT, is processed by the Meta-Object Compiler (MOC),
// especially when AUTOMOC is used in CMake.
//
// For a pure interface with Q_OBJECT (e.g., for signals),
// if all methods are pure virtual and the destructor is defaulted in the header,
// this .cpp file might seem empty. However, its presence in the CMake target's
// sources helps ensure AUTOMOC picks up the header for MOC processing,
// which generates the necessary vtable and other meta-object code.

// If INetworkManager had any non-inline static members or specific destructor
// needs beyond =default that couldn't be in the header, they would go here.
// For now, INetworkManager::~INetworkManager() = default; is in the header.
