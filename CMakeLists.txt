cmake_minimum_required(VERSION 3.14)

project(NetworkDemoApp LANGUAGES CXX) # Renamed project

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core DBus Network Test) # Find Qt (6 or 5) and major components
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core DBus Network Test) # Find specific versioned components

enable_testing() # Enable CTest

# Define network-utils library
add_library(network-utils STATIC
  libs/network-utils/src/firewalld/qtfirewalldmanager.cpp
  libs/network-utils/include/network-utils/firewalld/qtfirewalldmanager.h # For AUTOMOC
  libs/network-utils/src/common/dbus_types.cpp
  libs/network-utils/src/networkmanager/INetworkManager.cpp
  libs/network-utils/include/network-utils/networkmanager/INetworkManager.h # For AUTOMOC
  libs/network-utils/src/networkmanager/QtNetworkManager.cpp
  libs/network-utils/include/network-utils/networkmanager/QtNetworkManager.h # For AUTOMOC
  # NetworkManager sources will be added later
)
target_include_directories(network-utils
  PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/network-utils/include"
    "${CMAKE_CURRENT_BINARY_DIR}" # For MOC/UIC generated files
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/libs/network-utils/src"
)
target_link_libraries(network-utils
  PUBLIC
    Qt${QT_VERSION_MAJOR}::Core
    Qt${QT_VERSION_MAJOR}::DBus
    Qt${QT_VERSION_MAJOR}::Network # Added for QHostAddress
)
set_target_properties(network-utils PROPERTIES CXX_STANDARD ${CMAKE_CXX_STANDARD}) # Ensure C++20
# Explicitly enable AUTOMOC, AUTOUIC, AUTORCC for the library
set_target_properties(network-utils PROPERTIES AUTOMOC ON AUTOUIC ON AUTORCC ON)

# Main Application (NetworkDemoApp)
add_executable(NetworkDemoApp main.cpp) # Changed from FirewalldManager
target_link_libraries(NetworkDemoApp PRIVATE network-utils)

install(TARGETS NetworkDemoApp # Changed from FirewalldManager
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

# Qt Test Target
add_executable(FirewalldQtTests
  libs/network-utils/tests/firewalld/test_qtfirewalldmanager.cpp
)
target_link_libraries(FirewalldQtTests
  PRIVATE
    network-utils
    Qt${QT_VERSION_MAJOR}::Test
)
add_test(NAME FirewalldQtTests COMMAND FirewalldQtTests) # Updated test name

# Boost Test Target
find_package(Boost REQUIRED COMPONENTS unit_test_framework)

add_executable(FirewalldBoostTests
  libs/network-utils/tests/firewalld/test_qtfirewalldmanager_boost.cpp
  libs/network-utils/tests/firewalld/mock_firewalld_service.cpp
)
target_link_libraries(FirewalldBoostTests
  PRIVATE
    network-utils
    Boost::unit_test_framework
)
add_test(NAME FirewalldBoostTests COMMAND FirewalldBoostTests) # Updated test name

# NetworkManager Live Test Target
add_executable(NetworkManagerLiveTests
  libs/network-utils/tests/networkmanager/test_qtnetworkmanager_live.cpp
)

target_link_libraries(NetworkManagerLiveTests PRIVATE
  network-utils
  Qt${QT_VERSION_MAJOR}::Core
  Qt${QT_VERSION_MAJOR}::DBus
  Qt${QT_VERSION_MAJOR}::Test
)
set_target_properties(NetworkManagerLiveTests PROPERTIES AUTOMOC ON)

add_test(NAME NetworkManagerLiveTests COMMAND NetworkManagerLiveTests)

# NetworkManager Boost Test Target
add_executable(NetworkManagerBoostTests
  libs/network-utils/tests/networkmanager/MockNetworkManagerService.h
  libs/network-utils/tests/networkmanager/MockNetworkManagerService.cpp
  libs/network-utils/tests/networkmanager/MockNMDevice.h
  libs/network-utils/tests/networkmanager/MockNMDevice.cpp
  libs/network-utils/tests/networkmanager/MockNMIp4Config.h
  libs/network-utils/tests/networkmanager/MockNMIp4Config.cpp
  libs/network-utils/tests/networkmanager/test_qtnetworkmanager_boost.cpp
)
target_link_libraries(NetworkManagerBoostTests PRIVATE
  network-utils
  Qt${QT_VERSION_MAJOR}::Core
  Qt${QT_VERSION_MAJOR}::DBus
  Qt${QT_VERSION_MAJOR}::Network # For QHostAddress if used in mock/tests
  Qt${QT_VERSION_MAJOR}::Test # For QTest utilities like QSignalSpy, if needed later
  Boost::unit_test_framework
)
set_target_properties(NetworkManagerBoostTests PROPERTIES AUTOMOC ON)
add_test(NAME NetworkManagerBoostTests COMMAND NetworkManagerBoostTests)
