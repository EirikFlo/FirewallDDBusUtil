cmake_minimum_required(VERSION 3.14)

project(test1 LANGUAGES CXX)

set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(QT NAMES Qt6 Qt5 REQUIRED COMPONENTS Core DBus Test)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core DBus Test)

add_executable(FirewalldManager
  ifirewalldmanager.h
  qtfirewalldmanager.h
  qtfirewalldmanager.cpp
  main.cpp
)
target_link_libraries(FirewalldManager Qt${QT_VERSION_MAJOR}::Core Qt${QT_VERSION_MAJOR}::DBus)

install(TARGETS FirewalldManager
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

add_executable(FirewalldManagerTests
  test_qtfirewalldmanager.cpp
  # Add qtfirewalldmanager.cpp and qtfirewalldmanager.h if not part of a library
  # If QtFirewalldManager is built as a library, link against it.
  # For now, assume we might need to compile them directly into the test
  # or that the main FirewalldManager target is a library.
  # Adjust if QtFirewalldManager is part of a static/shared library.
)
# Link QtFirewalldManager sources directly if not a library
target_sources(FirewalldManagerTests PRIVATE qtfirewalldmanager.cpp)

target_link_libraries(FirewalldManagerTests
  Qt${QT_VERSION_MAJOR}::Core
  Qt${QT_VERSION_MAJOR}::DBus
  Qt${QT_VERSION_MAJOR}::Test
)

add_test(NAME FirewalldManagerTests COMMAND FirewalldManagerTests)

# Boost Test Setup
find_package(Boost REQUIRED COMPONENTS unit_test_framework)

add_executable(FirewalldManagerBoostTests
  test_qtfirewalldmanager_boost.cpp
  # qtfirewalldmanager.cpp is already linked via target_sources if FirewalldManager is not a library
  # If FirewalldManager is a library, link against it instead of target_sources below.
)

# Link QtFirewalldManager sources directly if not a library
# This assumes FirewalldManager is NOT a library and its sources need to be compiled with the tests.
# If FirewalldManager is a library target (add_library), then link against that target instead.
target_sources(FirewalldManagerBoostTests PRIVATE 
  qtfirewalldmanager.cpp
  mock_firewalld_service.cpp
)

target_link_libraries(FirewalldManagerBoostTests
  Qt${QT_VERSION_MAJOR}::Core
  Qt${QT_VERSION_MAJOR}::DBus
  Boost::unit_test_framework
)

add_test(NAME FirewalldManagerBoostTests COMMAND FirewalldManagerBoostTests)
