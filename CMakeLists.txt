cmake_minimum_required(VERSION 3.16)

project(dlms_association
  VERSION 0.1.0
  LANGUAGES C CXX)

option(DLMS_BUILD_TESTS "Build GoogleTest tests" ON)
option(DLMS_USE_SYSTEM_GTEST "Use system-installed GoogleTest" OFF)

add_library(dlms_association
  src/association/association_client.cpp
  src/association/association_c_api.cpp
  src/association/association_status.cpp
  src/association/association_types.cpp)

if(NOT TARGET dlms_profile AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../dlms-profile/CMakeLists.txt")
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../dlms-profile" "${CMAKE_CURRENT_BINARY_DIR}/_deps/dlms-profile")
endif()

if(NOT TARGET dlms_apdu AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../dlms-apdu/CMakeLists.txt")
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../dlms-apdu" "${CMAKE_CURRENT_BINARY_DIR}/_deps/dlms-apdu")
endif()

target_compile_features(dlms_association PUBLIC cxx_std_11)

target_include_directories(dlms_association
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_link_libraries(dlms_association
  PUBLIC
    dlms_profile
    dlms_apdu)

set(DLMS_ASSOCIATION_HAS_API ON CACHE INTERNAL
  "dlms-association exposes the association client API")

if(DLMS_BUILD_TESTS)
  enable_testing()
  add_subdirectory(test)
endif()
