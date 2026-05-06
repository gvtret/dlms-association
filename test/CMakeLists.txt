if(DLMS_USE_SYSTEM_GTEST)
  find_package(GTest REQUIRED)
elseif(NOT TARGET GTest::gtest_main)
  include(FetchContent)
  FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  FetchContent_MakeAvailable(googletest)
endif()

add_executable(dlms_association_tests
  association/test_association_client.cpp
  association/test_association_c_api.cpp
  association/test_association_types.cpp)

target_link_libraries(dlms_association_tests
  PRIVATE
    dlms_association
    GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(dlms_association_tests)

add_executable(dlms_association_c_header_smoke
  association/test_association_c_header_smoke.c)

target_link_libraries(dlms_association_c_header_smoke
  PRIVATE
    dlms_association)

add_test(
  NAME AssociationCApi.CHeaderCompilesAsC
  COMMAND dlms_association_c_header_smoke)
