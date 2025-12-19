find_package(Qt${QT_VERSION_MAJOR} COMPONENTS Test REQUIRED)

add_executable(test
  main.cpp
  connectiontest.cpp)

target_link_libraries(test PRIVATE
  Qt${QT_VERSION_MAJOR}::Core
  Qt${QT_VERSION_MAJOR}::Test
  ${LIBRARY_TARGET_NAME})
