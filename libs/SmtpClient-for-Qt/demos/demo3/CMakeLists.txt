add_executable(demo3 demo3.cpp)

target_link_libraries(demo3 PRIVATE
  Qt${QT_VERSION_MAJOR}::Core
  ${LIBRARY_TARGET_NAME})
