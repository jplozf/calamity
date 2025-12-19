add_executable(demo4 demo4.cpp)

target_link_libraries(demo4 PRIVATE
  Qt${QT_VERSION_MAJOR}::Core
  ${LIBRARY_TARGET_NAME})
