add_executable(demo1 demo1.cpp)

target_link_libraries(demo1 PRIVATE
  Qt${QT_VERSION_MAJOR}::Core
  ${LIBRARY_TARGET_NAME})
