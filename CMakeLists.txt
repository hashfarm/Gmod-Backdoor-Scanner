cmake_minimum_required(VERSION 3.16)
project(BD-Scan CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

add_executable(bd-scan
  BD-Scan/BD-Scan.cpp
  BD-Scan/ScanApplication.cpp
  BD-Scan/CommandLine.cpp
  BD-Scan/HtmlReport.cpp
  BD-Scan/SarifReport.cpp
)
target_include_directories(bd-scan PRIVATE BD-Scan)

add_executable(bd-scan-selfcheck BD-Scan/tests/selfcheck.cpp)
target_include_directories(bd-scan-selfcheck PRIVATE BD-Scan)

foreach(target bd-scan bd-scan-selfcheck)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Werror)
  endif()
endforeach()

find_package(Threads REQUIRED)
target_link_libraries(bd-scan PRIVATE Threads::Threads)
target_link_libraries(bd-scan-selfcheck PRIVATE Threads::Threads)

# GCC before 9 keeps std::filesystem in a separate library.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9.0)
  target_link_libraries(bd-scan PRIVATE stdc++fs)
  target_link_libraries(bd-scan-selfcheck PRIVATE stdc++fs)
endif()

set(BD_SCAN_RULE_FILES
  BD-Scan/lua_patterns.txt
  BD-Scan/binary_patterns.txt
  BD-Scan/data_patterns.txt
  BD-Scan/module_patterns.txt
  BD-Scan/composite_rules.txt
  BD-Scan/known_hashes.txt
  BD-Scan/whitelist.txt
)

add_custom_target(bd-scan-rules ALL DEPENDS bd-scan)

foreach(rule ${BD_SCAN_RULE_FILES})
  get_filename_component(rule_name ${rule} NAME)
  foreach(target bd-scan bd-scan-rules)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${CMAKE_CURRENT_SOURCE_DIR}/${rule}
        $<TARGET_FILE_DIR:bd-scan>/${rule_name})
  endforeach()
endforeach()

enable_testing()
add_test(NAME selfcheck
         COMMAND bd-scan-selfcheck ${CMAKE_CURRENT_SOURCE_DIR}/BD-Scan)

set_tests_properties(selfcheck PROPERTIES TIMEOUT 60)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
  add_test(NAME integration
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/BD-Scan/tests/integration.py
      $<TARGET_FILE:bd-scan> ${CMAKE_CURRENT_SOURCE_DIR}/BD-Scan)
  set_tests_properties(integration PROPERTIES TIMEOUT 120)

  add_test(NAME evasion
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/BD-Scan/tests/evasion.py
      $<TARGET_FILE:bd-scan> ${CMAKE_CURRENT_SOURCE_DIR}/BD-Scan)
  set_tests_properties(evasion PROPERTIES TIMEOUT 120)
endif()

install(TARGETS bd-scan RUNTIME DESTINATION bin)
install(FILES ${BD_SCAN_RULE_FILES} DESTINATION bin)
