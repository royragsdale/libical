
include_directories(
  ${CMAKE_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/src
  ${CMAKE_BINARY_DIR}/src
  ${CMAKE_SOURCE_DIR}/src/libical
  ${CMAKE_BINARY_DIR}/src/libical
)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_CURRENT_BINARY_DIR})

########### next target ###############

set(FUZZ_HARNESS "libical-fuzz")
add_executable(${FUZZ_HARNESS} libical_fuzz.cc)
target_link_libraries(${FUZZ_HARNESS} ical)
set(CMAKE_EXE_LINKER_FLAGS "-fsanitize=fuzzer")
