add_subdirectory(Lib)

set(data_sources ${lib_sources} PARENT_SCOPE)

include_directories(${PROJECT_SOURCE_DIR}/src/polycubed/src/server/include/Resources/Data)