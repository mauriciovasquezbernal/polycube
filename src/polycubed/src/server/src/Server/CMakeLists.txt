set(server_sources
        ${CMAKE_CURRENT_LIST_DIR}/Base64.cpp
        ${CMAKE_CURRENT_LIST_DIR}/ResponseGenerator.cpp
        PARENT_SCOPE)

include_directories(${PROJECT_SOURCE_DIR}/src/polycubed/src/server/include/Server)