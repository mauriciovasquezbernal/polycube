add_subdirectory(Parser)
add_subdirectory(Resources)
add_subdirectory(Server)
add_subdirectory(Types)
add_subdirectory(Validators)

set(sources ${resources_sources} ${validators_sources} ${types_sources} ${server_sources} ${parser_sources} PARENT_SCOPE)
set(includes ${parser_includes} PARENT_SCOPE)