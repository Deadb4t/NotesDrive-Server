project(notesdrive-server)

add_executable(notesdrive-server main.cpp)

install(TARGETS notesdrive-server RUNTIME DESTINATION bin)
