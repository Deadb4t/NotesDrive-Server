Cmake_minimum_required(VERSION 3.0)

project(notesdrive-server)

add_executable(notesdrive-server hashing/sha3-hashing.cpp filemanager.cpp clientmanager.cpp server.cpp encryption/rsa-encryption.cpp encryption/utils-encryption.cpp authentication/yubikeyauth.cpp main.cpp)

install(TARGETS notesdrive-server RUNTIME DESTINATION bin)

FIND_PACKAGE(Boost 1.55 COMPONENTS system thread chrono filesystem random REQUIRED)
IF (Boost_FOUND)
    INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})
    ADD_DEFINITIONS( "-DHAS_BOOST" )
    LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})
    target_link_libraries (notesdrive-server ${Boost_LIBRARIES} -lpthread ${Boost_LIBRARIES})
    MESSAGE(STATUS "** Boost Include: ${Boost_INCLUDE_DIR}")
    MESSAGE(STATUS "** Boost Libraries: ${Boost_LIBRARIES}")
ENDIF(Boost_FOUND)

FIND_PACKAGE(CryptoPP REQUIRED)
IF (CRYPTOPP_FOUND)
    INCLUDE_DIRECTORIES(${CRYPTOPP_INCLUDE_DIRS} /usr/include/cryptopp)
    LINK_DIRECTORIES(${CRYPTOPP_LIBRARIES})
    target_link_libraries(notesdrive-server ${CRYPTOPP_LIBRARIES})
    MESSAGE(STATUS "** CryptoPP Include: ${CRYPTOPP_INCLUDE_DIRS}:/usr/include/cryptopp")
    MESSAGE(STATUS "** CryptoPP Libraries: ${CRYPTOPP_LIBRARIES}")
ENDIF(CRYPTOPP_FOUND)