cmake_minimum_required(VERSION 3.12)

project(
    rohc_p2p
        LANGUAGES CXX
)

add_executable(traffic_compressor main.cpp)

set_target_properties(
    traffic_compressor 
        PROPERTIES
            CXX_STANDARD 17
            CXX_EXTENSIONS OFF
            CXX_STANDARD_REQUIRED ON
            COMPILE_OPTIONS "-Wpedantic;-Wall;-Wextra;-Werror;"
            LINK_LIBRARIES "${CMAKE_THREAD_LIBS_INIT};netfilter_queue"
            BUILD_RPATH "${CMAKE_BINARY_DIR}/lib"
            INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib"
)

install(
    TARGETS traffic_compressor 
        RUNTIME DESTINATION bin
        COMPONENT prog
)
