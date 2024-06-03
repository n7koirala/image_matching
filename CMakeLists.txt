cmake_minimum_required(VERSION 3.10)
project(ImageMatching VERSION 1.0)

# Set the C++ standard to C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add definitions and compiler options
add_definitions(-DOPENFHE_VERSION=1.0.3 -DMATHBACKEND=4)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-parentheses -O3 -fopenmp")

# Include directories
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    /usr/local/include/openfhe/core
    /usr/local/include/openfhe/pke
    /usr/local/include/openfhe/
)

# Source files
add_executable(ImageMatching
    src/main.cpp
    src/receiver.cpp
    src/receiver_secure.cpp
    src/sender.cpp
    src/openFHE_wrapper.cpp
    src/vector_utils.cpp
)

# Specify the path to the OpenFHE libraries
link_directories(/usr/local/lib)

# Link the OpenFHE libraries along with the C++ filesystem library
target_link_libraries(ImageMatching
    ${CMAKE_DL_LIBS}
    stdc++fs
    OPENFHEcore
    OPENFHEpke
    OPENFHEpke_static
    OPENFHEcore_static
)