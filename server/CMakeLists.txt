cmake_minimum_required(VERSION 3.21)
project(npd LANGUAGES C VERSION 0.1.0)
set(C_STANDARD 11)

add_executable(uvs server.c)
target_link_libraries(uvs uv)
target_compile_options(uvs PRIVATE -fno-strict-aliasing -Wall)
