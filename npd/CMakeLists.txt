cmake_minimum_required(VERSION 3.21)
project(npd LANGUAGES C VERSION 0.1.0)
set(C_STANDARD 11)

add_executable(npd npd.c npd_f.c npd_ipv4.c)

# z -> zlib
target_link_libraries(npd z)
target_compile_options(npd PRIVATE -Wall)
