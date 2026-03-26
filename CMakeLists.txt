cmake_minimum_required(VERSION 3.21)
set(CMAKE_POLICY_VERSION_MINIMUM 3.21)

set(PROJECT_NAME dns_resolver)
project(
    ${PROJECT_NAME}
	LANGUAGES    C ASM
	VERSION      0.0.1
    DESCRIPTION  "DNS Resolver"
	HOMEPAGE_URL "https://github.com/EngineersBox/dns-resolver"
)
# 0 = Debug, 3 = Release
set(COMPILE_OPTIMISATION_LEVEL 0)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -fno-omit-frame-pointer")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O${COMPILE_OPTIMISATION_LEVEL} -g -ggdb -gdwarf-4")
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fanalyzer")
# target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
# target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address)

# Include source content
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "src/*.[cs]")
file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "src/*.h")

set(INCLUDE_DIRS "")
foreach (_headerFile ${HEADERS})
	get_filename_component(_dir ${_headerFile} PATH)
	list(APPEND INCLUDE_DIRS ${_dir})
endforeach()
list(REMOVE_DUPLICATES INCLUDE_DIRS)
message("Include dirs:")
foreach (_include_dir ${INCLUDE_DIRS})
	message("- ${_include_dir}")
endforeach()

# Mark executable
add_executable(${PROJECT_NAME} ${SOURCES})
target_include_directories(${PROJECT_NAME} PUBLIC ${INCLUDE_DIRS})
target_compile_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
target_link_options(${PROJECT_NAME} PRIVATE -fsanitize=address)
