# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

# - Get the project version from a Git archive
#
# Archives don't contain the Git history, but `git archive` replaces the
# placeholder in `tools/cmake/archive_version` with the output of
# `git describe`. The placeholder remains if the sources were copied any other
# way, in which case the version doesn't change.
function(get_version_from_archive)
    file(STRINGS ${CMAKE_SOURCE_DIR}/tools/cmake/archive_version ARCHIVE_VERSION)

    string(REGEX REPLACE "^v" "" CLEAN_TAG "${ARCHIVE_VERSION}")
    if (NOT CLEAN_TAG MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-[0-9]+-g([0-9a-f]+))?$")
        message(WARNING "Failed to get the archive's version, using default version ${PROJECT_VERSION}")
        return()
    endif ()

    set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1} PARENT_SCOPE)
    set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2} PARENT_SCOPE)
    set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3} PARENT_SCOPE)
    set(PROJECT_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}" PARENT_SCOPE)

    if (NOT "${CMAKE_MATCH_5}" STREQUAL "")
        set(PROJECT_VERSION_SUFFIX "-${CMAKE_MATCH_5}" PARENT_SCOPE)
    endif ()
endfunction()

function(get_version_from_git)
    find_package(Git)
    if (NOT Git_FOUND)
        message(WARNING "Failed to find git, using default version ${PROJECT_VERSION}")
        return()
    endif ()

    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_TAG
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GIT_RESULT
    )
    if (NOT GIT_RESULT EQUAL 0)
        message(WARNING "Failed to get git tag, using default version")
        return()
    endif ()

    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --short=7 HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_COMMIT_SHORT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GIT_RESULT
    )
    if (NOT GIT_RESULT EQUAL 0)
        message(WARNING "Failed to get short SHA, using default version")
        return()
    endif ()

    string(REGEX REPLACE "^v" "" CLEAN_TAG "${GIT_TAG}")
    if (CLEAN_TAG MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-.*)?$")
        set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
        set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})
        set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3})
        set(PROJECT_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}")
    else ()
        message(WARNING "Tag '${CLEAN_TAG}' does not match semver format, using default version")
        return()
    endif ()

    # Check if the HEAD commit is tagged
    execute_process(
        COMMAND ${GIT_EXECUTABLE} tag --points-at HEAD
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE COMMIT_TAGS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GIT_RESULT
    )
    if (NOT GIT_RESULT EQUAL 0)
        message(WARNING "Failed to check if HEAD is tagged, using default version")
        return()
    endif ()

    # Check if the repo is dirty
    execute_process(
        COMMAND ${GIT_EXECUTABLE} status --porcelain
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_STATUS
        OUTPUT_STRIP_TRAILING_WHITESPACE
        RESULT_VARIABLE GIT_RESULT
    )
    if (NOT GIT_RESULT EQUAL 0)
        message(WARNING "Failed to check if repo is dirty, using default version")
        set(${RESULT_VAR} "" PARENT_SCOPE)
        return()
    endif ()

    set(IS_TAGGED TRUE)
    if (COMMIT_TAGS STREQUAL "")
        set(IS_TAGGED FALSE)
    endif ()

    set(IS_DIRTY TRUE)
    if (GIT_STATUS STREQUAL "")
        set(IS_DIRTY FALSE)
    endif ()

    set(PROJECT_VERSION_SUFFIX "")
    if (IS_DIRTY)
        set(PROJECT_VERSION_SUFFIX "-${GIT_COMMIT_SHORT_HASH}*")
    elseif (NOT IS_TAGGED)
        set(PROJECT_VERSION_SUFFIX "-${GIT_COMMIT_SHORT_HASH}")
    endif ()

    # Return the result
    set(PROJECT_VERSION_MAJOR ${PROJECT_VERSION_MAJOR} PARENT_SCOPE)
    set(PROJECT_VERSION_MINOR ${PROJECT_VERSION_MINOR} PARENT_SCOPE)
    set(PROJECT_VERSION_PATCH ${PROJECT_VERSION_PATCH} PARENT_SCOPE)
    set(PROJECT_VERSION_SUFFIX ${PROJECT_VERSION_SUFFIX} PARENT_SCOPE)
    set(PROJECT_VERSION "${CMAKE_MATCH_1}.${CMAKE_MATCH_2}.${CMAKE_MATCH_3}" PARENT_SCOPE)
endfunction()
