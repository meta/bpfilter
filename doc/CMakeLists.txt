# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2023 Meta Platforms, Inc. and affiliates.

#[[
	Generate bpfilter's documentation

	The documentation is generated using:
	- Doxygen: parse the source files for Doxygen comments and generate XML
	  files containing the technical documentation.
	- Breathe: Sphinx plugin to easily integrate Doxygen documentation into
	  a Sphinx website.
	- Sphinx: generate the documentation website based on source files in
	  reStructuredText format and Doxygen/Breathe technical documentation.

	Source files on which Doxygen depends uses `GLOB_RECURSE`, which is usually
	frowned upon: source files will be discovered during CMake's generation
	step, so new files will be ignored until CMake runs, which can be confusing.
	However, those source files are manually added to their respective
	CMakeLists.txt, requiring developers to run CMake anyway. Using
	`GLOB_RECURSE` here ensures that the source files don't need to be added
	to multiple CMakeLists.txt, making our lives easier.

	Warnings emitted by Doxygen during the XML generation or Sphinx during the
	HTML generation will be treated as errors. Those warnings are useful as
	they usually refer to an invalid Doxygen syntax, it's a quick fix that helps
	to increase the documentation's quality.

	Doxygen's configuration file is version-specific. The approach taken here is
	to use Doxygen to generate the default configuration in the build folder,
	then include this default version in the project's Doxyfile and override
	relevant settings.


	## About the benchmarks and coverage reports

	The benchmarks and coverage reports are generated from the benchmarks and
	coverage results, into `html/external/$TYPE`. Both custom commands behave
	similarly; the coverage report is described below as an example.

	The main documentation generation will create an empty placeholder report,
	because if no coverage data is available, no real coverage report will be
	generated. However, the main documentation generation target doesn't depend
	on the coverage report, as we don't want to regenerate the complete
	documentation if only the coverage report must be updated (we generate the
	main documentation from scratch every time, because Sphinx doesn't properly
	handle incremental builds).

	Hence, we need to generate the coverage report **if** coverage data is
	available, while keeping the placeholder report if we try to generate
	the report with no coverage data available (weak dependency).

	To achieve these requirements (which also apply to the benchmarks report),
	CMake's DEPFILE option is used for the coverage report generation: by
	default, the dependency file only depends on the main documentation's
	`index.html`. When the coverage data is gathered, the dependency file
	is updated to include the generated coverage report's `index.html`.
	Because of this new dependency, generating the documentation (`make doc`)
	will copy the HTML report into the documentation tree.

	This complex mechanism ensures:
	- genhtml is looked for and used only when the coverage data is gathered
	  from the build directory, not from the documentation's CMakeLists.txt.
	- The coverage report is copied into the documentation tree only if
	  it has been updated (`make coverage` was run).
	- A default coverage report placeholder is used if no coverage report
	  has been generated yet.
#]]

find_package(Doxygen REQUIRED)
find_program(SPHINX_BIN sphinx-build REQUIRED)

file(GLOB_RECURSE bf_srcs
	${CMAKE_SOURCE_DIR}/src/*.h 			${CMAKE_SOURCE_DIR}/src/*.c
	${CMAKE_SOURCE_DIR}/tests/harness/*.h	${CMAKE_SOURCE_DIR}/tests/harness/*.c
)

# Remove src/external/.* files from the list of sources
list(FILTER bf_srcs EXCLUDE REGEX "${CMAKE_SOURCE_DIR}/src/external/.*")

set(doc_srcs
	${CMAKE_CURRENT_SOURCE_DIR}/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/bfcli.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/tutorials/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/tutorials/first-chain.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/how-to/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/how-to/install.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/how-to/apply-ruleset.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/how-to/block-addresses.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/how-to/update-chain.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/how-to/update-blocklist.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/how-to/inspect.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/how-to/remove-chain.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/reference/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/reference/bfcli.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/reference/ruleset.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/reference/chains.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/reference/hooks.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/reference/rules.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/reference/matchers.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/reference/sets.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/explanation/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/explanation/rule-evaluation.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/explanation/hooks.rst
	${CMAKE_CURRENT_SOURCE_DIR}/usage/explanation/lifecycle.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/build.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/contributing.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/generation.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/memory.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/packets_processing.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/release.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/style.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/tests.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/modules/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/modules/core/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/modules/core/locking.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/modules/helpers.rst
	${CMAKE_CURRENT_SOURCE_DIR}/developers/modules/libbpfilter/libbpfilter.rst
	${CMAKE_CURRENT_SOURCE_DIR}/external/benchmarks/index.rst
	${CMAKE_CURRENT_SOURCE_DIR}/external/coverage/index.rst
)

configure_file(Doxyfile.in Doxyfile)
configure_file(conf.py.in conf.py)

add_custom_command(
	COMMAND Doxygen::doxygen -s -g ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.base >/dev/null
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.base
	COMMENT "Generating Doxyfile.base configuration"
)

add_custom_command(
	COMMAND Doxygen::doxygen ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
		${CMAKE_CURRENT_BINARY_DIR}/Doxyfile.base
		${bf_srcs}
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/xml/index.xml
	COMMENT "Generating Doxygen XML documentation"
)

add_custom_command(
	COMMAND
		${CMAKE_COMMAND}
			-E copy_directory_if_different
			${CMAKE_CURRENT_SOURCE_DIR}/_static
			${CMAKE_CURRENT_BINARY_DIR}/_static
	COMMAND
		${CMAKE_COMMAND}
			-E copy_directory_if_different
			${CMAKE_CURRENT_SOURCE_DIR}/_templates
			${CMAKE_CURRENT_BINARY_DIR}/_templates
	COMMAND
		${SPHINX_BIN}
			-E				# Ensure the Doxygen changes are accounted for
			-W 				# Return non-zero if a warning is triggered...
			--keep-going	# ... but don't stop as soon as there is a warning.
			-q				# Quiet.
			--jobs auto		# Use multiple cores.
			-c ${CMAKE_CURRENT_BINARY_DIR}
			${CMAKE_CURRENT_SOURCE_DIR}
			${CMAKE_CURRENT_BINARY_DIR}/html
			${doc_srcs}
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/conf.py
		${CMAKE_CURRENT_BINARY_DIR}/xml/index.xml
		${doc_srcs}
	OUTPUT
		${CMAKE_CURRENT_BINARY_DIR}/html/index.html
	COMMENT "Generating the documentation"
)

file(WRITE ${CMAKE_BINARY_DIR}/.benchmarks_report.d
    "${CMAKE_CURRENT_BINARY_DIR}/html/external/benchmarks/index.html: \
		${CMAKE_CURRENT_BINARY_DIR}/html/index.html"
)

file(WRITE ${CMAKE_BINARY_DIR}/.benchmarks_report.d.full
    "${CMAKE_CURRENT_BINARY_DIR}/html/external/benchmarks/index.html: \
		${CMAKE_CURRENT_BINARY_DIR}/html/index.html \
		${CMAKE_BINARY_DIR}/benchmarks/index.html"
)

add_custom_command(
	COMMAND
		bash -c "if [ -f ${CMAKE_BINARY_DIR}/benchmarks/index.html ]; then \
			${CMAKE_COMMAND} \
				-E copy_if_different \
				${CMAKE_BINARY_DIR}/benchmarks/index.html \
				${CMAKE_CURRENT_BINARY_DIR}/html/external/benchmarks/index.html; \
		fi"
	COMMAND
		${CMAKE_COMMAND}
			-E touch
			${CMAKE_CURRENT_BINARY_DIR}/html/external/benchmarks/index.html
	DEPFILE ${CMAKE_BINARY_DIR}/.benchmarks_report.d
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/html/external/benchmarks/index.html
	COMMENT "Generate the benchmarks summary"
	VERBATIM
)

file(WRITE ${CMAKE_BINARY_DIR}/.coverage_report.d
    "${CMAKE_CURRENT_BINARY_DIR}/html/external/coverage/index.html: \
		${CMAKE_CURRENT_BINARY_DIR}/html/index.html"
)

file(WRITE ${CMAKE_BINARY_DIR}/.coverage_report.d.full
    "${CMAKE_CURRENT_BINARY_DIR}/html/external/coverage/index.html: \
		${CMAKE_CURRENT_BINARY_DIR}/html/index.html \
		${CMAKE_BINARY_DIR}/coverage/index.html"
)

add_custom_command(
	COMMAND
		bash -c "if [ -d ${CMAKE_BINARY_DIR}/coverage ]; then \
			${CMAKE_COMMAND} \
				-E copy_directory_if_different \
				${CMAKE_BINARY_DIR}/coverage \
				${CMAKE_CURRENT_BINARY_DIR}/html/external/coverage; \
		fi"
	COMMAND
		${CMAKE_COMMAND}
			-E touch
			${CMAKE_CURRENT_BINARY_DIR}/html/external/coverage/index.html
	DEPFILE ${CMAKE_BINARY_DIR}/.coverage_report.d
	OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/html/external/coverage/index.html
	COMMENT "Generate the coverage report"
	VERBATIM
)

add_custom_target(doc
	DEPENDS
		${CMAKE_CURRENT_BINARY_DIR}/html/index.html
		${CMAKE_CURRENT_BINARY_DIR}/html/external/benchmarks/index.html
		${CMAKE_CURRENT_BINARY_DIR}/html/external/coverage/index.html
)
