# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
<<<<<<< HEAD
CMAKE_SOURCE_DIR = /home/jazicate/SecureCryptoProject

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/jazicate/SecureCryptoProject/build
=======
CMAKE_SOURCE_DIR = "/home/jazicate/SecureCryptoProject - Copy"

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = "/home/jazicate/SecureCryptoProject - Copy/build"
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21

# Include any dependencies generated for this target.
include CMakeFiles/TestProject.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/TestProject.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/TestProject.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/TestProject.dir/flags.make

CMakeFiles/TestProject.dir/tests/test.cpp.o: CMakeFiles/TestProject.dir/flags.make
<<<<<<< HEAD
CMakeFiles/TestProject.dir/tests/test.cpp.o: /home/jazicate/SecureCryptoProject/tests/test.cpp
CMakeFiles/TestProject.dir/tests/test.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jazicate/SecureCryptoProject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/TestProject.dir/tests/test.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/tests/test.cpp.o -MF CMakeFiles/TestProject.dir/tests/test.cpp.o.d -o CMakeFiles/TestProject.dir/tests/test.cpp.o -c /home/jazicate/SecureCryptoProject/tests/test.cpp

CMakeFiles/TestProject.dir/tests/test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/tests/test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jazicate/SecureCryptoProject/tests/test.cpp > CMakeFiles/TestProject.dir/tests/test.cpp.i

CMakeFiles/TestProject.dir/tests/test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/tests/test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jazicate/SecureCryptoProject/tests/test.cpp -o CMakeFiles/TestProject.dir/tests/test.cpp.s

CMakeFiles/TestProject.dir/src/encryptor.cpp.o: CMakeFiles/TestProject.dir/flags.make
CMakeFiles/TestProject.dir/src/encryptor.cpp.o: /home/jazicate/SecureCryptoProject/src/encryptor.cpp
CMakeFiles/TestProject.dir/src/encryptor.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jazicate/SecureCryptoProject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/TestProject.dir/src/encryptor.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/src/encryptor.cpp.o -MF CMakeFiles/TestProject.dir/src/encryptor.cpp.o.d -o CMakeFiles/TestProject.dir/src/encryptor.cpp.o -c /home/jazicate/SecureCryptoProject/src/encryptor.cpp

CMakeFiles/TestProject.dir/src/encryptor.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/src/encryptor.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jazicate/SecureCryptoProject/src/encryptor.cpp > CMakeFiles/TestProject.dir/src/encryptor.cpp.i

CMakeFiles/TestProject.dir/src/encryptor.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/src/encryptor.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jazicate/SecureCryptoProject/src/encryptor.cpp -o CMakeFiles/TestProject.dir/src/encryptor.cpp.s

CMakeFiles/TestProject.dir/src/decryptor.cpp.o: CMakeFiles/TestProject.dir/flags.make
CMakeFiles/TestProject.dir/src/decryptor.cpp.o: /home/jazicate/SecureCryptoProject/src/decryptor.cpp
CMakeFiles/TestProject.dir/src/decryptor.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jazicate/SecureCryptoProject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/TestProject.dir/src/decryptor.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/src/decryptor.cpp.o -MF CMakeFiles/TestProject.dir/src/decryptor.cpp.o.d -o CMakeFiles/TestProject.dir/src/decryptor.cpp.o -c /home/jazicate/SecureCryptoProject/src/decryptor.cpp

CMakeFiles/TestProject.dir/src/decryptor.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/src/decryptor.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jazicate/SecureCryptoProject/src/decryptor.cpp > CMakeFiles/TestProject.dir/src/decryptor.cpp.i

CMakeFiles/TestProject.dir/src/decryptor.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/src/decryptor.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jazicate/SecureCryptoProject/src/decryptor.cpp -o CMakeFiles/TestProject.dir/src/decryptor.cpp.s

CMakeFiles/TestProject.dir/src/keymanager.cpp.o: CMakeFiles/TestProject.dir/flags.make
CMakeFiles/TestProject.dir/src/keymanager.cpp.o: /home/jazicate/SecureCryptoProject/src/keymanager.cpp
CMakeFiles/TestProject.dir/src/keymanager.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jazicate/SecureCryptoProject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/TestProject.dir/src/keymanager.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/src/keymanager.cpp.o -MF CMakeFiles/TestProject.dir/src/keymanager.cpp.o.d -o CMakeFiles/TestProject.dir/src/keymanager.cpp.o -c /home/jazicate/SecureCryptoProject/src/keymanager.cpp

CMakeFiles/TestProject.dir/src/keymanager.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/src/keymanager.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jazicate/SecureCryptoProject/src/keymanager.cpp > CMakeFiles/TestProject.dir/src/keymanager.cpp.i

CMakeFiles/TestProject.dir/src/keymanager.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/src/keymanager.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jazicate/SecureCryptoProject/src/keymanager.cpp -o CMakeFiles/TestProject.dir/src/keymanager.cpp.s

CMakeFiles/TestProject.dir/src/logger.cpp.o: CMakeFiles/TestProject.dir/flags.make
CMakeFiles/TestProject.dir/src/logger.cpp.o: /home/jazicate/SecureCryptoProject/src/logger.cpp
CMakeFiles/TestProject.dir/src/logger.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/home/jazicate/SecureCryptoProject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object CMakeFiles/TestProject.dir/src/logger.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/src/logger.cpp.o -MF CMakeFiles/TestProject.dir/src/logger.cpp.o.d -o CMakeFiles/TestProject.dir/src/logger.cpp.o -c /home/jazicate/SecureCryptoProject/src/logger.cpp

CMakeFiles/TestProject.dir/src/logger.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/src/logger.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/jazicate/SecureCryptoProject/src/logger.cpp > CMakeFiles/TestProject.dir/src/logger.cpp.i

CMakeFiles/TestProject.dir/src/logger.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/src/logger.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/jazicate/SecureCryptoProject/src/logger.cpp -o CMakeFiles/TestProject.dir/src/logger.cpp.s
=======
CMakeFiles/TestProject.dir/tests/test.cpp.o: /home/jazicate/SecureCryptoProject\ -\ Copy/tests/test.cpp
CMakeFiles/TestProject.dir/tests/test.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="/home/jazicate/SecureCryptoProject - Copy/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/TestProject.dir/tests/test.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/tests/test.cpp.o -MF CMakeFiles/TestProject.dir/tests/test.cpp.o.d -o CMakeFiles/TestProject.dir/tests/test.cpp.o -c "/home/jazicate/SecureCryptoProject - Copy/tests/test.cpp"

CMakeFiles/TestProject.dir/tests/test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/tests/test.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/home/jazicate/SecureCryptoProject - Copy/tests/test.cpp" > CMakeFiles/TestProject.dir/tests/test.cpp.i

CMakeFiles/TestProject.dir/tests/test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/tests/test.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/home/jazicate/SecureCryptoProject - Copy/tests/test.cpp" -o CMakeFiles/TestProject.dir/tests/test.cpp.s

CMakeFiles/TestProject.dir/src/encryptor.cpp.o: CMakeFiles/TestProject.dir/flags.make
CMakeFiles/TestProject.dir/src/encryptor.cpp.o: /home/jazicate/SecureCryptoProject\ -\ Copy/src/encryptor.cpp
CMakeFiles/TestProject.dir/src/encryptor.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="/home/jazicate/SecureCryptoProject - Copy/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/TestProject.dir/src/encryptor.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/src/encryptor.cpp.o -MF CMakeFiles/TestProject.dir/src/encryptor.cpp.o.d -o CMakeFiles/TestProject.dir/src/encryptor.cpp.o -c "/home/jazicate/SecureCryptoProject - Copy/src/encryptor.cpp"

CMakeFiles/TestProject.dir/src/encryptor.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/src/encryptor.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/home/jazicate/SecureCryptoProject - Copy/src/encryptor.cpp" > CMakeFiles/TestProject.dir/src/encryptor.cpp.i

CMakeFiles/TestProject.dir/src/encryptor.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/src/encryptor.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/home/jazicate/SecureCryptoProject - Copy/src/encryptor.cpp" -o CMakeFiles/TestProject.dir/src/encryptor.cpp.s

CMakeFiles/TestProject.dir/src/decryptor.cpp.o: CMakeFiles/TestProject.dir/flags.make
CMakeFiles/TestProject.dir/src/decryptor.cpp.o: /home/jazicate/SecureCryptoProject\ -\ Copy/src/decryptor.cpp
CMakeFiles/TestProject.dir/src/decryptor.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="/home/jazicate/SecureCryptoProject - Copy/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object CMakeFiles/TestProject.dir/src/decryptor.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/src/decryptor.cpp.o -MF CMakeFiles/TestProject.dir/src/decryptor.cpp.o.d -o CMakeFiles/TestProject.dir/src/decryptor.cpp.o -c "/home/jazicate/SecureCryptoProject - Copy/src/decryptor.cpp"

CMakeFiles/TestProject.dir/src/decryptor.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/src/decryptor.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/home/jazicate/SecureCryptoProject - Copy/src/decryptor.cpp" > CMakeFiles/TestProject.dir/src/decryptor.cpp.i

CMakeFiles/TestProject.dir/src/decryptor.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/src/decryptor.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/home/jazicate/SecureCryptoProject - Copy/src/decryptor.cpp" -o CMakeFiles/TestProject.dir/src/decryptor.cpp.s

CMakeFiles/TestProject.dir/src/keymanager.cpp.o: CMakeFiles/TestProject.dir/flags.make
CMakeFiles/TestProject.dir/src/keymanager.cpp.o: /home/jazicate/SecureCryptoProject\ -\ Copy/src/keymanager.cpp
CMakeFiles/TestProject.dir/src/keymanager.cpp.o: CMakeFiles/TestProject.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir="/home/jazicate/SecureCryptoProject - Copy/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object CMakeFiles/TestProject.dir/src/keymanager.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/TestProject.dir/src/keymanager.cpp.o -MF CMakeFiles/TestProject.dir/src/keymanager.cpp.o.d -o CMakeFiles/TestProject.dir/src/keymanager.cpp.o -c "/home/jazicate/SecureCryptoProject - Copy/src/keymanager.cpp"

CMakeFiles/TestProject.dir/src/keymanager.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/TestProject.dir/src/keymanager.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E "/home/jazicate/SecureCryptoProject - Copy/src/keymanager.cpp" > CMakeFiles/TestProject.dir/src/keymanager.cpp.i

CMakeFiles/TestProject.dir/src/keymanager.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/TestProject.dir/src/keymanager.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S "/home/jazicate/SecureCryptoProject - Copy/src/keymanager.cpp" -o CMakeFiles/TestProject.dir/src/keymanager.cpp.s
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21

# Object files for target TestProject
TestProject_OBJECTS = \
"CMakeFiles/TestProject.dir/tests/test.cpp.o" \
"CMakeFiles/TestProject.dir/src/encryptor.cpp.o" \
"CMakeFiles/TestProject.dir/src/decryptor.cpp.o" \
<<<<<<< HEAD
"CMakeFiles/TestProject.dir/src/keymanager.cpp.o" \
"CMakeFiles/TestProject.dir/src/logger.cpp.o"
=======
"CMakeFiles/TestProject.dir/src/keymanager.cpp.o"
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21

# External object files for target TestProject
TestProject_EXTERNAL_OBJECTS =

<<<<<<< HEAD
/home/jazicate/SecureCryptoProject/bin/TestProject: CMakeFiles/TestProject.dir/tests/test.cpp.o
/home/jazicate/SecureCryptoProject/bin/TestProject: CMakeFiles/TestProject.dir/src/encryptor.cpp.o
/home/jazicate/SecureCryptoProject/bin/TestProject: CMakeFiles/TestProject.dir/src/decryptor.cpp.o
/home/jazicate/SecureCryptoProject/bin/TestProject: CMakeFiles/TestProject.dir/src/keymanager.cpp.o
/home/jazicate/SecureCryptoProject/bin/TestProject: CMakeFiles/TestProject.dir/src/logger.cpp.o
/home/jazicate/SecureCryptoProject/bin/TestProject: CMakeFiles/TestProject.dir/build.make
/home/jazicate/SecureCryptoProject/bin/TestProject: /usr/lib/x86_64-linux-gnu/libcrypto.so
/home/jazicate/SecureCryptoProject/bin/TestProject: CMakeFiles/TestProject.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/home/jazicate/SecureCryptoProject/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking CXX executable /home/jazicate/SecureCryptoProject/bin/TestProject"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TestProject.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TestProject.dir/build: /home/jazicate/SecureCryptoProject/bin/TestProject
=======
/home/jazicate/SecureCryptoProject\ -\ Copy/bin/TestProject: CMakeFiles/TestProject.dir/tests/test.cpp.o
/home/jazicate/SecureCryptoProject\ -\ Copy/bin/TestProject: CMakeFiles/TestProject.dir/src/encryptor.cpp.o
/home/jazicate/SecureCryptoProject\ -\ Copy/bin/TestProject: CMakeFiles/TestProject.dir/src/decryptor.cpp.o
/home/jazicate/SecureCryptoProject\ -\ Copy/bin/TestProject: CMakeFiles/TestProject.dir/src/keymanager.cpp.o
/home/jazicate/SecureCryptoProject\ -\ Copy/bin/TestProject: CMakeFiles/TestProject.dir/build.make
/home/jazicate/SecureCryptoProject\ -\ Copy/bin/TestProject: /usr/lib/x86_64-linux-gnu/libcrypto.so
/home/jazicate/SecureCryptoProject\ -\ Copy/bin/TestProject: CMakeFiles/TestProject.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir="/home/jazicate/SecureCryptoProject - Copy/build/CMakeFiles" --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX executable \"/home/jazicate/SecureCryptoProject - Copy/bin/TestProject\""
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/TestProject.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/TestProject.dir/build: /home/jazicate/SecureCryptoProject\ -\ Copy/bin/TestProject
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
.PHONY : CMakeFiles/TestProject.dir/build

CMakeFiles/TestProject.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/TestProject.dir/cmake_clean.cmake
.PHONY : CMakeFiles/TestProject.dir/clean

CMakeFiles/TestProject.dir/depend:
<<<<<<< HEAD
	cd /home/jazicate/SecureCryptoProject/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/jazicate/SecureCryptoProject /home/jazicate/SecureCryptoProject /home/jazicate/SecureCryptoProject/build /home/jazicate/SecureCryptoProject/build /home/jazicate/SecureCryptoProject/build/CMakeFiles/TestProject.dir/DependInfo.cmake "--color=$(COLOR)"
=======
	cd "/home/jazicate/SecureCryptoProject - Copy/build" && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" "/home/jazicate/SecureCryptoProject - Copy" "/home/jazicate/SecureCryptoProject - Copy" "/home/jazicate/SecureCryptoProject - Copy/build" "/home/jazicate/SecureCryptoProject - Copy/build" "/home/jazicate/SecureCryptoProject - Copy/build/CMakeFiles/TestProject.dir/DependInfo.cmake" "--color=$(COLOR)"
>>>>>>> 84501201364922e8ffda41cbc00677c708e74c21
.PHONY : CMakeFiles/TestProject.dir/depend

