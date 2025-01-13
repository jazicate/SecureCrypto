# CMake generated Testfile for 
# Source directory: /home/jazicate/SecureCryptoProject
# Build directory: /home/jazicate/SecureCryptoProject/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(TestProject "/home/jazicate/SecureCryptoProject/bin/TestProject")
set_tests_properties(TestProject PROPERTIES  _BACKTRACE_TRIPLES "/home/jazicate/SecureCryptoProject/CMakeLists.txt;58;add_test;/home/jazicate/SecureCryptoProject/CMakeLists.txt;0;")
subdirs("_deps/catch2-build")
