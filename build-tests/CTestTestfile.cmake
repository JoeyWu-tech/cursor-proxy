# CMake generated Testfile for 
# Source directory: E:/ProjectCode/C++Code/antigravity-proxy
# Build directory: E:/ProjectCode/C++Code/antigravity-proxy/build-tests
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
if(CTEST_CONFIGURATION_TYPE MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
  add_test(antigravity_tests "E:/ProjectCode/C++Code/antigravity-proxy/build-tests/Debug/antigravity_tests.exe")
  set_tests_properties(antigravity_tests PROPERTIES  _BACKTRACE_TRIPLES "E:/ProjectCode/C++Code/antigravity-proxy/CMakeLists.txt;138;add_test;E:/ProjectCode/C++Code/antigravity-proxy/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
  add_test(antigravity_tests "E:/ProjectCode/C++Code/antigravity-proxy/build-tests/Release/antigravity_tests.exe")
  set_tests_properties(antigravity_tests PROPERTIES  _BACKTRACE_TRIPLES "E:/ProjectCode/C++Code/antigravity-proxy/CMakeLists.txt;138;add_test;E:/ProjectCode/C++Code/antigravity-proxy/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
  add_test(antigravity_tests "E:/ProjectCode/C++Code/antigravity-proxy/build-tests/MinSizeRel/antigravity_tests.exe")
  set_tests_properties(antigravity_tests PROPERTIES  _BACKTRACE_TRIPLES "E:/ProjectCode/C++Code/antigravity-proxy/CMakeLists.txt;138;add_test;E:/ProjectCode/C++Code/antigravity-proxy/CMakeLists.txt;0;")
elseif(CTEST_CONFIGURATION_TYPE MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
  add_test(antigravity_tests "E:/ProjectCode/C++Code/antigravity-proxy/build-tests/RelWithDebInfo/antigravity_tests.exe")
  set_tests_properties(antigravity_tests PROPERTIES  _BACKTRACE_TRIPLES "E:/ProjectCode/C++Code/antigravity-proxy/CMakeLists.txt;138;add_test;E:/ProjectCode/C++Code/antigravity-proxy/CMakeLists.txt;0;")
else()
  add_test(antigravity_tests NOT_AVAILABLE)
endif()
