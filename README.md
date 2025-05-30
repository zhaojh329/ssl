# Usage

Add ssl subdirectory in your repo.

```
git submodule add https://github.com/zhaojh329/ssl.git
```

Add these code in `the CMakeLists.txt` of your repo.
```
add_subdirectory(ssl)

if(SSL_SUPPORT)
    target_link_libraries(xx PRIVATE ${SSL_TARGET})
endif()
```

Include `ssl.h` in your source code.
```
 #ifdef SSL_SUPPORT
 #include "ssl/ssl.h"
 #endif
```

# CMake variables
```
// SSL support
SSL_SUPPORT:BOOL

// Force select MbedTLS(PolarSSL)
USE_MBEDTLS:BOOL

// Force select OpenSSL
USE_OPENSSL:BOOL

// Force select WolfSSL(CyaSSL)
USE_WOLFSSL:BOOL
```
