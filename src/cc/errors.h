#ifndef EMPTCP_ERRORS_H
#define EMPTCP_ERRORS_H

#include<cstring>
#include<cerrno> 
#include<exception> 
#include<system_error>
#include<string>
#include<sstream>

namespace errors {

//project based exception
class Exception : public std::exception {
    using std::exception::exception;
};

class InvalidFrame : public Exception {
    using Exception::Exception;
};

class KeyboardInterrupt : public Exception {
    using Exception::Exception;
};

class ExceptionCode : public Exception {
public:
    ExceptionCode(const std::string &hint, int code) : _err(code) {
        std::stringstream ss;
        ss << hint << " err: " << _err;
        _msg = ss.str();
    }
    
    virtual const char* what() const noexcept override {
        return _msg.data();
    }
private: 
    int _err;
    std::string _msg; 
};

inline std::system_error make_system_error(int e = errno) {
    return std::system_error(e,std::system_category());
}

inline std::system_error make_system_error(const char* what_msg, int e = errno) {
    return std::system_error(e,std::system_category(), what_msg);
}

}

#endif 
