package com.ignited.login;

public class WrongIdPasswordException extends LoginFailException {
    public WrongIdPasswordException() {
    }

    public WrongIdPasswordException(String message) {
        super(message);
    }

    public WrongIdPasswordException(String message, Throwable cause) {
        super(message, cause);
    }

    public WrongIdPasswordException(Throwable cause) {
        super(cause);
    }
}
