package com.ignited.login;

public class WrongCaptchaException extends LoginFailException {

    public WrongCaptchaException() {
        super();
    }

    public WrongCaptchaException(String message) {
        super(message);
    }

    public WrongCaptchaException(String message, Throwable cause) {
        super(message, cause);
    }

    public WrongCaptchaException(Throwable cause) {
        super(cause);
    }
}
