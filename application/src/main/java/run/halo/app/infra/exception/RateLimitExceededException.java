package run.halo.app.infra.exception;

import org.springframework.security.core.AuthenticationException;

public class RateLimitExceededException extends AuthenticationException {
    public RateLimitExceededException(String message) {
        super(message);
    }
}
