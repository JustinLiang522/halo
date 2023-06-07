package run.halo.app.security.authentication.login;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Base64;
import com.google.common.util.concurrent.RateLimiter;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerFormLoginAuthenticationConverter;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import run.halo.app.infra.exception.RateLimitExceededException;

public class LoginAuthenticationConverter extends ServerFormLoginAuthenticationConverter {

    private final CryptoService cryptoService;

    private final RateLimiter rateLimiter;

    public LoginAuthenticationConverter(CryptoService cryptoService, RateLimiter rateLimiter) {
        this.cryptoService = cryptoService;
        this.rateLimiter = rateLimiter;
    }

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {

        if (!rateLimiter.tryAcquire()) {
            return Mono.error(new RateLimitExceededException("Rate limit exceeded."));
        }

        return super.convert(exchange)
            // validate the password
            .flatMap(token -> {
                var credentials = (String) token.getCredentials();
                byte[] credentialsBytes;
                try {
                    credentialsBytes = Base64.getDecoder().decode(credentials);
                } catch (IllegalArgumentException e) {
                    // the credentials are not in valid Base64 scheme
                    return Mono.error(new BadCredentialsException("Invalid Base64 scheme."));
                }
                return cryptoService.decrypt(credentialsBytes)
                    .onErrorMap(InvalidEncryptedMessageException.class,
                        error -> new BadCredentialsException("Invalid credential.", error))
                    .map(decryptedCredentials -> new UsernamePasswordAuthenticationToken(
                        token.getPrincipal(),
                        new String(decryptedCredentials, UTF_8)));
            });
    }
}
