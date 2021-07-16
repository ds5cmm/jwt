package io.jarvis.jwt.config;

public interface JwtProperties {
    String SECRET = "cos";
    int EXPIRATION_TIME = 1000 * 60 * 10;
    String TOKEN_PREFIX = "Bearer ";
    String HEADER_STRING = "Authorization";

}
