package io.jarvis.jwt.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import io.jarvis.jwt.auth.PrincipalDetails;
import io.jarvis.jwt.config.JwtProperties;
import io.jarvis.jwt.model.User;
import io.jarvis.jwt.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);

        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        //super.doFilterInternal(request, response, chain);
        log.info("인증이나 권한이 필요한 주소 요청이 됨.");
        String authorizationHeader = request.getHeader("authorization");
        log.info("authorizationHeader: "+authorizationHeader);

        // header정보 존재여부
        if(authorizationHeader == null || !authorizationHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
            log.info("header 정보가 없음.");
            chain.doFilter(request, response);
            return;
        }

        String jwtToken = request.getHeader(JwtProperties.HEADER_STRING).replace(JwtProperties.TOKEN_PREFIX, "");

        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(jwtToken).getClaim("username").asString();

        // 서명이 정상적인경우
        if(username != null) {
            User userEntity = userRepository.findByUsername(username);

            log.info(userEntity.toString());
            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
            // jwt토큰 서명을 통해서 서명이 정상이면 authorization객체 생성
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null, principalDetails.getAuthorities());

            // 강제로 세션에 authorization객체 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            log.info("정상처리");
        }

        chain.doFilter(request, response);

    }
}
