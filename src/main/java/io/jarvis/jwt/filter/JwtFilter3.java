package io.jarvis.jwt.filter;


import lombok.extern.slf4j.Slf4j;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

@Slf4j
public class JwtFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        log.info("JwtFilter3");

        HttpServletRequest req = (HttpServletRequest)servletRequest;
        HttpServletResponse res = (HttpServletResponse)servletResponse;

        if(req.getMethod().equals("POST")) {
            log.info("POST 요청됨");
            String headerAuth = req.getHeader("Authorization");


            if(headerAuth!=null && headerAuth.equals("cos")) {
                log.info(headerAuth);
                filterChain.doFilter(req, res);
            } else {
                PrintWriter outPW = res.getWriter();
                log.info("인증안됨.");
                outPW.print("인증안됨!!");
            }
        }
    }
}
