package io.jarvis.jwt.config;

import io.jarvis.jwt.filter.JwtFilter1;
import io.jarvis.jwt.filter.JwtFilter2;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<JwtFilter1> jwtfilter1() {
        FilterRegistrationBean<JwtFilter1> bean = new FilterRegistrationBean<>(new JwtFilter1());
        bean.addUrlPatterns("/*");
        bean.setOrder(1);
        return bean;
    }

    @Bean
    public FilterRegistrationBean<JwtFilter2> jwtfilter2() {
        FilterRegistrationBean<JwtFilter2> bean = new FilterRegistrationBean<>(new JwtFilter2());
        bean.addUrlPatterns("/*");
        bean.setOrder(0);
        return bean;
    }

}
