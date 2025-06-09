package com.lostidentity.filter;


import jakarta.servlet.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;


@Slf4j
public class AuthoritiesLoggingAfterFilter implements Filter {


    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        Authentication authn = SecurityContextHolder.getContext().getAuthentication();

        if(null != authn){
            log.info("User : " + authn.getName() + " is successfully authenticated and "
            + "has the authorities : " + authn.getAuthorities().toString());
        }
        chain.doFilter(request, response);
    }
}
