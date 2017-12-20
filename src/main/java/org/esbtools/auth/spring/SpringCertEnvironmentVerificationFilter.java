package org.esbtools.auth.spring;

import java.io.IOException;

import javax.naming.NamingException;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.esbtools.auth.servlet.CertEnvironmentVerificationFilter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;

public class SpringCertEnvironmentVerificationFilter extends CertEnvironmentVerificationFilter {

    public SpringCertEnvironmentVerificationFilter(String environment) {
        super(environment);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        super.init(filterConfig);
    }

    @Override
    protected void unsuccessfulAuthentication(ServletRequest request,
            ServletResponse response, NamingException failed) throws IOException, ServletException {

        SecurityContextHolder.clearContext();

        AuthenticationException authException = new EnvironmentVerificationAuthenticationException(
                "Unable to authenticate", failed);

        request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, authException);

        throw authException;
    }

    public static class EnvironmentVerificationAuthenticationException extends AuthenticationException {
        private static final long serialVersionUID = -9117378985089473004L;

        public EnvironmentVerificationAuthenticationException(String msg, Throwable t) {
            super(msg, t);
        }
    }

}
