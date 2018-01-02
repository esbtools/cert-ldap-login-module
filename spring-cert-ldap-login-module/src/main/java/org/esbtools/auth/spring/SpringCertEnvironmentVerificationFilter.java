package org.esbtools.auth.spring;

import java.io.IOException;

import javax.naming.NamingException;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.esbtools.auth.servlet.CertEnvironmentVerificationFilter;
import org.springframework.security.core.AuthenticationException;

public class SpringCertEnvironmentVerificationFilter extends CertEnvironmentVerificationFilter {

    public SpringCertEnvironmentVerificationFilter(String environment) {
        super(environment);
    }

    @Override
    protected void unsuccessfulAuthentication(ServletRequest request,
            ServletResponse response, NamingException failed) throws IOException, ServletException {
        throw new EnvironmentVerificationAuthenticationException(failed.getMessage(), failed);
    }

    public static class EnvironmentVerificationAuthenticationException extends AuthenticationException {
        private static final long serialVersionUID = -9117378985089473004L;

        public EnvironmentVerificationAuthenticationException(String msg, Throwable t) {
            super(msg, t);
        }
    }

}
