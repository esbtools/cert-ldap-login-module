package org.esbtools.auth.spring;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.Response;

import org.esbtools.auth.spring.SpringCertEnvironmentVerificationFilter.EnvironmentVerificationAuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;

public class EsbToolsExceptionTraslatingFilter extends GenericFilterBean {

    private static final Logger LOGGER = LoggerFactory.getLogger(EsbToolsExceptionTraslatingFilter.class);

    private final ErrorResponseWriter writer;

    public EsbToolsExceptionTraslatingFilter(ErrorResponseWriter writer) {
        this.writer = writer;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        LOGGER.debug("Executing");
        try {
            chain.doFilter(request, response);
        } catch (EnvironmentVerificationAuthenticationException e) {
            LOGGER.debug("blocking access");

            SecurityContextHolder.clearContext();

            if (response instanceof HttpServletResponse) {
                ((HttpServletResponse) response).setStatus(writer.getStatus().getStatusCode());
            }

            response.setContentType(writer.getContentType());
            response.getWriter().write(writer.print(e));
            response.getWriter().close();
        }
    }

    public abstract static class ErrorResponseWriter {

        private final Response.Status status;
        private final String contentType;

        public Response.Status getStatus() {
            return status;
        }

        public String getContentType() {
            return contentType;
        }

        public ErrorResponseWriter(String contentType, Response.Status status) {
            this.contentType = contentType;
            this.status = status;
        }

        public abstract String print(Exception e);
    }

}
