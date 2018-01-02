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

            if ((response instanceof HttpServletResponse) && writer.status != null) {
                ((HttpServletResponse) response).setStatus(writer.status.getStatusCode());
            }

            if (writer.contentType != null) {
                response.setContentType(writer.contentType);
            }
            response.getWriter().write(writer.print(e));
            response.getWriter().close();
        }
    }

    public abstract static class ErrorResponseWriter {

        public final Response.Status status;
        public final String contentType;

        public ErrorResponseWriter() {
            this(null, null);
        }

        public ErrorResponseWriter(String contentType, Response.Status status) {
            this.contentType = contentType;
            this.status = status;
        }

        public abstract String print(Exception e);
    }

}
