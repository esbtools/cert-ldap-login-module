package org.esbtools.auth.spring;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.naming.NamingException;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.esbtools.auth.util.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.web.filter.OncePerRequestFilter;

public class CertEnvironmentVerificationFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(CertEnvironmentVerificationFilter.class);

  private final Environment environment;

  public CertEnvironmentVerificationFilter(String environment) {
    this.environment = (null == environment) ? null : new Environment(environment);

    LOGGER.info("Cert Environment: " + ((environment == null) ? "Not Set" : environment));
  }

  @Override
  public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    if (null != environment) {
      LOGGER.debug("Attempting Environment Cert verification");
      X509Certificate certChain[] = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

      if ((null != certChain) && (certChain.length > 0)) {
        LOGGER.debug("Verifying environment on cert");
        String dn = certChain[0].getSubjectDN().getName();
        try {
          environment.validate(dn);
        }
        catch (NamingException e) {
          unsuccessfulAuthentication(request, response,
              new CertEnvironmentAuthenticationException(e.getMessage()));
          return; //end the chain
        }
      }
      else {
        LOGGER.debug("Cert not found. Skipping Environment Cert verification.");
      }
    }
    else {
      LOGGER.debug("No environment configured. Skipping Environment Cert verification.");
    }

    chain.doFilter(request, response);
  }

  /**
   * Ensures the authentication object in the secure context is set to null when
   * authentication fails.
   * <p>
   * Caches the failure exception as a request attribute
   */
  protected void unsuccessfulAuthentication(HttpServletRequest request,
      HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
    SecurityContextHolder.clearContext();

    if (LOGGER.isDebugEnabled()) {
        LOGGER.debug("Cleared security context due to exception", failed);
    }
    request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, failed);

    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, failed.getMessage());
  }

}
