package org.esbtools.auth.servlet;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.naming.NamingException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.esbtools.auth.util.Environment;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertEnvironmentVerificationFilter implements Filter {

  private static final Logger LOGGER = LoggerFactory.getLogger(CertEnvironmentVerificationFilter.class);

  private final Environment env;

  public CertEnvironmentVerificationFilter(String environment) {
    env = new Environment(environment);

    LOGGER.info("Cert Environment: " + ((environment == null) ? "Not Set" : environment));
  }

  @Override
  public void init(FilterConfig filterConfig) throws ServletException {
    //Do Nothing!
  }

  @Override
  public void destroy() {
    //Do Nothing!
  }
  
  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    LOGGER.debug("Attempting Environment Cert verification");
    X509Certificate certChain[] = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

    if ((null != certChain) && (certChain.length > 0)) {
      LOGGER.debug("Verifying environment on cert");
      String dn = certChain[0].getSubjectDN().getName();
      try {
        env.validate(dn);
      }
      catch (NamingException e) {
        unsuccessfulAuthentication(request, response, e);
        return; //end the chain
      }
    }
    else {
      LOGGER.debug("Cert not found. Skipping Environment Cert verification.");
    }

    chain.doFilter(request, response);
  }

  protected void unsuccessfulAuthentication(ServletRequest request,
          ServletResponse response, NamingException failed) throws IOException, ServletException {
    if (response instanceof HttpServletResponse) {
       ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
    
    response.setContentType("text/html");
    response.getWriter().write("<html><head><title>Error</title></head><body>" + failed.getMessage() + "</body></html>");
    response.getWriter().close();
  }

}
