package org.esbtools.auth.spring;

import java.io.IOException;
import java.security.cert.X509Certificate;

import javax.annotation.Nullable;
import javax.naming.NamingException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.web.filter.OncePerRequestFilter;

public class CertEnvironmentVerificationFilter extends OncePerRequestFilter {

  private static final Logger LOGGER = LoggerFactory.getLogger(CertEnvironmentVerificationFilter.class);

  public static final String LOCATION = "l";

  private final String environment;

  public CertEnvironmentVerificationFilter(@Nullable String environment) {
    this.environment = environment;

    LOGGER.info("Cert Environment: " + ((environment == null) ? "Not Set" : environment));
  }

  @Override
  public void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    if (null != environment) {
      LOGGER.debug("Attempting Environment Cert verification");
      X509Certificate certChain[] = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

      String dn = certChain[0].getSubjectDN().getName();

      if ((null != certChain) && (certChain.length > 0)) {
        LOGGER.debug("Verifying environment on cert");
        if(!validateEnvironment(dn)) {
          unsuccessfulAuthentication(request, response,
              new CertEnvironmentAuthenticationException(
                  "Location from certificate does not match configured environment"));
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

  private boolean validateEnvironment(String certificatePrincipal) {
    if (StringUtils.isNotBlank(environment)) {
      try {
        String location = getLDAPAttribute(certificatePrincipal, LOCATION);

        if (!StringUtils.equalsIgnoreCase(environment, location)) {
          return false;
        }
      } catch (NamingException e) {
        return false;
      }
    }

    return true;
  }

  private String getLDAPAttribute(String certificatePrincipal, String searchAttribute) throws NamingException {
    String searchName = new String();
    LdapName name = new LdapName(certificatePrincipal);
    for (Rdn rdn : name.getRdns()) {
      if (rdn.getType().equalsIgnoreCase(searchAttribute)) {
        searchName = (String) rdn.getValue();
        break;
      }
    }
    return searchName;
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
