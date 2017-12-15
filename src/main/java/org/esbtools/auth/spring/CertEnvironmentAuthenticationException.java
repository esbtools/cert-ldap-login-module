package org.esbtools.auth.spring;

import org.springframework.security.core.AuthenticationException;

public class CertEnvironmentAuthenticationException extends AuthenticationException {

  private static final long serialVersionUID = -1102864286332227011L;

  public CertEnvironmentAuthenticationException(String msg) {
    super(msg);
  }

  public CertEnvironmentAuthenticationException(String msg, Throwable t) {
    super(msg, t);
  }

}
