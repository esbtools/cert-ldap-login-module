[![Build Status](https://travis-ci.org/esbtools/cert-ldap-login-module.svg?branch=master)](https://travis-ci.org/esbtools/ldap-login-module.svg?branch=master)
[![Coverage Status](https://coveralls.io/repos/esbtools/cert-ldap-login-module/badge.svg?branch=master&service=github)](https://coveralls.io/github/esbtools/cert-ldap-login-module?branch=master)

# How to configure authentication/authorization on JBoss

## In standalone.xml:

```
<subsystem xmlns="urn:jboss:domain:security:1.2">
 <security-domain name="esbtools-cert">
    <authentication>
        <login-module name="CertLdapLoginModule" code="org.esbtools.auth.jboss.CertLdapLoginModule" flag="required">
            <module-option name="password-stacking" value="useFirstPass"/>
            <module-option name="securityDomain" value="esbtools-cert"/>
            <module-option name="verifier" value="org.jboss.security.auth.certs.AnyCertVerifier"/>
            <module-option name="authRoleName" value="authenticated"/>
            <module-option name="ldapServer" value="<ldap hostname>"/>
            <module-option name="port" value="636"/>
            <module-option name="searchBase" value="ou=example,dc=esbtools,dc=org"/>
            <module-option name="bindDn" value="uid=esbtools-app,ou=example,dc=esbtools,dc=org"/>
            <module-option name="bindPassword" value="<password>"/>
            <module-option name="useSSL" value="true"/>
            <module-option name="poolSize" value="5"/>
            <module-option name="trustStore" value="${jboss.server.config.dir}/truststore.jks"/>
            <module-option name="trustStorePassword" value="<password>"/>
        </login-module>
    </authentication>
    <jsse keystore-password="<password>" keystore-url="file://${jboss.server.config.dir}/keystore.jks" truststore-password="<password>" truststore-url="file://${jboss.server.config.dir}/truststore.jks" client-auth="true"/>
  </security-domain>
</subsystem>
```

# How to configure authentication/authorization in Spring Security

## Using Spring Boot and Configuration Properties

``` java
@Configuration
@EnableConfigurationProperties
public class ApplicationConfiguration {

  @Bean
  @ConfigurationProperties(prefix = "ldap")
  public LdapConfiguration ldapConfiguration() {
    return new LdapConfiguration();
  }
  
  @Bean
  public LdapUserDetailsService ldapUserDetailsService(
      LdapConfiguration ldapConfiguration,
      @Value("${ldap.user-details.search_base}") String searchBaseDn,
      @Value("${ldap.user-details.rolesCacheExpiryMS}") int rolesCacheExpiryMS) throws Exception {
    return new LdapUserDetailsService(searchBaseDn, ldapConfiguration, rolesCacheExpiryMS);
  }
}

// Inject into filter chain as seen below or utilize standalone
```

```
# application.properties
ldap.server=foo.bar.com
ldap.port=636
ldap.bindDn=uid=userservice-jboss,ou=serviceaccounts,dc=redhat,dc=com
ldap.bindDNPwd=password
ldap.poolSize=5
ldap.useSSL=true
ldap.debug=false
ldap.trustStorePassword=password
ldap.connectionTimeoutMS=30000
ldap.responseTimeoutMS=30000
ldap.keepAlive=true
ldap.poolMaxConnectionAgeMS=15000
ldap.user-details.search_base=dc=redhat,dc=com
ldap.user-details.rolesCacheExpiryMS=300000
```

## Using annotation driven configuration:

``` java
import org.esbtools.auth.ldap.LdapConfiguration;
import org.esbtools.auth.spring.LdapUserDetailsService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource(value = {"classpath:/ldapconfig.properties"})
public class ApplicationConfiguration {

  @Bean
  public LdapConfiguration ldapConfiguration(
      @Value("${ldapconfig.server}") String server,
      @Value("${ldapconfig.port}") Integer port,
      @Value("${ldapconfig.username}") String bindDn,
      @Value("${ldapconfig.password}") String bindDNPwd,
      @Value("${ldapconfig.pool_size}") Integer poolSize,
      @Value("${ldapconfig.use_tls}") Boolean useSSL,
      @Value("${ldapconfig.truststore}") String trustStore,
      @Value("${ldapconfig.truststore_password}") String trustStorePassword,
      @Value("${ldapconfig.connectionTimeoutMS}") Integer connectionTimeoutMS,
      @Value("${ldapconfig.responseTimeoutMS}") Integer responseTimeoutMS,
      @Value("${ldapconfig.debug}") Boolean debug,
      @Value("${ldapconfig.keepAlive}") Boolean keepAlive,
      @Value("${ldapconfig.poolMaxConnectionAgeMS}") Integer poolMaxConnectionAgeMS) {

    LdapConfiguration config = new LdapConfiguration();
    config.server(server);
    config.port(port);
    config.bindDn(bindDn);
    config.bindDNPwd(bindDNPwd);
    config.poolSize(poolSize);
    config.useSSL(useSSL);
    config.trustStore(trustStore);
    config.trustStorePassword(trustStorePassword);
    config.connectionTimeoutMS(connectionTimeoutMS);
    config.responseTimeoutMS(responseTimeoutMS);
    config.debug(debug);
    config.keepAlive(keepAlive);
    config.poolMaxConnectionAgeMS(poolMaxConnectionAgeMS);

    return config;
  }

  @Bean
  public LdapUserDetailsService ldapUserDetailsService(
      LdapConfiguration ldapConfiguration,
      @Value("${ldapconfig.search_base:dc=redhat,dc=com}") String searchBaseDn,
      @Value("${ldapconfig.rolesCacheExpiryMS:300000}") int rolesCacheExpiryMS) throws Exception {
    return new LdapUserDetailsService(
        searchBaseDn,
        ldapConfiguration,
        rolesCacheExpiryMS);
  }

}
```

``` java
import org.esbtools.auth.spring.EsbToolsExceptionTraslatingFilter;
import org.esbtools.auth.spring.EsbToolsExceptionTraslatingFilter.ErrorResponseWriter;
import org.esbtools.auth.spring.SpringCertEnvironmentVerificationFilter;
import org.esbtools.auth.spring.LdapUserDetailsService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private LdapUserDetailsService ldapUserDetailsService;

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //...

        http.x509()
                .authenticationUserDetailsService(ldapUserDetailsService)
                .and()
                .addFilterAfter(
                        new CertEnvironmentVerificationFilter(environment), X509AuthenticationFilter.class);

        //...
    }

    //...
}
```
