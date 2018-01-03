# How to configure authentication/authorization in Spring Security

Using annotation driven configuration:

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
                    new EsbToolsExceptionTraslatingFilter(new ErrorResponseWriter() {
                        //...
                    }),
                    ExceptionTranslationFilter.class)
                .addFilterAfter(
                    new SpringCertEnvironmentVerificationFilter("expectedEnvironment"),
                    EsbToolsExceptionTraslatingFilter.class);

        //...
    }

    //...
}
```
