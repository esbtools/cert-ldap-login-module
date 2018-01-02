package org.esbtools.auth.spring;

import java.util.stream.Collectors;

import org.esbtools.auth.ldap.LdapConfiguration;
import org.esbtools.auth.ldap.LdapRolesProvider;
import org.esbtools.auth.util.CachedRolesProvider;
import org.esbtools.auth.util.RolesCache;
import org.esbtools.auth.util.RolesProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

public class LdapUserDetailsService implements UserDetailsService, AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> {

    private static final Logger LOGGER = LoggerFactory.getLogger(LdapUserDetailsService.class);

    private final RolesProvider rolesProvider;

    public LdapUserDetailsService(String searchBase, LdapConfiguration ldapConfiguration, int rolesCacheExpiryMS) throws Exception {
      this(new LdapRolesProvider(searchBase, ldapConfiguration), rolesCacheExpiryMS);
    }
    
    public LdapUserDetailsService(String searchBase, LdapConfiguration ldapConfiguration) throws Exception {
      this(new LdapRolesProvider(searchBase, ldapConfiguration));
    }
    
    public LdapUserDetailsService(LdapRolesProvider rolesProvider, int rolesCacheExpiryMS) {
      this(new CachedRolesProvider(rolesProvider, new RolesCache(rolesCacheExpiryMS)));
    }

    public LdapUserDetailsService(RolesProvider rolesProvider) {
        this.rolesProvider = rolesProvider;
    }

    @Override
    public UserDetails loadUserDetails(PreAuthenticatedAuthenticationToken token) throws UsernameNotFoundException {
      return loadUserByUsername(token.getName());
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        LOGGER.debug("Using LdapUserDetailsService with principal: " + username);

        try {
            return new User(
                    username,
                    "no-password",
                    rolesProvider.getUserRoles(username).stream()
                            .map(n -> new SimpleGrantedAuthority(n))
                            .collect(Collectors.toList())
                    );
        }
        catch (Exception e) {
            LOGGER.error("Unable to check ldap for unknown reason.", e);

            throw new UsernameNotFoundException(username + " could not be authorized");
        }
    }

}
