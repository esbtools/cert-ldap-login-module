package org.esbtools.auth.spring;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Collections;
import java.util.HashSet;

import org.esbtools.auth.util.RolesProvider;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@RunWith(MockitoJUnitRunner.class)
public class LdapUserDetailsServiceTest {

    @Mock
    private RolesProvider rolesProvider;

    @Test
    public void testLoadUserByUsername_UsernameShouldAlwaysBeReturned() throws Exception {
        when(rolesProvider.getUserRoles(anyString())).thenReturn(new HashSet<>());

        UserDetails details = new LdapUserDetailsService(rolesProvider)
                .loadUserByUsername("johnny5");

        assertNotNull(details);
        assertEquals("johnny5", details.getUsername());

        verify(rolesProvider, times(1)).getUserRoles(anyString());
    }

    @Test
    public void testLoadUserByUsername_NoRoles() throws Exception {
        when(rolesProvider.getUserRoles(anyString())).thenReturn(new HashSet<>());

        UserDetails details = new LdapUserDetailsService(rolesProvider)
                .loadUserByUsername("johnny5");

        assertNotNull(details);
        assertTrue(details.getAuthorities().isEmpty());

        verify(rolesProvider, times(1)).getUserRoles(anyString());
    }

    @Test
    public void testLoadUserByUsername_Roles() throws Exception {
        when(rolesProvider.getUserRoles(anyString())).thenReturn(
                Collections.singleton("laser"));

        UserDetails details = new LdapUserDetailsService(rolesProvider)
                .loadUserByUsername("johnny5");

        assertNotNull(details);
        assertEquals(1, details.getAuthorities().size());
        assertEquals("laser", details.getAuthorities().iterator().next().getAuthority());

        verify(rolesProvider, times(1)).getUserRoles(anyString());
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testLoadUserByUsername_UsernameNotFound() throws Exception {
        when(rolesProvider.getUserRoles(anyString())).thenThrow(
                new Exception("fake excepion"));

        new LdapUserDetailsService(rolesProvider)
                .loadUserByUsername("larry");

    }

}
