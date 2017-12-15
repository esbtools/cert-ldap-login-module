/*
 Copyright 2017 esbtools Contributors and/or its affiliates.

 This file is part of esbtools.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.esbtools.auth;

import org.esbtools.auth.util.CachedRolesProvider;
import org.esbtools.auth.util.RolesCache;
import org.esbtools.auth.util.RolesProvider;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@RunWith(MockitoJUnitRunner.class)
public class CachedRolesProviderTest {

    @Mock
    RolesProvider rolesProvider;

    @Spy
    RolesCache rolesCache = new RolesCache(1000);

    CachedRolesProvider cachedRolesProvider;

    final Set<String> roles = new HashSet<String>(Arrays.asList(new String[]{"role1","role2"}));

    @Before
    public void init() {
        cachedRolesProvider = new CachedRolesProvider(rolesProvider, rolesCache);
    }

    @Test
    public void testRolesCache() throws Exception {

        Mockito.when(rolesProvider.getUserRoles("user")).thenReturn(roles);

        // cache miss
        Set<String> returnedRoles = cachedRolesProvider.getUserRoles("user");
        Assert.assertEquals(roles, returnedRoles);
        // cache hit
        returnedRoles = cachedRolesProvider.getUserRoles("user");
        Assert.assertEquals(roles, returnedRoles);
        Thread.sleep(1000);
        // cache miss (expired)
        returnedRoles = cachedRolesProvider.getUserRoles("user");
        Assert.assertEquals(roles, returnedRoles);

        // checked rolesCache for user 3 times
        Mockito.verify(rolesCache, Mockito.times(3)).get("user");
        // populated cache twice
        Mockito.verify(rolesCache, Mockito.times(2)).put("user", roles);
        // 2 remote calls, because user was found in cache once
        Mockito.verify(rolesProvider, Mockito.times(2)).getUserRoles("user");
        // fallback cache was not used
        Mockito.verify(rolesCache, Mockito.times(0)).getFromFallback("user");
    }

    @Test
    public void testFallBackRolesCache() throws Exception {

        // ldap failure
        Mockito.when(rolesProvider.getUserRoles("user")).thenThrow(new LDAPException(ResultCode.SERVER_DOWN));

        rolesCache.put("user", roles);
        Thread.sleep(1000); // wait till it expires
        Assert.assertNull("rolesCache should have expired", rolesCache.get("user"));

        Set<String> returnedRoles = cachedRolesProvider.getUserRoles("user");
        Assert.assertEquals(roles, returnedRoles);
        Mockito.verify(rolesCache, Mockito.times(1)).getFromFallback("user");

    }
}
