/*
 Copyright 2017esbtools Contributors and/or its affiliates.

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
package org.esbtools.auth.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Set;

/**
 * Caches results from {@link RolesProvider} and supports fallback to cache.
 * See {@link RolesCache} for more details.
 *
 * @author mpatercz
 *
 */
public class CachedRolesProvider implements RolesProvider {

    private final Logger LOGGER = LoggerFactory.getLogger(CachedRolesProvider.class);

    private RolesProvider rolesProvider;
    private RolesCache rolesCache;

    public CachedRolesProvider(RolesProvider rolesProvider) {
        super();
        this.rolesProvider = rolesProvider;
        this.rolesCache = new RolesCache(5*60*1000);
    }

    public CachedRolesProvider(RolesProvider rolesProvider, RolesCache rolesCache) {
        super();
        this.rolesProvider = rolesProvider;
        this.rolesCache = rolesCache;
    }

    @Override
    public Set<String> getUserRoles(String username) throws Exception {

        try {
            Set<String> roles = rolesCache.get(username);

            if (roles != null) {
                LOGGER.debug("Found roles in cache for uid={}", username);
                return roles;
            }

            LOGGER.debug("Cache missed for uid={}. Calling ldap.", username);

            roles = rolesProvider.getUserRoles(username);
            rolesCache.put(username, roles);

            return roles;
        } catch (Exception e) {
            Set<String> roles = rolesCache.getFromFallback(username);

            if (roles != null) {
                LOGGER.error("There was an error getting roles for "+username+", taking roles from fallback cache.", e);
                return roles;
            }

            // no fallback, nothing we can do
            throw e;
        }
    }

    protected Set<String> getFallback(String username) {
        Set<String> roles = rolesCache.getFromFallback(username);
        if (roles == null) {
            return null;
        }
        // was able to use the cache or use the LDAP server on the second retry
        LOGGER.debug("User "+username+" found in failoverCache");
        return roles;
    }

}
