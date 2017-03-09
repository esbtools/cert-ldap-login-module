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

import org.jboss.security.SimpleGroup;
import org.jboss.security.auth.spi.BaseCertLoginModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.LoginException;
import java.security.Principal;
import java.security.acl.Group;

public class CertLoginModule extends BaseCertLoginModule {

    private final Logger LOGGER = LoggerFactory.getLogger(CertLoginModule.class);
    private final Logger ACCESS_LOGGER = LoggerFactory.getLogger(CertLoginModule.class + "access");

    @Override
    protected Group[] getRoleSets() throws LoginException {
        LOGGER.debug("staticRoleLoginModule getRoleSets()");

        String roleName = "authenticated";

        SimpleGroup userRoles = new SimpleGroup("Roles");

        Principal p = null;

        String certPrincipal = getUsername();

        try {
            LOGGER.debug("Certificate principal:" + certPrincipal);

            p = super.createIdentity(roleName);

            userRoles.addMember(p);

            if (ACCESS_LOGGER.isDebugEnabled()) {
                ACCESS_LOGGER.debug("Certificate principal: " + certPrincipal + ", roles: " + userRoles);
            }

            LOGGER.debug("Assign principal [" + p.getName() + "] to role [" + roleName + "]");
        } catch (Exception e) {
            String principalName = p == null ? certPrincipal : p.getName();
            LOGGER.error("Failed to assign principal [" + principalName + "] to role [" + roleName + "]", e);
            throw new LoginException(e.getMessage());
        }
        Group[] roleSets = {userRoles};
        return roleSets;
    }

}
