/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2017] VMware, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.user;

import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.vmware.identity.idm.InvalidPrincipalException;
import com.vmware.identity.idm.PersonUser;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityUserDatabase implements UaaUserDatabase {

    private final CasIdmClient _idmClient;
    // private final List<GrantedAuthority> _adminAuthorities;
    // private final List<GrantedAuthority> _regularAuthorities;
    private final List<GrantedAuthority> _defaultAuthorities;

    public VmidentityUserDatabase(CasIdmClient casIdmClient, Set<String> defaultAuthorities) {
        this._idmClient = casIdmClient;
        this._defaultAuthorities = Collections.unmodifiableList(
                AuthorityUtils.createAuthorityList(defaultAuthorities.toArray(new String[0])));
        // String[] authArray = (String[])defaultAuthorities.toArray();
        // this._adminAuthorities = AuthorityUtils.createAuthorityList(authArray);
        // this._regularAuthorities = AuthorityUtils.createAuthorityList(authArray);
        // mergeAuthorities(this._adminAuthorities, UaaAuthority.ADMIN_AUTHORITIES);
        // mergeAuthorities(this._regularAuthorities, UaaAuthority.USER_AUTHORITIES);
    }

    @Override
    public UaaUser retrieveUserByName(String username, String origin) throws UsernameNotFoundException {
        try {
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this._idmClient);
            UaaUser user = null;
            String[] parts = username.split("@");
            PrincipalId id = new PrincipalId(parts[0], parts[1]);
            PersonUser personUser = this._idmClient.findPersonUser(tenant, id);

            String upn = VmidentityUtils.getPrincipalUpn(personUser.getId());

            // todo: this is a potentially big perf hit
            // we need to make sure authorities are retrieved only *after* auth, as part of auth
            List<GrantedAuthority> authorities = VmidentityUtils.getUserAuthorities(this._idmClient, personUser.getId(), tenant, systemDomain);

            UaaUserPrototype proto =
                new UaaUserPrototype()
                    .withId(upn) // todo: this should probably become objectId (when all sso stack is switched)
                    .withZoneId(tenant)
                    .withUsername(upn)
                    .withOrigin(origin)
                    .withEmail(upn) // email is required; now idm it is optional
                    .withAuthorities(authorities);

            if (personUser.getDetail() != null) {
                proto =
                    proto.withFamilyName(personUser.getDetail().getLastName())
                    .withGivenName(personUser.getDetail().getFirstName())
                    .withPasswordLastModified(new Date(personUser.getDetail().getPwdLastSet()));
            }

            user = new UaaUser(proto);
            return user;
        } catch (InvalidPrincipalException ex) {
            throw new UsernameNotFoundException(username, ex);
        } catch (Exception ex) {
            throw new IllegalStateException(
                    String.format("User '%s' not found in tenant '%s'.", username, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public UaaUser retrieveUserById(String id) throws UsernameNotFoundException {

        try {
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            String systemDomain = VmidentityUtils.getSystemDomain(tenant, this._idmClient);

            String[] parts = id.split("@");
            String origin = (systemDomain.equalsIgnoreCase(parts[1])) ? OriginKeys.UAA : OriginKeys.LDAP;

            return this.retrieveUserByName(id, origin);
        } catch (UsernameNotFoundException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalStateException(
                    String.format("User '%s' not found in tenant '%s'.", id, VmidentityUtils.getZoneId()), ex);
        }
    }

    @Override
    public UaaUser retrieveUserByEmail(String email, String origin) throws UsernameNotFoundException {
        // todo: should implement by real e-mail in future
        return this.retrieveUserByName(email, origin);
    }
}
