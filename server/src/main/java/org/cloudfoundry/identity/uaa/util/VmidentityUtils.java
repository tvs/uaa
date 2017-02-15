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
package org.cloudfoundry.identity.uaa.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;

import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.vmware.identity.idm.Attribute;
import com.vmware.identity.idm.AttributeValuePair;
import com.vmware.identity.idm.DomainType;
import com.vmware.identity.idm.IIdentityStoreData;
import com.vmware.identity.idm.PrincipalId;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityUtils {

    public static String getSystemDomain(String tenant, CasIdmClient idmClient) throws Exception {
        Collection<IIdentityStoreData> provider = idmClient.getProviders(tenant, EnumSet.of(DomainType.SYSTEM_DOMAIN));
        // todo: should get security domain name, not provider name.
        // Collection<SecurityDomain> domains = client.getSecurityDomains(tenant, provider.iterator().next().getName());

        if ((provider == null) || (provider.iterator() == null) || (provider.iterator().hasNext() == false)) {
            throw new IllegalStateException("System domain must exist.");
        }

        return provider.iterator().next().getName();

    }

    public static String getTenantName(String systemTenant) {
        return getTenantName(IdentityZoneHolder.get().getId(), systemTenant);
    }

    public static String getTenantName(String zoneId, String systemTenant) {
        if (zoneId.equalsIgnoreCase(IdentityZone.getUaa().getId())) {
            zoneId = systemTenant;
        }
        return zoneId;
    }

    public static String getTenantName(CasIdmClient idmClient) throws Exception {
        String zoneId = IdentityZoneHolder.get().getId();
        return getTenantName(zoneId, idmClient);
    }

    public static String getTenantName(String zoneId, CasIdmClient idmClient) throws Exception {
        if (zoneId.equalsIgnoreCase(IdentityZone.getUaa().getId())) {
            zoneId = idmClient.getSystemTenant();
        }
        return zoneId;
    }

    public static String getZoneId() {
        String zoneId = IdentityZoneHolder.get().getId();

        return zoneId;
    }

    public static String getPrincipalUpn(PrincipalId userId) {

        // TODO: check native ad as .Authenticate and find user return domain in
        // different case....
        return userId.getName() + "@" + userId.getDomain().toUpperCase(Locale.ENGLISH);
    }

    public static List<GrantedAuthority> getUserAuthorities(CasIdmClient idmClient, PrincipalId userId, String tenant, String systemDomain) throws Exception
    {
        // for now, we are implementing scopes as groups in system domain.
        // todo: we should implement other UAA strategies later.
        ArrayList<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();

        ArrayList<Attribute> attributes = new ArrayList<Attribute>(1);
        attributes.add(new Attribute(com.vmware.identity.idm.KnownSamlAttributes.ATTRIBUTE_USER_GROUPS));
        Collection<AttributeValuePair> attrs = idmClient.getAttributeValues(tenant, userId, attributes);
        boolean isAdmin = false;
        String systemDomainPrefix = systemDomain + "\\";
        String systemDomainAdmin = systemDomainPrefix + "Administrator";
        systemDomainPrefix = systemDomainPrefix.toUpperCase(Locale.ENGLISH);
        int systemDomainPrefixLength = systemDomainPrefix.length();

        if (attrs != null && attrs.iterator().hasNext())
        {
            AttributeValuePair avp = attrs.iterator().next();
            if (avp != null && avp.getValues() != null)
            {
                for (String val : avp.getValues())
                {
                    if ( val != null )
                    {
                        if ( ( isAdmin == false ) && ( val.equalsIgnoreCase(systemDomainAdmin) ) )
                        {
                            isAdmin = true;
                            authorities.addAll(UaaAuthority.ADMIN_AUTHORITIES);
                               SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(val.substring(systemDomainPrefixLength));
                               authorities.add(grantedAuthority);
                        }
                        else if ( val.toUpperCase(Locale.ENGLISH).startsWith(systemDomainPrefix) )
                        {
                            SimpleGrantedAuthority grantedAuthority = new SimpleGrantedAuthority(val.substring(systemDomainPrefixLength));
                            authorities.add(grantedAuthority);
                        }
                    }
                }
            }
        }

        if ( isAdmin == false )
        {
            authorities.addAll(UaaAuthority.USER_AUTHORITIES);
        }

        return authorities;
    }

    // assumes Upn
    public static PrincipalId getPrincipalId(String id)
    {
        PrincipalId principal = null;
        String[] parts = id.split("@");
        if (parts.length != 2)
        {
            throw new IllegalArgumentException(String.format("Invalid format for user id '%s'", id));
        }
        else
        {
            principal = new PrincipalId(parts[0], parts[1]);
        }
        return principal;
    }
}
