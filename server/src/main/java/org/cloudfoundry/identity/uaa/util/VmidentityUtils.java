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

import java.util.Collection;
import java.util.EnumSet;
import java.util.Locale;

import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

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

    public static String getZoneId() {
        String zoneId = IdentityZoneHolder.get().getId();

        return zoneId;
    }

    public static String getPrincipalUpn(PrincipalId userId) {

        // TODO: check native ad as .Authenticate and find user return domain in
        // different case....
        return userId.getName() + "@" + userId.getDomain().toUpperCase(Locale.ENGLISH);
    }

}
