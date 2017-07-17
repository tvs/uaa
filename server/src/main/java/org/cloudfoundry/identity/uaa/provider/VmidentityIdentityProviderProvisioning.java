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
package org.cloudfoundry.identity.uaa.provider;

import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.client.VmidentityDataAccessException;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.vmware.identity.idm.DomainType;
import com.vmware.identity.idm.IIdentityStoreData;
import com.vmware.identity.idm.IIdentityStoreDataEx;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityIdentityProviderProvisioning implements IdentityProviderProvisioning {

    private final Log logger = LogFactory.getLog(VmidentityIdentityProviderProvisioning.class);

    private final CasIdmClient idmClient;

    public VmidentityIdentityProviderProvisioning(CasIdmClient idmClient) {
        this.idmClient = idmClient;
    }

    @Override
    public IdentityProvider create(IdentityProvider identityProvider) {
        throw new UnsupportedOperationException("Creating a provider is not yet supported.");
    }

    @Override
    public IdentityProvider update(IdentityProvider identityProvider) {
        logger.warn("Updating a provider is not yet supported.");
        return this.retrieve(identityProvider.getId());
    }

    @Override
    public IdentityProvider retrieve(String id) {
        try {
            String tenant = VmidentityUtils.getTenantName(this.idmClient.getSystemTenant());
            Collection<IIdentityStoreData> providers = this.idmClient.getProviders(
                    tenant, EnumSet.of(DomainType.SYSTEM_DOMAIN, DomainType.EXTERNAL_DOMAIN));

            if (providers != null) {
                for (IIdentityStoreData provider : providers) {
                    if (provider.getName().equalsIgnoreCase(id)) {
                        return getIdentityProviderForStore(provider, tenant);
                    }
                }
            }
            return null;
        } catch (Exception ex) {
            throw new VmidentityDataAccessException("Failed to retrieve provider with id '" + id + "'", ex);
        }
    }

    @Override
    public List<IdentityProvider> retrieveActive(String zoneId) {
        return this.retrieveAll(true, zoneId);
    }

    @Override
    public List<IdentityProvider> retrieveAll(boolean activeOnly, String zoneId) {
        try {
            // TODO: active only - we only have active right now...
            String tenant = VmidentityUtils.getTenantName(zoneId, this.idmClient.getSystemTenant());
            Collection<IIdentityStoreData> providers = this.idmClient.getProviders(
                    tenant, EnumSet.of(DomainType.SYSTEM_DOMAIN, DomainType.EXTERNAL_DOMAIN));

            List<IdentityProvider> result = new ArrayList<IdentityProvider>();
            if (providers != null) {
                for (IIdentityStoreData provider : providers) {
                    result.add(getIdentityProviderForStore(provider, tenant));
                }
            }

            return result;
        } catch (Exception ex) {
            throw new VmidentityDataAccessException("Failed to retrieve providers for zone '" + zoneId + "', activeOnly '" + activeOnly + "'", ex);
        }
    }

    @Override
    public IdentityProvider retrieveByOrigin(String origin, String zoneId) {
        try {
            String tenant = VmidentityUtils.getTenantName(zoneId, this.idmClient.getSystemTenant());
            IIdentityStoreData provider = null;

            if (OriginKeys.UAA.equalsIgnoreCase(origin)) {
                Collection<IIdentityStoreData> providers = this.idmClient.getProviders(tenant, EnumSet.of(DomainType.SYSTEM_DOMAIN));

                if (providers == null || providers.isEmpty()) {
                    throw new IllegalStateException("System domain must exist.");
                }

                provider = providers.iterator().next();
            } else {
                provider = this.idmClient.getProvider(tenant, origin);
            }

            if (provider != null) {
                return getIdentityProviderForStore(provider, tenant);
            } else {
                return null;
            }
        } catch (Exception ex) {
            throw new VmidentityDataAccessException("Failed to retrieve provider with origin '" + origin + "' and zone '" + zoneId + "'", ex);
        }
    }

    private IdentityProvider getIdentityProviderForStore(IIdentityStoreData data, String tenant) throws Exception {
        IdentityProvider identityProvider = new IdentityProvider();

        identityProvider.setId(data.getName());
        identityProvider.setVersion(1);
        // identityProvider.setCreated(rs.getTimestamp(pos++));
        // identityProvider.setLastModified(rs.getTimestamp(pos++));
        identityProvider.setName(data.getName());
        identityProvider.setOriginKey(
                ((data.getDomainType() == DomainType.SYSTEM_DOMAIN) ? OriginKeys.UAA : data.getName()));
        identityProvider.setType(
                ((data.getDomainType() == DomainType.SYSTEM_DOMAIN) ? OriginKeys.UAA : OriginKeys.LDAP));

        if ((data.getDomainType() == DomainType.SYSTEM_DOMAIN)) {
            com.vmware.identity.idm.LockoutPolicy idmLP = this.idmClient.getLockoutPolicy(tenant);
            com.vmware.identity.idm.PasswordPolicy idmPP = this.idmClient.getPasswordPolicy(tenant);

            PasswordPolicy pp = new PasswordPolicy(
                    idmPP.getMinimumLength(),
                    idmPP.getMaximumLength(),
                    idmPP.getMinimumUppercaseCount(),
                    idmPP.getMinimumLowercaseCount(),
                    idmPP.getMinimumNumericCount(),
                    idmPP.getMinimumSpecialCharacterCount(),
                    idmPP.getPasswordLifetimeDays() / 30);
            LockoutPolicy lp = new LockoutPolicy(// TOIDO: is this mapping correct?
                    (int) idmLP.getFailedAttemptIntervalSec(),
                    idmLP.getMaxFailedAttempts(),
                    (int) idmLP.getAutoUnlockIntervalSec());

            UaaIdentityProviderDefinition config = new UaaIdentityProviderDefinition(pp, lp, false);

            identityProvider.setConfig(config);
        } else if ((data.getDomainType() == DomainType.EXTERNAL_DOMAIN)) {
            IIdentityStoreDataEx dataEx = data.getExtendedIdentityStoreData();
            if (dataEx == null) {
                throw new IllegalStateException(String.format(
                        "getExtendedIdentityStoreData should not be null. IdentityStore='%s'.", data.getName()));
            }

            LdapIdentityProviderDefinition config = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                    dataEx.getConnectionStrings().iterator().next(),
                    dataEx.getUserName(),
                    dataEx.getPassword(),
                    dataEx.getUserBaseDn(),
                    null,
                    dataEx.getGroupBaseDn(),
                    null,
                    "email",
                    null,
                    null,
                    true,
                    true,
                    Integer.MAX_VALUE, dataEx.getCertificates() != null && dataEx.getCertificates().size() > 0);

            identityProvider.setConfig(config);
        } else {
            throw new IllegalStateException(
                    String.format("Unexpected domain type '%s'.", data.getDomainType().toString()));
        }

        identityProvider.setIdentityZoneId(tenant);
        identityProvider.setActive(true);

        return identityProvider;
    }
}
