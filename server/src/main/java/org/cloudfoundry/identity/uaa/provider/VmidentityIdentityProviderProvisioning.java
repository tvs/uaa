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
import java.util.Iterator;
import java.util.List;

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;

import com.vmware.identity.idm.DomainType;
import com.vmware.identity.idm.IIdentityStoreData;
import com.vmware.identity.idm.IIdentityStoreDataEx;
import com.vmware.identity.idm.client.CasIdmClient;

public class VmidentityIdentityProviderProvisioning implements IdentityProviderProvisioning {

    private final CasIdmClient _idmClient;

    public VmidentityIdentityProviderProvisioning(CasIdmClient idmClient) {
        this._idmClient = idmClient;
    }

    @Override
    public IdentityProvider create(IdentityProvider identityProvider) {
        throw new IllegalStateException("creating a provider is not yet supported.");
    }

    @Override
    public IdentityProvider update(IdentityProvider identityProvider) {
        // no op; //todo
        return this.retrieve(identityProvider.getId());
    }

    @Override
    public IdentityProvider retrieve(String id) {
        try {
            String tenant = VmidentityUtils.getTenantName(this._idmClient.getSystemTenant());
            Collection<IIdentityStoreData> providers = this._idmClient.getProviders(
                    tenant, EnumSet.of(DomainType.SYSTEM_DOMAIN, DomainType.EXTERNAL_DOMAIN));

            if ((providers != null) && (providers.iterator() != null)) {
                Iterator<IIdentityStoreData> iter = providers.iterator();
                while (iter.hasNext()) {
                    IIdentityStoreData ids = iter.next();
                    if (ids.getName().equalsIgnoreCase(id)) {
                        return getIdentityProviderForStore(ids, tenant);
                    }
                }
            }
            return null;
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("Failed to retrieve provider Id '%s'.", id), ex);
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
            String tenant = VmidentityUtils.getTenantName(zoneId, this._idmClient.getSystemTenant());
            Collection<IIdentityStoreData> providers = this._idmClient.getProviders(
                    tenant, EnumSet.of(DomainType.SYSTEM_DOMAIN, DomainType.EXTERNAL_DOMAIN));

            List<IdentityProvider> result = new ArrayList<IdentityProvider>();
            if ((providers != null) && (providers.iterator() != null)) {
                Iterator<IIdentityStoreData> iter = providers.iterator();
                while (iter.hasNext()) {
                    result.add(getIdentityProviderForStore(iter.next(), tenant));
                }
            }
            return result;
        } catch (Exception ex) {
            throw new IllegalStateException(String.format("Failed to retrieve provider zoneId '%s', activeOnly ''.",
                    zoneId, (activeOnly ? "true" : "false")), ex);
        }
    }

    @Override
    public IdentityProvider retrieveByOrigin(String origin, String zoneId) {
        try {
            String tenant = VmidentityUtils.getTenantName(zoneId, this._idmClient.getSystemTenant());
            if (OriginKeys.UAA.equalsIgnoreCase(origin)) {
                // retrieve system domain provider

                Collection<IIdentityStoreData> provider = this._idmClient.getProviders(
                        tenant, EnumSet.of(DomainType.SYSTEM_DOMAIN));
                // todo: should get security domain name, not provider name.
                // Collection<SecurityDomain> domains = client.getSecurityDomains(tenant,
                // provider.iterator().next().getName());

                if ((provider == null) || (provider.iterator() == null) || (provider.iterator().hasNext() == false)) {
                    throw new IllegalStateException("System domain must exist.");
                }

                return getIdentityProviderForStore(provider.iterator().next(), tenant);
            } else if (OriginKeys.LDAP.equalsIgnoreCase(origin)) {
                Collection<IIdentityStoreData> provider = this._idmClient.getProviders(
                        tenant, EnumSet.of(DomainType.EXTERNAL_DOMAIN));

                // TODO: how do we mimic multiple IDSs ?
                if ((provider != null) && (provider.iterator() != null) && (provider.iterator().hasNext() == true)) {
                    return getIdentityProviderForStore(provider.iterator().next(), tenant);
                } else {
                    return null;
                }
            } else {
                throw new IllegalStateException(String.format("Unsupported origin", origin));
            }
        } catch (Exception ex) {
            throw new IllegalStateException(
                    String.format("Failed to retrieve provider origin '%s' zoneId '%s'.", origin, zoneId), ex);
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
                ((data.getDomainType() == DomainType.SYSTEM_DOMAIN) ? OriginKeys.UAA : OriginKeys.LDAP));
        identityProvider.setType(
                ((data.getDomainType() == DomainType.SYSTEM_DOMAIN) ? OriginKeys.UAA : OriginKeys.LDAP));
        if ((data.getDomainType() == DomainType.SYSTEM_DOMAIN)) {
            com.vmware.identity.idm.LockoutPolicy idmLP = this._idmClient.getLockoutPolicy(tenant);
            com.vmware.identity.idm.PasswordPolicy idmPP = this._idmClient.getPasswordPolicy(tenant);

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
