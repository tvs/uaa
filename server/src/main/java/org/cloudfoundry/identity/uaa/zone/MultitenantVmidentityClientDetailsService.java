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
package org.cloudfoundry.identity.uaa.zone;

import static org.cloudfoundry.identity.uaa.util.CompareUtils.compareToList;
import static org.cloudfoundry.identity.uaa.util.CompareUtils.compareToMap;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.api.ldap.model.exception.LdapEntryAlreadyExistsException;
import org.cloudfoundry.identity.uaa.client.MultitenantClientDetailsService;
import org.cloudfoundry.identity.uaa.client.VmidentityDataAccessException;
import org.cloudfoundry.identity.uaa.oauth.client.ClientConstants;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.Validate;
import org.cloudfoundry.identity.uaa.util.VmidentityUtils;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.ClientAlreadyExistsException;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationException;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.util.Assert;

import com.google.common.primitives.Ints;
import com.vmware.identity.idm.DuplicatedOIDCClientException;
import com.vmware.identity.idm.NoSuchOIDCClientException;
import com.vmware.identity.idm.OIDCClient;
import com.vmware.identity.idm.client.CasIdmClient;

public class MultitenantVmidentityClientDetailsService implements MultitenantClientDetailsService {

    private static final Log logger = LogFactory.getLog(MultitenantVmidentityClientDetailsService.class);

    private static final String CLIENT_FIELDS = "client_id, client_secret, resource_ids, scope, "
            + "authorized_grant_types, web_server_redirect_uri, authorities, access_token_validity, "
            + "refresh_token_validity, additional_information, autoapprove, lastmodified";

    private final CasIdmClient idmClient;
    private final PasswordEncoder passwordEncoder;

    public MultitenantVmidentityClientDetailsService(CasIdmClient idmClient, PasswordEncoder passwordEncoder) throws NoSuchAlgorithmException {
        Assert.notNull(idmClient, "CasIdmClient required");
        this.idmClient = idmClient;
        this.passwordEncoder = passwordEncoder;
    }

    public List<ClientDetails> query(String filter, String sortBy, boolean ascending) {
        logger.debug("Querying clients with filter: " + filter);

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            Collection<OIDCClient> clients = idmClient.getOIDCClients(tenant, filter);

            List<ClientDetails> details = new ArrayList<ClientDetails>(clients.size());
            for (OIDCClient client : clients) {
                details.add(mapOIDCClient(client, tenant, idmClient, passwordEncoder));
            }

            if (sortBy != null) {
                sortClientDetails(details, sortBy, ascending);
            }

            return details;
        } catch (Exception e) {
            logger.error("Unable to query clients by filter '" + filter + "'", e);
            throw new VmidentityDataAccessException("Unable to query users by filter: " + filter);
        }
    }

    @Override
    public void addClientDetails(ClientDetails clientDetails) throws ClientAlreadyExistsException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            String encodedSecret = null;
            if (clientDetails.getClientSecret() != null) {
                encodedSecret = passwordEncoder.encode(clientDetails.getClientSecret());
            }
            OIDCClient client = mapClientDetails(clientDetails, encodedSecret);
            idmClient.addOIDCClient(tenant, client);
        } catch (DuplicatedOIDCClientException e) {
            logger.error("Client with ID already exists: " + clientDetails.getClientId(), e);
            throw new ClientAlreadyExistsException("Client already exists: " + clientDetails.getClientId());
        } catch (LdapEntryAlreadyExistsException e) {
            logger.error("Client with registered redirect already exists: " + clientDetails.getRegisteredRedirectUri(), e);
            throw new ClientAlreadyExistsException("Client with registered redirect already exists: " + clientDetails.getRegisteredRedirectUri());
        } catch (Exception e) {
            logger.error("Unable to add client details", e);
            throw new VmidentityDataAccessException("Unable to add client details");
        }

    }

    @Override
    public void updateClientDetails(ClientDetails clientDetails) throws NoSuchClientException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            ClientDetails previous = loadClientByClientId(clientDetails.getClientId());
            OIDCClient client = mapClientDetails(clientDetails, previous.getClientSecret());
            idmClient.setOIDCClient(tenant, client);
        } catch (NoSuchOIDCClientException e) {
            logger.error("No client found with id: " + clientDetails.getClientId() + " in identity zone " + IdentityZoneHolder.get().getName(), e);
            throw new NoSuchClientException("No client found with id = " + clientDetails.getClientId() + " in identity zone " + IdentityZoneHolder.get().getName());
        } catch (Exception e) {
            logger.error("Unable to update client details with id: " + clientDetails.getClientId(), e);
            throw new VmidentityDataAccessException("Unable to update client details");
        }
    }

    @Override
    public void updateClientSecret(String clientId, String secret) throws NoSuchClientException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            ClientDetails clientDetails = loadClientByClientId(clientId);
            OIDCClient client = mapClientDetails(clientDetails, passwordEncoder.encode(secret));
            idmClient.setOIDCClient(tenant, client);
        } catch (NoSuchOIDCClientException e) {
            logger.error("No client found with id: " + clientId + " in identity zone " + IdentityZoneHolder.get().getName(), e);
            throw new NoSuchClientException("No client found with id = " + clientId + " in identity zone " + IdentityZoneHolder.get().getName());
        } catch (Exception e) {
            logger.error("Unable to update client secret with id: " + clientId, e);
            throw new VmidentityDataAccessException("Unable to update client secret");
        }
    }

    @Override
    public void removeClientDetails(String clientId) throws NoSuchClientException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            idmClient.deleteOIDCClient(tenant, clientId);
        } catch (NoSuchOIDCClientException e) {
            logger.error("No client found with id = " + clientId, e);
            throw new NoSuchClientException("No client found with id = " + clientId);
        } catch (Exception e) {
            logger.error("Unable to remove client details with id = " + clientId, e);
            throw new VmidentityDataAccessException("Unable to remvoe client details");
        }
    }

    @Override
    public List<ClientDetails> listClientDetails() {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            Collection<OIDCClient> clients = idmClient.getOIDCClients(tenant);

            List<ClientDetails> details = new ArrayList<ClientDetails>(clients.size());
            for (OIDCClient client : clients) {
                details.add(mapOIDCClient(client, tenant, idmClient, passwordEncoder));
            }

            return details;
        } catch (Exception e) {
            logger.error("Unable to list client details for identity zone: " + IdentityZoneHolder.get().getName(), e);
            throw new VmidentityDataAccessException("Unable to list client details");
        }
    }

    @Override
    public ClientDetails loadClientByClientId(String clientId) throws ClientRegistrationException {
        ClientDetails details;

        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            details = mapOIDCClient(idmClient.getOIDCClient(tenant, clientId), tenant, idmClient, passwordEncoder);
        } catch (NoSuchOIDCClientException e) {
            logger.error("Unable to load client with id: " + clientId, e);
            throw new NoSuchClientException("No client with requested id: " + clientId);
        } catch (Exception e) {
            logger.error("An error occurred loading client with id: " + clientId, e);
            throw new VmidentityDataAccessException("Unable to load client with id: " + clientId);
        }

        return details;
    }

    @Override
    public int deleteByIdentityZone(String zoneId) {
        try {
            String tenant = VmidentityUtils.getTenantName(zoneId, idmClient);
            Collection<OIDCClient> clients = idmClient.getOIDCClients(tenant);

            for (OIDCClient client : clients) {
                idmClient.deleteOIDCClient(tenant, client.getClientId());
            }

            return clients.size();
        } catch (Exception e) {
            logger.error("Unable to delete clients for identity zone: " + zoneId, e);
            throw new VmidentityDataAccessException("Unable to delete clients for identity zone: " + zoneId);
        }
    }

    @Override
    public int deleteByOrigin(String origin, String zoneId) {
        return 0;
    }

    @Override
    public Log getLogger() {
        return logger;
    }

    @Override
    public int getTotalCount() {
        try {
            int count = 0;
            Collection<String> tenants = idmClient.getAllTenants();

            for (String tenant : tenants) {
                Collection<OIDCClient> clients = idmClient.getOIDCClients(tenant);
                count += clients.size();
            }

            return count;
        } catch (Exception e) {
            logger.error("Unable to enumerate clients", e);
            throw new VmidentityDataAccessException("Unable to enumerate clients");
        }
    }

    @Override
    public void addClientSecret(String clientId, String newSecret) throws NoSuchClientException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            ClientDetails clientDetails = loadClientByClientId(clientId);

            String encodedNewSecret = passwordEncoder.encode(newSecret);
            StringBuilder newSecretBuilder = new StringBuilder().append(clientDetails.getClientSecret() == null ? "" : clientDetails.getClientSecret() + " ").append(encodedNewSecret);
            OIDCClient client = mapClientDetails(clientDetails, newSecretBuilder.toString());
            idmClient.setOIDCClient(tenant, client);
        } catch (NoSuchOIDCClientException e) {
            logger.error("No client found with id: " + clientId + " in identity zone " + IdentityZoneHolder.get().getName(), e);
            throw new NoSuchClientException("No client found with id = " + clientId + " in identity zone " + IdentityZoneHolder.get().getName());
        } catch (Exception e) {
            logger.error("Unable to add client secret with id: " + clientId, e);
            throw new VmidentityDataAccessException("Unable to add client secret");
        }
    }

    @Override
    public void deleteClientSecret(String clientId) throws NoSuchClientException {
        try {
            String tenant = VmidentityUtils.getTenantName(idmClient);
            ClientDetails clientDetails = loadClientByClientId(clientId);
            String clientSecret = clientDetails.getClientSecret().split(" ")[1];
            OIDCClient client = mapClientDetails(clientDetails, clientSecret);
            idmClient.setOIDCClient(tenant, client);
        } catch (NoSuchOIDCClientException e) {
            logger.error("No client found with id: " + clientId + " in identity zone " + IdentityZoneHolder.get().getName(), e);
            throw new NoSuchClientException("No client found with id = " + clientId + " in identity zone " + IdentityZoneHolder.get().getName());
        } catch (Exception e) {
            logger.error("Unable t update client secret with id: " + clientId, e);
            throw new VmidentityDataAccessException("Unable to update client secret");
        }
    }

    private static OIDCClient mapClientDetails(ClientDetails details, String clientSecret) {
        OIDCClient.Builder builder = new OIDCClient.Builder(details.getClientId());
        // It would be better to treat these as 'Collection' types instead...
        builder.redirectUris(convertToList(details.getRegisteredRedirectUri()));
        builder.resourceIds(convertToList(details.getResourceIds()));
        builder.scopes(convertToList(details.getScope()));
        builder.authorizedGrantTypes(convertToList(details.getAuthorizedGrantTypes()));
        builder.authorities(authoritiesToListOfStrings(details.getAuthorities()));

        // builder.accessTokenValiditySeconds(details.getAccessTokenValiditySeconds()); TODO access token validity
        // builder.refreshTokenValiditySeconds(details.getRefreshTokenValiditySeconds()); TODO refresh token validity

        if (clientSecret != null) {
            builder.clientSecret(clientSecret);
        }

        Set<String> autoApproveScopes = new HashSet<String>();
        Map<String, Object> additionalInformation = details.getAdditionalInformation();
        Object autoApprovedFromAddInfo = additionalInformation.get(ClientConstants.AUTO_APPROVE);
        if (autoApprovedFromAddInfo != null) {
           if (JsonUtils.isTrue(autoApprovedFromAddInfo)) {
               autoApproveScopes.add("true");
           } else if (autoApprovedFromAddInfo instanceof Collection<?>) {
               @SuppressWarnings("unchecked")
               Collection<? extends String> approvedScopes = (Collection<? extends String>) autoApprovedFromAddInfo;
               autoApproveScopes.addAll(approvedScopes);
           }
        }
        builder.autoApproveScopes(convertToList(autoApproveScopes));

        return builder.build();
    }

    private static BaseClientDetails mapOIDCClient(OIDCClient client, String tenant, CasIdmClient idmClient, PasswordEncoder passwordEncoder) throws Exception {
        BaseClientDetails details = new BaseClientDetails();
        details.setClientId(client.getClientId());
        details.setClientSecret(client.getClientSecret());
        details.setRegisteredRedirectUri(new HashSet<String>(client.getRedirectUris()));
        details.setAccessTokenValiditySeconds(
                Ints.saturatedCast(idmClient.getMaximumBearerTokenLifetime(tenant) / 1000));
        details.setRefreshTokenValiditySeconds(
                Ints.saturatedCast(idmClient.getMaximumBearerRefreshTokenLifetime(tenant) / 1000));

        if (client.getResourceIds() != null) {
            details.setResourceIds(client.getResourceIds());
        }

        if (client.getScopes() != null) {
            details.setScope(client.getScopes());
        }

        if (client.getAuthorizedGrantTypes() != null) {
            details.setAuthorizedGrantTypes(client.getAuthorizedGrantTypes());
        }

        if (client.getAuthorities() != null) {
            details.setAuthorities(AuthorityUtils.createAuthorityList(client.getAuthorities().toArray(new String[0])));
        }

        if (client.getAutoApproveScopes() != null) {
            details.setAutoApproveScopes(client.getAutoApproveScopes());
        }

        if (client.getAdditionalInformation() != null) {
            details.setAdditionalInformation(client.getAdditionalInformation());
        }

        return details;
    }

    private static List<String> authoritiesToListOfStrings(Collection<GrantedAuthority> authorities) {
        List<String> stringAuthorities = new ArrayList<String>(authorities.size());

        for (GrantedAuthority authority : authorities) {
            stringAuthorities.add(authority.getAuthority());
        }

        return stringAuthorities;
    }

    private static List<String> convertToList(Collection<String> collection) {
        List<String> list = Collections.emptyList();
        if (collection != null) {
            list = new ArrayList<String>(collection.size());
            list.addAll(collection);
        }
        return list;
    }

    private void sortClientDetails(List<ClientDetails> list, String sortBy, boolean ascending) {
        validateOrderBy(sortBy);
        switch (sortBy.toLowerCase()) {
            case "client_id":
                list.sort(Comparator.comparing(ClientDetails::getClientId));
                break;
            case "client_secret":
                list.sort(Comparator.comparing(ClientDetails::getClientSecret));
                break;
            case "resource_ids":
                list.sort((a, b) -> compareToList(a.getResourceIds(), b.getResourceIds()));
                break;
            case "scope":
                list.sort((a, b) -> compareToList(a.getScope(), b.getScope()));
                break;
            case "authorized_grant_types":
                list.sort((a, b) -> compareToList(a.getAuthorizedGrantTypes(), b.getAuthorizedGrantTypes()));
                break;
            case "web_server_redirect_uri":
                list.sort((a, b) -> compareToList(a.getRegisteredRedirectUri(), b.getRegisteredRedirectUri()));
                break;
            case "authorities":
                list.sort((a, b) -> compareToList(a.getAuthorities(), b.getAuthorities()));
                break;
            case "access_token_validity":
                list.sort(Comparator.comparing(ClientDetails::getAccessTokenValiditySeconds));
                break;
            case "refresh_token_validity":
                list.sort(Comparator.comparing(ClientDetails::getRefreshTokenValiditySeconds));
                break;
            case "additional_information":
                list.sort((a, b) -> compareToMap(a.getAdditionalInformation(), b.getAdditionalInformation()));
                break;
            case "autoapprove":
                list.sort((a, b) -> compareToList(((BaseClientDetails) a).getAutoApproveScopes(), ((BaseClientDetails) b).getAutoApproveScopes()));
                break;
            case "lastmodified":
                // Do nothing
                break;
        }

        if (!ascending) {
            Collections.reverse(list);
        }
    }

    private void validateOrderBy(String orderBy) throws IllegalArgumentException {
        Validate.validateOrderBy(orderBy.toLowerCase(), CLIENT_FIELDS.toLowerCase());
    }

}
