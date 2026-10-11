// Metadata files as vendors and partners hand them out, for the tests.

// Self-signed test certificates (openssl): valid 2026-10-11 to 2108-11-30
// (the end as GeneralizedTime), and 2020-01-01 to 2021-01-01.
export const LONG_CERT = 'MIICFDCCAX2gAwIBAgIUMjAOBtYrdcN1VL3pWxifkbUXaS0wDQYJKoZIhvcNAQELBQAwGzEZMBcGA1UEAwwQbG9uZy5leGFtcGxlLmNvbTAgFw0yNjEwMTExMTUxNDdaGA8yMTA4MTEzMDExNTE0N1owGzEZMBcGA1UEAwwQbG9uZy5leGFtcGxlLmNvbTCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAttiVbQP9rYSrCWprVrsCEid+lrLg/jz5UNSPMcEwl7ioLz6xwQvLCvlF8Nkn8i5ZXQjItkzSN99dCNnXcDnLhfxjZgf78K5xNxI9MLTu8+vYqZeWws1zXyJobU7YGSOtWEELF68dcBkThvl+h7AKBvNU8Uww0yr2scipcwzHIXECAwEAAaNTMFEwHQYDVR0OBBYEFLCdzMVytR/Y2rrBuO/xeSfVGtlCMB8GA1UdIwQYMBaAFLCdzMVytR/Y2rrBuO/xeSfVGtlCMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAaYvUZHEfXvswgYWf4fh79+vB16183Bz5OOHJ0UAD/vI3HoJEED66uwvk5PJNaKf2qWuZEpgiN8NXAa9vv5IDfcUA7Lb3Z4mcUOIHV+a2DSZyuJ4Ri2Y+lRjYZRnimu/nhmGgK/QjXwln0msrsTHp4skCqAk23YnwEf9rCA1cJ8c=';
export const OLD_CERT = 'MIIBozCCAQwCAQEwDQYJKoZIhvcNAQELBQAwGjEYMBYGA1UEAwwPb2xkLmV4YW1wbGUuY29tMB4XDTIwMDEwMTAwMDAwMFoXDTIxMDEwMTAwMDAwMFowGjEYMBYGA1UEAwwPb2xkLmV4YW1wbGUuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDnu+EDYngrH8KTAcK3otySnm6wjlgYgs0uN/v0yIOLk5FeImVZvIwH/em77bzQSUXSpkGlPrDwp4vLlU0feYskQgEhzqImowHIGMVHNJKk+WOcPAO6rvmn9NDik080TDmkeSzl/fXh72mep/P5JcfP8DBTE55WbcGK0goTUoc64wIDAQABMA0GCSqGSIb3DQEBCwUAA4GBAF5slUWXfDVpmZ7cs3ZO6I8OXF6kBewS739nZwBx7ynM8pSpf8fL2/t9T3qqccobxn7UIlkLaR/VLaxotN1uSZ3xSOCO/7ITEwa3LuEqWAuNb1Vhave5CBZt3Sobi3A/ppuRUyD+CNOotB3+b7sLM5uU927OAyOf47DtdCEgjUkL';

// Written the way vendors ship it: md: prefixes, a signing and an encryption
// certificate, an Artifact endpoint first and the POST one as the default.
export const SP_METADATA = `<?xml version="1.0" encoding="UTF-8"?>
<!-- Expenses <b>metadata</b> -->
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
    entityID="https://expenses.example.com/saml?tenant=1&amp;x=2">
  <md:SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${LONG_CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:KeyDescriptor use="encryption"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>${LONG_CERT}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://expenses.example.com/saml/logout"/>
    <md:NameIDFormat>
      urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
    </md:NameIDFormat>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact" Location="https://expenses.example.com/saml/artifact" index="0"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://expenses.example.com/saml/acs" index="2"/>
    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://expenses.example.com/saml/acs-default" index="5" isDefault="true"/>
    <md:AttributeConsumingService index="0">
      <md:ServiceName xml:lang="en">Expenses</md:ServiceName>
      <md:RequestedAttribute Name="urn:oid:0.9.2342.19200300.100.1.3" FriendlyName="mail" isRequired="true"/>
      <md:RequestedAttribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname"/>
      <md:RequestedAttribute Name="department" FriendlyName="Department"/>
      <md:RequestedAttribute Name="urn:example:costcenter" FriendlyName="Cost
        center"/>
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
  <md:Organization><md:OrganizationName xml:lang="sv">Exempel AB, Malmö</md:OrganizationName></md:Organization>
</md:EntityDescriptor>
`;

export const WSFED_METADATA = `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
<EntityDescriptor entityID="urn:intranet" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:wsa="http://www.w3.org/2005/08/addressing">
  <RoleDescriptor xsi:type="fed:ApplicationServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
    <fed:PassiveRequestorEndpoint><wsa:EndpointReference><wsa:Address><![CDATA[https://intranet.example.com/]]></wsa:Address></wsa:EndpointReference></fed:PassiveRequestorEndpoint>
  </RoleDescriptor>
</EntityDescriptor>
</EntitiesDescriptor>`;

export const IDP_METADATA = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="http://fabrikam.example.com/adfs/services/trust">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://fabrikam.example.com/adfs/ls/"/>
  </IDPSSODescriptor>
</EntityDescriptor>`;
