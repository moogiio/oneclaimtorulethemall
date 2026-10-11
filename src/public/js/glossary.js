// "AD FS words explained": the terms people new to AD FS meet in this app.
export const GLOSSARY = [
  ['AD FS', 'Active Directory Federation Services. It lets users sign in to applications with their Windows account and tells each application who they are.'],
  ['Application (relying party trust)', 'An application that lets AD FS sign its users in, such as Zoom or your expenses app. AD FS Management calls it a relying party trust.'],
  ['Identity provider (claims provider trust)', 'Where users come from: your own Active Directory, or a partner company\'s AD FS whose users may sign in to your applications.'],
  ['Claim', 'One piece of information about the user that AD FS sends, such as the e-mail address, the name or an AD group.'],
  ['Claim type', 'The name of a claim, usually a URL like http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress. The application\'s setup guide says which names it expects.'],
  ['Claim rule', 'An instruction that decides which claims AD FS sends or accepts, or whether a user gets in. This app writes them for you.'],
  ['Name ID', 'The claim that tells a SAML application who the user is. Most SAML applications need one, often the e-mail address.'],
  ['Access control policy', 'A ready-made setting for who gets in, like "Permit everyone" or "Permit specific group". AD FS 2016 and later use them instead of access rules.'],
  ['Issuer', 'Who issued a claim. AD AUTHORITY means Active Directory itself, so the claim can be trusted.'],
  ['AD group and SID', 'Groups in Active Directory. AD FS compares groups by their SID, a unique ID like S-1-5-21-…. You type the name, the export looks up the SID on the AD FS server.'],
  ['Token', 'The signed message with the claims that AD FS sends to the application after a sign-in.'],
  ['Metadata', 'A file an application publishes, at a URL or as a download, with its identifier, sign-in URLs, certificates and often the claims it wants. AD FS can set up the trust from it in one go.'],
  ['SAML 2.0 and WS-Federation', 'Two ways an application can sign users in through AD FS. Most cloud applications use SAML; older Microsoft-based ones often use WS-Federation.'],
  ['Identifier', 'The unique name of an application in AD FS, often its URL. SAML applications call it entity ID or audience, WS-Federation applications call it realm.'],
  ['Reply URL', 'Where AD FS sends the user back to, with the token. SAML applications call it ACS URL.'],
  ['Primary AD FS server', 'In an AD FS farm with the Windows Internal Database, the one server where changes are made. The others copy them.'],
];

export const glossary = {
  glossaryItems() {
    return GLOSSARY;
  },

  openGlossary() {
    this.$refs.glossaryDialog.showModal();
  },

  closeGlossary() {
    this.$refs.glossaryDialog.close();
  },
};
