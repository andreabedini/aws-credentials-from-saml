function parseSAMLDocument(samlDocument) {
  // decode the XML SAML response
  const samlXMLDoc = decodeURIComponent(unescape(window.atob(samlDocument)))
  const parser = new DOMParser()
  const doc = parser.parseFromString(samlXMLDoc, "text/xml")

  // find the list of roles we can assume
  const roleNodes = doc.querySelectorAll('[Name="https://aws.amazon.com/SAML/Attributes/Role"]')
  const roles = Array.from(roleNodes)
    .map(attribute => {
      const [roleArn, principalArn] = attribute.textContent.split(",")
      return {roleArn, principalArn}
    })

  return roles
}

async function assumeRoleWithSAML(principalArn, roleArn, samlAssertion) {
  const formData = new URLSearchParams()
  formData.append("Action", "AssumeRoleWithSAML")
  formData.append("Version", "2011-06-15")
  formData.append("PrincipalArn", principalArn)
  formData.append("RoleArn", roleArn)
  formData.append("SAMLAssertion", samlAssertion)

  const response = await fetch("https://sts.amazonaws.com", {
    method: "POST",
    headers: {
      'Accept': 'application/json',
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    body: formData
  })

  return response.json()
}

function downloadAs(string, filename) {
  const blob = new Blob([string])
  const url = URL.createObjectURL(blob)

  return browser.downloads.download({
    url,
    filename,
    conflictAction: "overwrite"
  })
}

function onBeforeRequest(requestDetails) {
  const samlDocument = requestDetails.requestBody.formData.SAMLResponse[0]
  const roles = parseSAMLDocument(samlDocument)

  /* Call AWS to assume a role using the SAML document
   *
   * TODO here we are only considering the first role in the SAML document.
   * In general the SAML document could specify multiple roles we can
   * assume and it would be good to cover those use cases too.  We could 1)
   * obtain credentials for all the roles and let the user choose which
   * role with the CLI profile flags 2) ask the user (from the browser)
   * which role to assume (introducing some sort of UI).
   */
  assumeRoleWithSAML(roles[0].principalArn, roles[0].roleArn, samlDocument)
  .then(data => {

    // Unpack the response from assumeRoleWithSAML
    const {
      AssumeRoleWithSAMLResponse: {
        AssumeRoleWithSAMLResult: {
          Credentials: credentials
        }
      }
    } = data

    // Prepare the shared credentials file for AWS CLI
    const str = `[default]
aws_access_key_id=${credentials.AccessKeyId}
aws_secret_access_key=${credentials.SecretAccessKey}
aws_session_token=${credentials.SessionToken}
    `

    // Download the credentials file
    return downloadAs(str, "credentials")
  }).catch(() => {
    // TODO notify the user in case something fails
  })

  // This is not a blocking handler, it's ok to return null
}

/* Install out onBeforeRequest handler
 *
 * See https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/API/webRequest/onBeforeRequest
 */
browser.webRequest.onBeforeRequest.addListener(
  onBeforeRequest,
  { urls: [ "https://signin.aws.amazon.com/saml" ] },
  ["requestBody"]
)
