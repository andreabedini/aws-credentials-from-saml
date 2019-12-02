function parseSAMLDocument(samlDocument) {
  // decode the XML SAML response
  const samlXMLDoc = decodeURIComponent(unescape(window.atob(samlDocument)))
  const parser = new DOMParser()
  const doc = parser.parseFromString(samlXMLDoc, "text/xml")

  // find the list of roles we can assume
  const roleNodes = doc.querySelectorAll('[Name="https://aws.amazon.com/SAML/Attributes/Role"] AttributeValue')
  console.log(roleNodes)
  const roles = Array.from(roleNodes)
    .map(attribute => {
      const [roleArn, principalArn] = attribute.textContent.split(",")
      return {roleArn, principalArn}
    })

  console.log(roles)

  const sessionDuration = doc.querySelector('[Name="https://aws.amazon.com/SAML/Attributes/SessionDuration"] AttributeValue').textContent

  return {roles, sessionDuration}
}

async function assumeRoleWithSAML(principalArn, roleArn, sessionDuration, samlAssertion) {
  const formData = new URLSearchParams()
  formData.append("Action", "AssumeRoleWithSAML")
  formData.append("Version", "2011-06-15")
  formData.append("PrincipalArn", principalArn)
  formData.append("RoleArn", roleArn)
  formData.append("SAMLAssertion", samlAssertion)
  // formData.append("DurationSeconds", sessionDuration)

  console.log(formData.toString())

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

async function assumeRolesWithSAML(roles, sessionDuration, samlAssertion) {
  return Promise.all(roles.map(
    ({principalArn, roleArn}) =>
      assumeRoleWithSAML(principalArn, roleArn, sessionDuration, samlAssertion)
  ))
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

function formatCredentials(response) {
  // Unpack the response from assumeRoleWithSAML
  const {
    AssumeRoleWithSAMLResponse: {
      AssumeRoleWithSAMLResult: {
        AssumedRoleUser: {
          Arn: assumedRoleUserArn
        },
        Credentials: credentials
      }
    }
  } = response

  const roleName = assumedRoleUserArn.split("/")[1]

  // Prepare the shared credentials file for AWS CLI
  const str = `[${roleName}]
aws_access_key_id=${credentials.AccessKeyId}
aws_secret_access_key=${credentials.SecretAccessKey}
aws_session_token=${credentials.SessionToken}
    `

  return str
}

function onBeforeRequest(requestDetails) {
  const samlAssertion = requestDetails.requestBody.formData.SAMLResponse[0]
  const {roles, sessionDuration} = parseSAMLDocument(samlAssertion)

  /* Call AWS to assume all the roles using the SAML assertion */
  assumeRolesWithSAML(roles, sessionDuration, samlAssertion)
  .then(data => {
    console.log(data)
    // Format the credentials for the CLI
    const str = data.map(formatCredentials).join("\n")

    // Download the credentials file
    return downloadAs(str, "credentials")
  }).catch(e => {
    console.error(e)
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
