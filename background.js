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

function onBeforeRequest(requestDetails) {
  const samlDocument = requestDetails.requestBody.formData.SAMLResponse[0]

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

  // new bit

  assumeRoleWithSAML(roles[0].principalArn, roles[0].roleArn, samlDocument)
  .then(data => {
    const {
      AssumeRoleWithSAMLResponse: {
        AssumeRoleWithSAMLResult: {
          Credentials: credentials
        }
      }
    } = data
    const str = `[default]
aws_access_key_id=${credentials.AccessKeyId}
aws_secret_access_key=${credentials.SecretAccessKey}
aws_session_token=${credentials.SessionToken}
    `
    const blob = new Blob([str])
    const url = URL.createObjectURL(blob)
    return browser.downloads.download({
      url,
      filename: "credentials",
      conflictAction: "overwrite"
    })
  })
}

browser.webRequest.onBeforeRequest.addListener(
  onBeforeRequest,
  { urls: [ "https://signin.aws.amazon.com/saml" ] },
  ["requestBody"]
)
