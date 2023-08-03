import requests
import json
# Fill in Parameters and values for Snyk Paramaters Line 5-8, Jira Params Line 16-19 & 68-69 & 101
# Jira Param #101 is the name of the component option

#Snyk Parameters
org_id="XXXXXXXXX"
project_id="XXXXXXXXX"
snyk_token="XXXXXXXXX"
snyk_headers = {
  'Authorization': 'token '+snyk_token,
  'Content-Type': 'application/json'
}



# Jira server details
JIRA_URL = 'XXXXXXXXX'
USERNAME = 'XXXXXXXXX
PASSWORD = 'XXXXXXXXX'


#Pull in project info from Snyk
snyk_url="https://snyk.io/api/v1/org/"+org_id+"/project/"+project_id
snyk_body={}

response = requests.request("GET", snyk_url, headers=snyk_headers, data=snyk_body)
response_dict = response.json()
crit_count=str((response_dict['issueCountsBySeverity']['critical']))
proj_name=response_dict['name']
proj_link=response_dict['browseUrl']

#Pull in list of critical issues from the project
snyk_url="https://snyk.io/api/v1/org/"+org_id+"/project/"+project_id+"/aggregated-issues"

snyk_body= json.dumps({
  "includeDescription": False,
  "includeIntroducedThrough": False,
  "filters": {
    "severities": [
      "critical"
    ],
    "exploitMaturity": [
      "mature",
      "proof-of-concept",
      "no-known-exploit",
      "no-data"
    ],
    "types": [
      "vuln",
      "license"
    ],
    "ignored": False,
    "patched": False,
    "priority": {
      "score": {
        "min": 0,
        "max": 1000
      }
    }
  }
})

response = requests.request("POST", snyk_url, headers=snyk_headers, data=snyk_body)
response_dict = response.json()


# Jira issue details
PROJECT_KEY = 'XXXXXXXXX'  # Replace 'PROJECT' with your actual project key
ISSUE_TYPE = 'XXXXXXXXX'      # Replace 'Task' with the desired issue type
SUMMARY = proj_name+' - ' +crit_count + ' Critical Vulnerabilities'
DESCRIPTION = 'See SNYK Url here:      ' +proj_link + '\n'
DESCRIPTION +='\n'
DESCRIPTION +='\n'
DESCRIPTION +='\n'
DESCRIPTION += '||*Package*||*Title*||*Snyk CVSS*||*Maturity*||*URL*||\n'

desc_count=1
while response_dict['issues']:
	issue = response_dict['issues'].pop()
	DESCRIPTION += "|"+issue['pkgName']+"|"+issue['issueData']['title']+ "|"+str(issue['issueData']['cvssScore'])+"|"+issue['priority']['factors'][0]['description']+ "|["+ issue['issueData']['url'] + "]| \n"
	desc_count+=1

def create_jira_ticket():
    auth = (USERNAME, PASSWORD)
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }

    data = {
        'fields': {
            'project': {
                'key': PROJECT_KEY
            },
            'summary': SUMMARY,
            'description': DESCRIPTION,
            'issuetype': {
                'name': ISSUE_TYPE
            },
            'components': [{
            'name': 'XXXXXXX'}]
            
        }
    }

    url = f"{JIRA_URL}/rest/api/2/issue/"
    response = requests.post(url, auth=auth, headers=headers, data=json.dumps(data))

    if response.status_code == 201:
        print(f"Jira ticket '{response.json()['key']}' created successfully.")
    else:
        print(f"Failed to create Jira ticket. Status code: {response.status_code}, Error message: {response.text}")

if __name__ == "__main__":
    create_jira_ticket()
