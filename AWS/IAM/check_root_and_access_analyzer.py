import boto3
def check_root_and_access_analyzer(client):
    """
    Checks the status of the root user and IAM Access Analyzers.
    Returns a formatted dictionary with the findings.
    """
    print("----- Checking Root User Status and Access Analyzer -----")
    
    try:
        iam_client = client
        accessanalyzer_client = boto3.client('accessanalyzer')  # Correct Access Analyzer client

        # Initialize variables
        root_access_disabled = True
        active_analyzers = []
        disabled_analyzers = []

        # Check root user status
        root_user_summary = iam_client.get_account_summary()['SummaryMap']

        # Determine if root access is disabled
        if root_user_summary['AccountAccessKeysPresent'] > 0 or root_user_summary['AccountMFAEnabled'] == 0:
            root_access_disabled = False

        # Check Access Analyzers
        analyzers = accessanalyzer_client.list_analyzers().get("analyzers", [])
        for analyzer in analyzers:
            name = analyzer.get("name")
            status = analyzer.get("status")
            if status == "ACTIVE":
                active_analyzers.append(name)
            else:
                disabled_analyzers.append(name)

        # Format root user status
        root_status = "Root user is disabled." if root_access_disabled else "Root user is enabled."

        # Format access analyzer status
        analyzer_status_lines = []
        if active_analyzers:
            analyzer_status_lines.append(f"Enabled access analyzers: {', '.join(active_analyzers)}.")
        if disabled_analyzers:
            analyzer_status_lines.append(f"Disabled access analyzers: {', '.join(disabled_analyzers)}.")

        # Combine results into final output
        result = {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Strict control of special privileges –  duration, purpose, monitoring",
            "Need to Achieve": "Need to check Root user is disabled and admin user is limited. The activity should be monitored periodically using IAM access analyzer.",
            "Function Used": "check_root_and_access_analyzer",
            "Results": {
                "Root User Status": root_status,
                "Enabled Access Analyzers": active_analyzers if active_analyzers else "No active analyzers found.",
                "Disabled Access Analyzers": disabled_analyzers if disabled_analyzers else "No disabled analyzers found."
            }
        }

        return result

    except Exception as e:
        return {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Strict control of special privileges –  duration, purpose, monitoring",
            "Need to Achieve": "Need to check Root user is disabled and admin user is limited. The activity should be monitored periodically using IAM access analyzer.",
            "Function Used": "check_root_and_access_analyzer",
            "Results": {
                "Error": f"Error checking root user status and access analyzer: {str(e)}"
            }
        }
