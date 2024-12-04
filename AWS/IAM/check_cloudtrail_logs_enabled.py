import boto3
def check_cloudtrail_logs_enabled(client):
    """
    Checks if CloudTrail logs are enabled at the account level.
    Returns a JSON-friendly dictionary with the findings.
    """
    print("----- Checking if CloudTrail logs are enabled at the account level -----")
    
    logs_status = []

    try:
        # Create a CloudTrail client
        cloudtrail_client = boto3.client('cloudtrail')
        trails = cloudtrail_client.describe_trails()

        # If no trails are found
        if not trails['trailList']:
            return {
                "Topic": "Credential monitoring",
                "Requirement": "Log generation and retention of all user account related activity",
                "Need to Achieve": "CloudTrail logs should be enabled in the account level.",
                "Function Used": "check_cloudtrail_logs_enabled",
                "Results": {
                    "Summary": "(-) No CloudTrail trails found.",
                    "Trail Logs Status": []
                }
            }

        # Check logging status for each trail
        for trail in trails['trailList']:
            trail_name = trail['Name']
            try:
                status = cloudtrail_client.get_trail_status(Name=trail_name)
                if status.get('IsLogging', False):
                    logs_status.append({
                        "trail_name": trail_name,
                        "logging_status": "Enabled"
                    })
                else:
                    logs_status.append({
                        "trail_name": trail_name,
                        "logging_status": "Not Enabled"
                    })
            except cloudtrail_client.exceptions.TrailNotFoundException:
                logs_status.append({
                    "trail_name": trail_name,
                    "logging_status": "Trail Not Found"
                })

        # Generate the summary
        if logs_status:
            enabled_trails = [f"{log['trail_name']}" for log in logs_status if log['logging_status'] == "Enabled"]
            not_enabled_trails = [f"{log['trail_name']}" for log in logs_status if log['logging_status'] == "Not Enabled"]
            summary = []

            if enabled_trails:
                summary.append(f"(+) CloudTrail logging is enabled for: {', '.join(enabled_trails)}")
            if not_enabled_trails:
                summary.append(f"(-) CloudTrail logging is NOT enabled for: {', '.join(not_enabled_trails)}")
            return {
                "Topic": "Credential monitoring",
                "Requirement": "Log generation and retention of all user account related activity",
                "Need to Achieve": "CloudTrail logs should be enabled in the account level.",
                "Function Used": "check_cloudtrail_logs_enabled",
                "Results": {
                    "Summary": "\n".join(summary),
                    "Trail Logs Status": logs_status
                }
            }

        else:
            return {
                "Topic": "Credential monitoring",
                "Requirement": "Log generation and retention of all user account related activity",
                "Need to Achieve": "CloudTrail logs should be enabled in the account level.",
                "Function Used": "check_cloudtrail_logs_enabled",
                "Results": {
                    "Summary": "(-) No CloudTrail trails with logging enabled found.",
                    "Trail Logs Status": []
                }
            }

    except Exception as e:
        return {
            "Topic": "Credential monitoring",
            "Requirement": "Log generation and retention of all user account related activity",
            "Need to Achieve": "CloudTrail logs should be enabled in the account level.",
            "Function Used": "check_cloudtrail_logs_enabled",
            "Results": {
                "Summary": f"Error during CloudTrail log check: {str(e)}",
                "Trail Logs Status": []
            }
        }
