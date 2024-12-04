import boto3
def check_analyzer_status(client):
    """
    Checks the status of IAM Access Analyzers.
    Returns a dictionary formatted for the PDF.
    """
    print("----- Checking IAM Access Analyzer Status -----")

    try:
        # Create a client for the Access Analyzer service
        accessanalyzer_client = boto3.client('accessanalyzer')

        # List IAM Access Analyzers
        analyzers = accessanalyzer_client.list_analyzers().get("analyzers", [])
        analyzer_output = []

        if not analyzers:
            analyzer_output.append("No IAM Access Analyzers found.")
        else:
            for analyzer in analyzers:
                name = analyzer.get("name")
                status = accessanalyzer_client.get_analyzer(analyzerName=name)["analyzer"]["status"]
                analyzer_output.append(f"Analyzer: {name}, Status: {status}")

        # Prepare the result
        result = {
            "Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Rules for granting and revoking access",
            "Need to Achieve": "Need to check IAM access analyzer is enabled.",
            "Function Used": "check_analyzer_status",
            "Results": {
                "Status": analyzer_output
            }
        }

        return result

    except Exception as e:
        return {
            "  Topic": "Governance procedures for access rights, identity & privileges",
            "Requirement": "Rules for granting and revoking access",
            "Need to Achieve": "Need to check IAM access analyzer is enabled.",
            "Function Used": "check_analyzer_status",
            "Results": {
                "Error": f"Error checking IAM Access Analyzer status: {str(e)}"
            }
        }

