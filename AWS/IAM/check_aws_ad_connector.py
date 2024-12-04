import boto3
def check_aws_ad_connector(client):
    """
    Checks if AWS Managed Microsoft AD or AD Connector is enabled.
    Returns a formatted dictionary with the findings.
    """
    print("----- Checking if AWS Managed Microsoft AD or AD Connector is enabled -----")
    
    try:
        # Create a client for AWS Directory Service
        directory_client = boto3.client('ds')

        # List directories
        directories = directory_client.describe_directories().get('DirectoryDescriptions', [])
        
        if not directories:
            return {
                "Topic": "Authentication & authorization for access",
                "Requirement": "Directory services",
                "Need to Achieve": "AWS AD connect can be utilized to connect with the existing AD.",
                "Function Used": "check_aws_ad_connector",
                "Results": {
                    "Summary": "(-) No AWS Directory Service directories found.",
                    "Directories Found": "None"
                }
            }

        ad_connector_enabled = False
        managed_ad_enabled = False
        
        # Check each directory
        for directory in directories:
            directory_type = directory['Type']
            
            if directory_type == 'MicrosoftAD':
                managed_ad_enabled = True
            elif directory_type == 'ADConnector':
                ad_connector_enabled = True

        # Determine the result based on the status of directories
        if managed_ad_enabled and ad_connector_enabled:
            summary = "(+) Both AWS Managed Microsoft AD and AD Connector are enabled."
            directories_found = "Both AWS Managed Microsoft AD and AD Connector are enabled."
        elif managed_ad_enabled:
            summary = "(+) AWS Managed Microsoft AD is enabled."
            directories_found = "AWS Managed Microsoft AD is enabled."
        elif ad_connector_enabled:
            summary = "(+) AWS AD Connector is enabled."
            directories_found = "AWS AD Connector is enabled."
        else:
            summary = "(-) Neither AWS Managed Microsoft AD nor AD Connector is enabled."
            directories_found = "Neither AWS Managed Microsoft AD nor AD Connector is enabled."

        # Prepare the result
        result = {
            "Topic": "Authentication & authorization for access",
            "Requirement": "Directory services",
            "Need to Achieve": "AWS AD connect can be utilized to connect with the existing AD.",
            "Function Used": "check_aws_ad_connector",
            "Results": {
                "Summary": summary,
                "Directories Found": directories_found
            }
        }

        return result

    except Exception as e:
        return {
            "Topic": "Authentication & authorization for access",
            "Requirement": "Directory services",
            "Need to Achieve": "AWS AD connect can be utilized to connect with the existing AD.",
            "Function Used": "check_aws_ad_connector",
            "Results": {
                "Error": f"Error during AD Connector check: {str(e)}"
            }
        }
