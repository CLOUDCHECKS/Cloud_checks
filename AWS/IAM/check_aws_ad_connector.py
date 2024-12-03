def check_aws_ad_connector(client):
    """
    Checks if AWS Managed Microsoft AD or AD Connector is enabled.

    Returns:
        dict: A summary of the findings.
    """
    print("----- Checking if AWS Managed Microsoft AD or AD Connector is enabled -----")
    try:
        # Create a client for AWS Directory Service
        directory_client = client

        # List directories
        directories = directory_client.describe_directories().get('DirectoryDescriptions', [])
        
        if not directories:
            return {"status": "No AWS Directory Service directories found."}
        
        ad_connector_enabled = False
        managed_ad_enabled = False
        
        # Check each directory
        for directory in directories:
            directory_type = directory['Type']
            
            if directory_type == 'MicrosoftAD':
                managed_ad_enabled = True
            elif directory_type == 'ADConnector':
                ad_connector_enabled = True
        
        # Prepare the result as a dictionary
        result = {
            "ad_connector_enabled": ad_connector_enabled,
            "managed_ad_enabled": managed_ad_enabled,
        }

        return result

    except Exception as e:
        return {"error": str(e)}
