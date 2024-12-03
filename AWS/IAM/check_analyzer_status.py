def check_analyzer_status(client):
    """
    Checks the status of IAM Access Analyzers.

    Returns:
        dict: A summary of the findings.
    """
    print("----- Checking IAM Access Analyzer Status -----")
    try:
        # Create a client for the Access Analyzer service
        analyzers = client.list_analyzers().get("analyzers", [])
        
        if not analyzers:
            return {"status": "No IAM Access Analyzers found."}
        
        analyzer_details = []
        for analyzer in analyzers:
            name = analyzer.get("name")
            status = client.get_analyzer(analyzerName=name)["analyzer"]["status"]
            analyzer_details.append({"name": name, "status": status})
        
        return {"analyzers": analyzer_details}

    except Exception as e:
        return {"error": str(e)}
