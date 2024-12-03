def check_password_policy(client):
    """
    Checks if the account's password policy is configured correctly.

    Returns:
        dict: A summary of the findings.
    """
    print("----- Checking Password Policy -----")
    try:
        iam_client = client
        # Retrieve the account's password policy
        password_policy = iam_client.get_account_password_policy()['PasswordPolicy']
        
        # Extract policy parameters
        min_length = password_policy.get('MinimumPasswordLength', 0)
        require_uppercase = password_policy.get('RequireUppercase', False)
        require_lowercase = password_policy.get('RequireLowercase', False)
        require_numbers = password_policy.get('RequireNumbers', False)
        
        # Initialize a list to collect any policy issues
        issues = []
        
        # Check each policy requirement
        if min_length <= 12:
            issues.append(f"- Minimum password length is {min_length}, should be greater than 12.")
        if not require_uppercase:
            issues.append("- Password policy does not require uppercase letters.")
        if not require_lowercase:
            issues.append("- Password policy does not require lowercase letters.")
        if not require_numbers:
            issues.append("- Password policy does not require numbers.")
        
        # Prepare the result as a dictionary
        if not issues:
            result = {
                "status": "(+) Password policy meets the required standards: Uppercase, Lowercase, Number, Length > 12."
            }
        else:
            result = {
                "status": "(-) Password policy does not meet the required standards.",
                "issues": issues
            }
        
        return result

    except Exception as e:
        return {"error": str(e)}
