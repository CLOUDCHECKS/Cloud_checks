def check_password_policy(client):
    """
    Checks the account's password policy and evaluates if it meets security standards.
    Returns a formatted dictionary with the findings.
    """
    print("----- Checking Password Policy -----")
    
    try:
        # Retrieve the account's password policy
        password_policy = client.get_account_password_policy()['PasswordPolicy']

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

        # Prepare the result
        result = {
            "9) Topic": "Password management",
            "    Requirement": "12 character complex, alphanumeric password",
            "    Need to Achieve": "All IAM users should have a password policy enforced with the required standards.",
            "    Function Used": "check_password_policy",
            "    Results": {}
        }

        # Determine the final output message
        if not issues:
            result["Results"] = {
                "Summary": "(+) All IAM users have a password policy enforced with the required standards: Uppercase, Lowercase, Number, Length > 12."
            }
        else:
            result["Results"] = {
                "Summary": "(-) Password policy does not meet the required standards:",
                "Issues": issues
            }

        return result

    except client.exceptions.NoSuchEntityException:
        return {
            "Topic": "Password management",
            "Requirement": "12 character complex, alphanumeric password",
            "Need to Achieve": "All IAM users should have a password policy enforced with the required standards.",
            "Function Used": "check_password_policy",
            "Results": {
                "Summary": "(-) No password policy is set for the account."
            }
        }

    except Exception as e:
        return {
            "Topic": "Password management",
            "Requirement": "12 character complex, alphanumeric password",
            "Need to Achieve": "All IAM users should have a password policy enforced with the required standards.",
            "Function Used": "check_password_policy",
            "Results": {
                "Error": f"Error checking password policy: {str(e)}"
            }
        }
