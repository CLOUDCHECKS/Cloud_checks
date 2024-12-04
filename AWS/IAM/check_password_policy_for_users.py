def check_password_policy_for_users(client):
    """
    Checks whether IAM users comply with the password policy enforced at the account level.
    Returns a JSON-friendly dictionary with users who do not comply and a summary.
    """
    print("----- Checking Password Policy Compliance for Users -----")
    
    users_not_compliant = []

    try:
        # Attempt to get the account's password policy
        try:
            password_policy = client.get_account_password_policy()['PasswordPolicy']
        except client.exceptions.NoSuchEntityException:
            return {
                "Topic": "Password management",
                "Requirement": "Strict adherence to password standards",
                "Need to Achieve": "All IAM users should have a password policy enforced with the required standards.",
                "Function Used": "check_password_policy_for_users",
                "Results": {
                    "Summary": "(-) No password policy set for the account.",
                    "Non-Compliant Users": []
                }
            }

        # Get all IAM users
        users = client.list_users()['Users']

        for user in users:
            user_name = user['UserName']

            try:
                # Check if the user has a password set
                client.get_user(UserName=user_name)['User']['PasswordLastUsed']

                # Check compliance with password policy
                non_compliance_reasons = []
                if password_policy.get('MinimumPasswordLength', 0) < 12:
                    non_compliance_reasons.append("Password length is less than 12.")
                if not password_policy.get('RequireUppercase', False):
                    non_compliance_reasons.append("Uppercase characters not required.")
                if not password_policy.get('RequireLowercase', False):
                    non_compliance_reasons.append("Lowercase characters not required.")
                if not password_policy.get('RequireNumbers', False):
                    non_compliance_reasons.append("Numbers not required.")
                
                if non_compliance_reasons:
                    users_not_compliant.append({
                        "user": user_name,
                        "reasons": non_compliance_reasons
                    })

            except client.exceptions.NoSuchEntityException:
                # If no password is set for the user
                users_not_compliant.append({
                    "user": user_name,
                    "reasons": ["No password set."]
                })

        # Generate the output
        if users_not_compliant:
            return {
                "Topic": "Password management",
                "Requirement": "Strict adherence to password standards",
                "Need to Achieve": "All IAM users should have a password policy enforced with the required standards.",
                "Function Used": "check_password_policy_for_users",
                "Results": {
                    "Summary": "(-) Some users do not comply with the password policy.",
                    "Non-Compliant Users": users_not_compliant
                }
            }
        else:
            return {
                "Topic": "Password management",
                "Requirement": "Strict adherence to password standards",
                "Need to Achieve": "All IAM users should have a password policy enforced with the required standards.",
                "Function Used": "check_password_policy_for_users",
                "Results": {
                    "Summary": "(+) All users comply with the password policy.",
                    "Non-Compliant Users": []
                }
            }

    except Exception as e:
        return {
            "Topic": "Password management",
            "Requirement": "Strict adherence to password standards",
            "Need to Achieve": "All IAM users should have a password policy enforced with the required standards.",
            "Function Used": "check_password_policy_for_users",
            "Results": {
                "Summary": f"Error checking password policy compliance: {str(e)}",
                "Non-Compliant Users": []
            }
        }
