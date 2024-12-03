def check_password_policy_for_users(client):
    """
    Checks if IAM users comply with the account-level password policy.

    Returns:
        dict: A summary of the findings.
    """
    print("----- Checking Password Policy for Users -----")
    try:
        iam_client = client
        users_not_compliant = []

        # Attempt to get the account's password policy
        try:
            password_policy = iam_client.get_account_password_policy()
        except iam_client.exceptions.NoSuchEntityException:
            return {"status": "No password policy set for the account."}
        
        # Get all IAM users
        users = iam_client.list_users()
        
        for user in users['Users']:
            user_name = user['UserName']
            
            # Check if the user has a password set
            try:
                user_password_last_set = iam_client.get_user(UserName=user_name)['User']['PasswordLastUsed']
                
                # If the password exists, check if it meets the policy requirements
                if not password_policy.get('RequireUppercaseCharacters', False):
                    users_not_compliant.append(f"{user_name} - No uppercase required")
                if not password_policy.get('RequireLowercaseCharacters', False):
                    users_not_compliant.append(f"{user_name} - No lowercase required")
                if not password_policy.get('RequireNumbers', False):
                    users_not_compliant.append(f"{user_name} - No number required")
                if not password_policy.get('MinimumPasswordLength', 12):
                    users_not_compliant.append(f"{user_name} - Minimum length requirement not met")
                
            except iam_client.exceptions.NoSuchEntityException:
                # If no password is set for the user
                users_not_compliant.append(f"{user_name} - No password set")
        
        # Prepare the result as a dictionary
        if users_not_compliant:
            result = {
                "status": "(-) Users not complying with the password policy.",
                "users_not_compliant": users_not_compliant
            }
        else:
            result = {
                "status": "(+) All users comply with the password policy."
            }

        return result

    except Exception as e:
        return {"error": str(e)}
