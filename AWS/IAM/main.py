import argparse
import boto3
from check_users_and_group_policies import check_users_and_group_policies
from check_analyzer_status import check_analyzer_status
from enable_iam_groups_and_assign_roles import enable_iam_groups_and_assign_roles
from check_least_privilege_access import check_least_privilege_access
from check_granular_access_for_users import check_granular_access_for_users
from check_root_and_access_analyzer import check_root_and_access_analyzer
from check_mfa_for_users import check_mfa_for_users
from check_aws_ad_connector import check_aws_ad_connector
from check_password_policy import check_password_policy
from check_password_policy_for_users import check_password_policy_for_users
from check_cloudtrail_logs_enabled import check_cloudtrail_logs_enabled
from check_least_privilege_and_group_policies import check_least_privilege_and_group_policies
from fpdf import FPDF  # Assuming PDFMake is not directly used in Python, FPDF is commonly used.


from fpdf import FPDF

def generate_pdf(results):
    """
    Generates a beautified PDF report with AWS checks.

    Args:
        results (dict): A dictionary containing the results of the checks.
    """
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Function to apply background color to all pages
    def set_page_background():
        pdf.set_fill_color(173, 216, 230)  # Light Blue
        pdf.rect(0, 0, 210, 297, 'F')  # Apply background fill for the entire page

    # Add the first page and set background
    pdf.add_page()
    set_page_background()

    # Add AWS Cloud logos (left and right top)
    pdf.image("NIC_logo_left.png", 10, 20, 20)  # Adjust the path to your logo location
    pdf.image("aws_logo_right.png", 180, 10, 20)  # Adjust the path to your logo location

    # Title Section (Centered Title Between Logos)
    pdf.set_font("Arial", style='B', size=18)
    pdf.set_xy(40, 10)  # Adjust starting X and Y coordinates for the title (between logos)
    pdf.cell(130, 10, txt="AWS CHECKS \n Security and Compliance Report", ln=True, align="C")
    pdf.ln(5)  # Space after the title

    # Add "IAM pillar" heading just below the main title (H3, Bold)
    pdf.set_font("Arial", style='B', size=14)
    pdf.cell(0, 10, txt="IAM pillar", ln=True, align="C")
    pdf.ln(10)  # Space after the "IAM pillar" heading

    # Set the text color to white for the entire document
    pdf.set_text_color(0, 0, 0)  # Black text

    # Add Results for Each Check
    pdf.set_font("Arial", size=12)

    count = 1
    for key, value in results.items():
        # Check if the value is a dictionary (i.e., check for the nested structure)
        if isinstance(value, dict):
            # Display the topic (e.g., 1) Topic: <Topic Name>)
            pdf.set_font("Arial", style='B', size=14)
            topic_text = value.get('Topic', 'No Topic Available').encode('latin-1', 'replace').decode('latin-1')
            pdf.cell(200, 10, txt=f"{count}. Topic: {topic_text}", ln=True)
            pdf.ln(5)

            # Add the requirement header (H2 Bold)
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(200, 10, txt="Requirement:", ln=True)
            pdf.ln(5)

            # Add requirement description
            pdf.set_font("Arial", size=12)
            requirement_text = value.get('Requirement', 'N/A').encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 10, txt=requirement_text)
            pdf.ln(5)

            # Add 'Need to Achieve' section (H2)
            pdf.set_font("Arial", style='B', size=12)
            pdf.cell(200, 10, txt="Need to Achieve:", ln=True)
            pdf.ln(5)

            # Add what needs to be achieved (H3, Italic)
            pdf.set_font("Arial", style='I', size=12)
            achieve_text = value.get('Need to Achieve', 'N/A').encode('latin-1', 'replace').decode('latin-1')
            pdf.multi_cell(0, 10, txt=achieve_text)
            pdf.ln(5)

            # Add Results Box with dynamic sizing
            pdf.set_font("Arial", size=12)
            result_text = value.get('Results', 'No results available')
            if isinstance(result_text, dict):
                result_text = "\n".join([f"{k}: {v}" for k, v in result_text.items()])
            result_text = result_text.encode('latin-1', 'replace').decode('latin-1')
            result_text_with_heading = f"Result of the Script:\n{result_text}"

            # Calculate the box height dynamically
            box_start_y = pdf.get_y()
            pdf.multi_cell(0, 10, txt=result_text_with_heading)
            box_end_y = pdf.get_y()
            box_height = box_end_y - box_start_y

            # Draw the result box
            pdf.rect(10, box_start_y, 190, box_height, 'D')
            pdf.ln(10)

            count += 1  # Increment the number for next topic

        # Add a new page if content is spilling over or on odd counts
        if pdf.get_y() > 250 or count % 2 == 0:
            pdf.add_page()
            set_page_background()

    # Save the PDF
    pdf.output("AWS_Security_Check_Report.pdf")
    print("PDF report generated successfully.")


def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="AWS Security Check Script")
    parser.add_argument("-p", "--profile", help="AWS profile to use", required=True)
    parser.add_argument("-m", "--mode", help="Mode (check_users_and_group_policies, check_analyzer_status, "
                                              "enable_iam_groups_and_assign_roles, check_least_privilege_access, "
                                              "check_granular_access_for_users, check_mfa_for_users, check_aws_ad_connector, "
                                              "check_password_policy, check_password_policy_for_users, "
                                              "check_cloudtrail_logs_enabled, check_least_privilege_and_group_policies, all)",
                        required=True)
    args = parser.parse_args()

    profile = args.profile
    mode = args.mode

    # Initialize AWS session and client
    session = boto3.Session(profile_name=profile)
    client = session.client('iam')

    # Initialize result dictionary
    results = {}

    # Mode-specific checks
    if mode == 'check_users_and_group_policies' or mode == 'all':
        results["check_users_and_group_policies"] = check_users_and_group_policies(client)
    if mode == 'check_analyzer_status' or mode == 'all':
        results["check_analyzer_status"] = check_analyzer_status(client)
    if mode == 'enable_iam_groups_and_assign_roles' or mode == 'all':
        results["enable_iam_groups_and_assign_roles"] = enable_iam_groups_and_assign_roles(client)
    if mode == 'check_least_privilege_access' or mode == 'all':
        results["check_least_privilege_access"] = check_least_privilege_access(client)
    if mode == 'check_granular_access_for_users' or mode == 'all':
        results["check_granular_access_for_users"] = check_granular_access_for_users(client)
    if mode == 'check_root_and_access_analyzer' or mode == 'all':
        results["check_root_and_access_analyzer"] = check_root_and_access_analyzer(client)
    if mode == 'check_mfa_for_users' or mode == 'all':
        results["check_mfa_for_users"] = check_mfa_for_users(client)
    if mode == 'check_aws_ad_connector' or mode == 'all':
        results["check_aws_ad_connector"] = check_aws_ad_connector(client)
    if mode == 'check_password_policy' or mode == 'all':
        results["check_password_policy"] = check_password_policy(client)
    if mode == 'check_password_policy_for_users' or mode == 'all':
        results["check_password_policy_for_users"] = check_password_policy_for_users(client)
    if mode == 'check_cloudtrail_logs_enabled' or mode == 'all':
        results["check_cloudtrail_logs_enabled"] = check_cloudtrail_logs_enabled(client)
    if mode == 'check_least_privilege_and_group_policies' or mode == 'all':
        results["check_least_privilege_and_group_policies"] = check_least_privilege_and_group_policies(client)

    # Generate PDF with results
    generate_pdf(results)


if __name__ == "__main__":
    main()
