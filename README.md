# Service-Control-Policies

# 10 important policies to consider:
# 1.Deny Termination of VPCs: This policy prevents accidental deletion of virtual private clouds (VPCs) which can lead to data loss. It ensures that only authorized individuals can terminate VPCs.
# 2.Require Encryption: This policy enforces encryption for data at rest and in transit. It helps protect sensitive information from unauthorized access or interception.
# 3.Restrict Public Access to S3 Buckets: This policy ensures that Amazon S3 buckets are not publicly accessible by default. It helps prevent accidental exposure of sensitive data to the public internet.
# 4.Enforce Multi-Factor Authentication (MFA): This policy requires the use of MFA for accessing AWS accounts. It adds an extra layer of security by requiring users to provide an additional authentication factor, such as a code from a mobile app or a hardware token.
# 5.Control Access to AWS Services: This policy limits access to specific AWS services based on user roles and responsibilities. It helps prevent unauthorized use of critical services and reduces the attack surface.
# 6.Enable Logging and Monitoring: This policy ensures that logging and monitoring mechanisms are enabled for various AWS services. It helps detect and respond to security incidents by providing visibility into system activities and events.
# 7.Implement Security Group Restrictions: This policy restricts inbound and outbound traffic by configuring security groups appropriately. It helps enforce the principle of least privilege and reduces the risk of unauthorized access.
# 8.Enable VPC Flow Logs: This policy enables VPC flow logs, which capture information about IP traffic flowing in and out of VPCs. It aids in network traffic analysis, troubleshooting, and detecting potential security threats.
# 9.Implement Least Privilege Access: This policy ensures that users and roles are granted only the minimum privileges required to perform their tasks. It helps limit the potential impact of compromised credentials and reduces the risk of accidental or malicious actions.
# 10.Regularly Rotate Access Keys and Passwords: This policy mandates the periodic rotation of access keys and passwords for user accounts. It helps mitigate the impact of leaked or compromised credentials.

# Termination VPC denial 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "ec2:DeleteVpc"
      ],
      "Resource": [
        "*"
      ]
    }
  ]
}

# Requiring Encryption
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "s3:PutObject",
        "s3:GetObject"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}

# Restricting public access to S3 buckets 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "s3:PutBucketAcl",
        "s3:PutBucketPolicy"
      ],
      "Resource": [
        "arn:aws:s3:::example-bucket"
      ],
      "Condition": {
        "StringNotEquals": {
          "aws:PrincipalArn": "arn:aws:iam::123456789012:root"
        }
      }
    }
  ]
}

# Enforcing (MFA)
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:CreateAccessKey",
        "iam:DeleteAccessKey",
        "iam:UpdateAccessKey",
        "iam:DeactivateMFADevice",
        "iam:EnableMFADevice",
        "iam:ResyncMFADevice"
      ],
      "Resource": [
        "arn:aws:iam::*:user/${aws:username}"
      ],
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}

# Access control to AWS services 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "s3:*",
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "s3:List*",
        "s3:Get*"
      ],
      "Resource": "arn:aws:s3:::example-bucket/*"
    }
  ]
}

# Enabling loggign and monitoring 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:CreateTrail",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:StartLogging",
        "cloudtrail:StopLogging"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:PutRetentionPolicy"
      ],
      "Resource": "arn

# Implementing security group restrictions 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress"],
      "Resource": "arn:aws:ec2:*:*:security-group/*",
      "Condition": {
        "Bool": {"aws:SecureTransport": "false"}
      }
    }
  ]
}

# Enabling VPC flow logs
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["ec2:CreateFlowLogs", "ec2:DescribeFlowLogs", "ec2:DeleteFlowLogs"],
      "Resource": "arn:aws:ec2:*:*:flow-log/*"
    }
  ]
}

# Implementing Least privilege access 
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
        "StringNotLike": {
          "aws:userid": "AROA**"
        }
      }
    }
  ]
}

# Rotating acess keys and passwords regularly
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": [
        "iam:DeleteAccessKey",
        "iam:UpdateAccessKey",
        "iam:DeleteLoginProfile",
        "iam:UpdateLoginProfile",
        "iam:CreateLoginProfile"
      ],
      "Resource": "arn:aws:iam::*:user/${aws:username}",
      "Condition": {
        "NumericLessThan": {
          "aws:MultiFactorAuthAge": "365"
        }
      }
    }
  ]
}

#To allow AWS accounts within an AWS Organization, which fall under the root account, to use AWS credits, you need to follow these steps:

#Identify the eligible accounts: Determine which accounts within your AWS Organization should have access to use AWS credits. Ensure that these accounts are linked to the organization and fall under the management of the root account.

#Assign permission policies: In the AWS Management Console, sign in to the root account and access the AWS Organizations service. Navigate to the "Policies" section.

#Create a new policy: Create a new service control policy (SCP) or modify an existing one to grant permissions for using AWS credits. SCPs are used to set permissions and restrictions for accounts within an organization.

#Specify permissions for AWS credits: In the SCP, define the necessary permissions to allow the eligible accounts to use AWS credits. This may involve granting access to specific AWS services or actions related to credits, such as redeeming or applying credits to eligible services.

#Attach the policy: Attach the SCP to the root or organizational unit (OU) that contains the eligible accounts. This ensures that the policy is applied to the desired accounts within the organization.

#Verify and test: Once the policy is attached, verify that the eligible accounts can now use AWS credits. Test the functionality by attempting to redeem or apply credits within the permitted accounts.

#It's important to note that AWS credits may have specific terms and conditions associated with them, including usage restrictions, expiration dates, and eligibility criteria. Ensure that you review and understand the terms of your specific AWS credits program to ensure compliance and proper usage.

#If you have any specific questions or need further assistance, it's recommended to consult AWS Support or the AWS documentation for detailed guidance on managing credits within an AWS Organization.
