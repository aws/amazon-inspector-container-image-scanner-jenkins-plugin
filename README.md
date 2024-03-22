The Jenkins plugin leverages the Amazon Inspector SBOM Generator binary and Amazon Inspector Scan API to produce detailed reports at the end of your build, so you can investigate and remediate risk before deployment.

Amazon Inspector is a vulnerability management service that scans container images for operating system and programming language package vulnerabilities based on CVEs.

Using the Amazon Inspector Jenkins plugin, you can add Amazon Inspector vulnerability scans to your Jenkins pipeline.

For a list of steps describing how to set up this plugin, see https://docs.aws.amazon.com/inspector/latest/user/cicd-jenkins.html

### Troubleshooting

Issue #1: If you receive the following error:

InstanceProfileCredentialsProvider(): Failed to load credentials from IMDS.

Resolution : Set up aws_access_key_id and aws_secret_access_key in ~/.aws/credential
