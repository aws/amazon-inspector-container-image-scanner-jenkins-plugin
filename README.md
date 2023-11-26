This plugin gives you the ability to add Amazon Inspector vulnerability scans to your pipeline. These scans leverage the Inspector SBOM generator binary and Amazon Inspector Scan API to produce detailed reports at the end of your build so you can investigate and remediate risk before deployment. The scans can also be configured to pass or fail pipeline executions based on the number and severity of vulnerabilities detected.

Amazon Inspector is a vulnerability management service offered by AWS that scans container images for both operating system and programming language package vulnerabilities based on CVEs.  For more information on Amazon Inspector’s CI/CD integration see [Integrating Amazon Inspector scans into your CI/CD pipeline](https://docs.aws.amazon.com/inspector/latest/user/scanning-cicd.html).

For a list of packages and container image formats the Inspector plugin supports see, [Supported packages and image formats](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html#sbomgen-supported).

Follow the steps in each section of this document to use the Inspector Jenkins plugin:

1. Set up an AWS account

* Configure an AWS account with an IAM role that allows access to the Inspector SBOM scanning API. For instructions, see [Setting up an AWS account to use the Amazon Inspector CI/CD integration](https://docs.aws.amazon.com/inspector/latest/user/configure-cicd-account.html)

2. Install the Inspector Jenkins Plugin

1. From your Jenkins dashboard, go to Manage Jenkins > Manage Plugins and select the Available tab.
2. Search for Amazon Inspector Scans.
3. Install the plugin.

3. Install the Inspector SBOM Generator

* Install and configure the Amazon Inspector SBOM Generator. For instructions, see [Installing Amazon Inspector SBOM Generator (Sbomgen)](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html#install-sbomgen)

4. Add your Docker credentials to Jenkins

1. Go to Dashboard > Manage Jenkins > Credentials > System > Global credentials > Add credentials.
2. Fill in details and select Create.

5. Add CSS support  in Jenkins script console to allow the HTML report link to open

1. Go to  Dashboard > Manage Jenkins > Nodes > Built-In Node  and select the Gear icon and navigate to script console
2. Add in script System.setProperty("hudson.model.DirectoryBrowserSupport.CSP", "") and click Run
3. This step needs to be done after Jenkins restart

6. Add the Inspector Scan build step to your project

1. On the configuration page, scroll down to Build Steps, choose Add build step and then select Amazon Inspector Scan.
2. Navigate to the plugin UI to fill following details:
    1. For IAM Role enter the ARN for the role you configured in step 1.
    2. For Docker credentials select your Docker user name.
    3. For Path to SBOM generator Binary add the installation path to your Amazon Inspector SBOM generator.
    4. Select an AWS Region to send the scan request through.
    5. Input your Image Id path. Your image can be local, remote, or archived. Image names should follow the Docker naming convention. If you’re analyzing an exported image, provide the path to the expected tar file. The following are examples of Image Id paths:
        1. For a local or remote container: NAME[:TAG|@DIGEST]
        2. For a tar file: /path/to/image.tar
    6. [Optional] Specify the Vulnerabilities Allowed based on severity. If the maximum is exceeded during a scan the image build will fail. If the values are all 0 the build will succeed regardless of the number of vulnerabilities found.
3. Select Save.

7. View your Inspector scan report

1. Complete a new build of your project.
2. When the build completes select an output format from the results. When you select HTML you have the option to download a JSON SBOM or CSV version of the report.


### Troubleshooting

Issue #1: If you receive the following error:

InstanceProfileCredentialsProvider(): Failed to load credentials from IMDS.]

Resolution : Set up aws_access_key_id and aws_secret_access_key in ~/.aws/credential


### Known Limitations and Issues

* Support for Windows OS and macOS is not provided at this time.
* Sbomgen was load tested against container images spanning 5 GB in size, 60 layers, and 2,000 installed packages. Sbomgen should be able to inventory images of this size within 5 minutes; however, this may vary depending on the configuration of your image and available hardware resources.
* Sbomgen prioritizes accuracy and low false positive rates, which often comes at the expense of speed.
* Sbomgen ONLY generates SBOMs - it does not perform vulnerability identification at this time.
* Sbomgen only generates SBOMs in CycloneDX + JSON format at this time.




