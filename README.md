Amazon Inspector is a vulnerability management service offered by AWS that scans container images for both operating system and programming language package vulnerabilities based on CVEs.  For more information on Amazon Inspector’s CI/CD integration see [Integrating Amazon Inspector scans into your CI/CD pipeline](https://docs.aws.amazon.com/inspector/latest/user/scanning-cicd.html).

This plugin gives you the ability to add Amazon Inspector vulnerability scans to your pipeline. These scans produce detailed reports at the end of your build so you can investigate and remediate risk before deployment. These scans can also be configured to pass or fail pipeline executions based on the number and severity of vulnerabilities detected.

For a list of packages and container image formats the Inspector plugin supports see, [Supported packages and image formats](https://docs.aws.amazon.com/inspector/latest/user/sbom-generator.html#sbomgen-supported).

For a list of steps describing how to set up this plugin, see https://docs.aws.amazon.com/inspector/latest/user/cicd-jenkins.html
