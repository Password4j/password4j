# Security Policy

## Supported Versions

We release patches for security vulnerabilities. Which versions are eligible receiving such patches depend on the [<span>CVSS 3</span>](https://www.first.org/cvss/calculator/3.0) Rating:
| Version | Supported      |
|---------|----------------|
| 0.x     | :red_circle:   |
| 1.0.x - 1.4.x     | :red_circle:   |
| 1.5.x +     | :green_circle: |

## Reporting a Vulnerability

Please report (suspected) security vulnerabilities by opening a pull request in this repository with the **type: bug** label. If the issue is confirmed, we will release a patch as soon as possible depending on complexity but historically within a few days.

We generally **aren’t** interested in the following problems:
* Any vulnerability with a [<span>CVSS 3</span>](https://www.first.org/cvss/calculator/3.0) score lower than `4.0`, unless it can be combined with other vulnerabilities to achieve a higher score.
* DoS, phishing, text injection, or social engineering attacks. Wikis, Tracs, forums, etc are intended to allow users to edit them.
* Output from automated scans - please manually verify issues and include a valid proof of concept.
* Theoretical vulnerabilities where you can't demonstrate a significant security impact with a PoC.
