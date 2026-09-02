---
title: Sec Bites
description: Evidence-backed threat research and practical hunting guidance for security teams
---

Sec Bites is a Jekyll-powered GitHub Pages site for independent research into
threat actors, ransomware operations, phishing campaigns, and adversary tooling.
Reports turn public evidence into behavior-led hunting guidance for Microsoft
Defender XDR and Microsoft Sentinel.

## Local development

Install Ruby and Bundler, then run:

```bash
bundle install
bundle exec jekyll serve
```

Open <http://localhost:4000/sec-bites/> to view the site.

## Deployment

Pushes to the `main` branch trigger the GitHub Pages deployment workflow in
GitHub Actions. Configure the repository's Pages source as **GitHub Actions**
before the first deployment.
