---
title: Sec Bites
description: Practical cybersecurity knowledge, served in small bites
---

Sec Bites is a Jekyll-powered GitHub Pages site for concise, practical
cybersecurity lessons.

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
