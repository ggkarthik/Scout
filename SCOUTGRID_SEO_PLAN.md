# ScoutGrid SEO Implementation Plan

This plan sequences the SEO work for `scoutgrid.io` and identifies which activities can be completed from the development console and which require external account access or business input.

## Sequential SEO Plan

| Step | Work | Owner |
|---:|---|---|
| 1 | Record current indexing, metadata, routes, performance, and HTTP behavior as the baseline. | Development console |
| 2 | Separate public marketing URLs from authenticated product URLs in the SEO rules. | Development console, with business confirmation |
| 3 | Replace “Scout.ai Prototype” with production titles, descriptions, canonical URLs, favicon, and social metadata. | Development console |
| 4 | Create valid `robots.txt` and `sitemap.xml` files. | Development console |
| 5 | Add `noindex` protection to login, invitation, setup, demo-success, and authenticated application pages. | Development console |
| 6 | Correct invalid-route behavior so nonexistent URLs return a real HTTP 404 instead of the React application with HTTP 200. | Development console |
| 7 | Pre-render public pages so their headings and content appear in the initial HTML response. | Development console |
| 8 | Create dedicated, indexable solution pages with clean URLs. | Development console |
| 9 | Optimize headings, page copy, internal links, image alt text, and calls to action. | Development console; business owner approves claims |
| 10 | Add Organization, SoftwareApplication, Breadcrumb, and appropriate FAQ structured data. | Development console; business owner provides company details |
| 11 | Generate a social-sharing image and configure Open Graph and Twitter metadata. | Development console |
| 12 | Improve public-page performance and Core Web Vitals. | Development console |
| 13 | Run the build, frontend tests, crawl checks, structured-data validation, and mobile checks. | Development console |
| 14 | Push the changes to GitHub and deploy the production site. | Development console |
| 15 | Verify live metadata, sitemap, robots rules, status codes, and rendered HTML. | Development console |
| 16 | Verify ScoutGrid in Google Search Console and Bing Webmaster Tools. | External action |
| 17 | Submit the sitemap and request indexing of priority pages. | External action |
| 18 | Create an analytics account and provide the measurement ID. | External action |
| 19 | Integrate analytics events for demo requests and other important conversions. | Development console |
| 20 | Publish ongoing articles, case studies, integrations, and industry research. | Shared |
| 21 | Build backlinks, directory profiles, partnerships, and community visibility. | Business and marketing |
| 22 | Review rankings, indexed pages, conversions, and crawl errors monthly. | Shared |

## Recommended Technical Architecture

Use the following architecture initially:

- `scoutgrid.io` — public marketing and SEO pages
- Existing authenticated routes — remain on the same domain initially but receive `noindex`
- `app.scoutgrid.io` — a later migration target for the authenticated product

Moving the product immediately to `app.scoutgrid.io` would require coordinated changes to DNS, authentication cookies, CORS, redirects, and email links. Treat that as a separate migration after the foundational SEO work is complete.

## Initial Public Pages

Create these public, indexable pages first:

1. `/`
2. `/platform`
3. `/sbom-management`
4. `/ai-bom`
5. `/cbom`
6. `/exposure-management`
7. `/vulnerability-prioritization`
8. `/software-inventory`
9. `/end-of-life-software`
10. `/integrations`
11. `/resources`
12. `/about`
13. `/security`
14. `/demo`

Each page should have:

- A unique page title and meta description
- One keyword-focused H1
- Server-rendered or pre-rendered content
- A canonical URL
- Open Graph and social metadata
- Contextual internal links
- Relevant structured data
- A clear product-demo call to action

## Work That Can Be Completed in the Development Console

The following work can be completed directly in the repository and deployment environment:

- Modify the React/Vite frontend
- Add static or pre-rendered marketing pages
- Configure metadata for every public route
- Create `robots.txt` and `sitemap.xml`
- Add structured data
- Add correct 404 behavior and indexing controls
- Generate an Open Graph image
- Write initial SEO copy
- Improve public-page performance
- Add analytics code after receiving the measurement ID
- Run automated tests and SEO checks
- Push changes to GitHub
- Deploy and verify production
- Perform keyword and competitor research
- Prepare a content calendar

## Work Required Outside the Development Console

The business owner or marketing team should:

1. Create or access the Google Search Console property for `scoutgrid.io`.
2. Verify domain ownership, normally using a Cloudflare DNS TXT record.
3. Create or access Bing Webmaster Tools.
4. Submit the sitemap after deployment.
5. Request indexing for the initial priority pages.
6. Create the analytics account and supply its measurement ID.
7. Confirm the legal company name, logo, address, and official social profiles.
8. Approve product claims, pricing language, and customer results.
9. Supply case studies, testimonials, and customer logos where permitted.
10. Create or update LinkedIn, Crunchbase, and relevant cybersecurity directory profiles.
11. Develop partner backlinks and community relationships.

If the Cloudflare connection is available, the development console can add the Search Console DNS verification record after Google provides the TXT value.

## Delivery Phases

### Release 1: Technical Foundation

Complete steps 1–7 and 10–15:

- Correct metadata
- Valid robots and sitemap files
- Indexing protections
- Proper HTTP 404 responses
- Pre-rendered public content
- Structured data
- Performance checks
- Production deployment and verification

### Release 2: Landing Pages

Complete steps 8–9:

- Build the primary solution and integration pages
- Optimize copy and internal linking
- Add conversion tracking

### Release 3: Search Registration

After Release 1 is live:

- Verify Google Search Console and Bing Webmaster Tools
- Submit the sitemap
- Request indexing for priority URLs
- Confirm that crawlers can access and render the pages

### Release 4: Organic Growth

Complete steps 20–22:

- Publish two to four authoritative articles per month
- Add case studies and integration pages
- Earn relevant industry backlinks
- Review search and conversion performance monthly

## Recommended Content Topics

Start with technically credible content that supports the solution pages:

- AI BOM vs. SBOM: what security teams need to track
- How to operationalize CycloneDX and SPDX SBOMs
- What is a Cryptography Bill of Materials?
- Using VEX to reduce SBOM vulnerability false positives
- How to find end-of-life software across applications and hosts
- Prioritizing CVEs using KEV, EPSS, reachability, and asset criticality
- Building an SBOM vulnerability-management workflow
- EU Cyber Resilience Act SBOM requirements
- SBOM ingestion from GitHub repositories and container registries
- Why the same component produces different vulnerability results

## Success Measures

Track the following outcomes:

- Number of valid indexed pages
- Sitemap processing errors
- Organic impressions and clicks
- Rankings for priority non-branded keywords
- Branded searches for ScoutGrid
- Demo requests attributed to organic search
- Conversion rate by landing page
- Core Web Vitals
- Crawl and soft-404 errors
- Referring domains and relevant backlinks

The technical foundation should be completed before investing heavily in articles or backlinks. Otherwise, search engines may still have difficulty discovering and interpreting the new content.
