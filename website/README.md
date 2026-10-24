# Corb website

The website is a static landing page plus the user guides from the repository's
`docs/` directory. Documentation text lives in Markdown; the website supplies
its layout and navigation.

## Build

Building requires Node.js and [Pandoc](https://pandoc.org/installing.html) on
`PATH`. No npm packages need to be installed.

From the repository root:

```sh
npm --prefix website run build
```

The output is `website/dist/`. Preview it with Python 3:

```sh
npm --prefix website run preview
```

Open `http://localhost:4173`. Stop the server with Ctrl-C.

## Self hosting

Copy the contents of `website/dist/` to your web server's document root or
upload them to a static host. The output requires no application server,
database, or Sites account. Set `CORB_SITE_URL` to the actual deployment base
before building, including the subpath if the site is hosted below the root.
For example, replace the example domain with your own:

```sh
CORB_SITE_URL=https://example.com/corb/ npm --prefix website run build
```

The build adds per-page canonical URLs and absolute social-preview image URLs.
Without this setting, local builds omit those URL-dependent fields. The setting
accepts HTTP or HTTPS and rejects credentials, query strings, and fragments.

Configure the supplied `404.html` as your host's error page. Its asset and
navigation paths use the configured deployment prefix, including for missing
URLs several directories deep. The host must return HTTP 404 for those requests;
the HTML file itself cannot set the response status.

Build again after editing a guide in `docs/`, the page template in
`website/template.html`, or the landing page and assets in `website/src/`.
Generated output is ignored by Git.

## Navigation and guide layout

`website/build.mjs` defines the shared site navigation and each published guide.
The build fills `{{navigation}}` in the guide template, landing page, and 404
page, using the appropriate relative paths and marking the current page.
Preview the generated `website/dist/` files rather than the source HTML.

Guide titles and introductions come before their section navigation. Desktop
contents are expanded in the margin; mobile contents use a native disclosure
before the article sections. Both lists come from the same Markdown headings
and work without JavaScript. Heading anchors and authored numbering are kept;
the website does not add section numbers.

## Fonts and images

Fonts are served locally by `fonts.css`; no font CDN or runtime dependency is
needed. Official IBM Plex Mono font files, their license, and provenance live
under `src/assets/fonts/ibm-plex-mono/`.

The original `src/assets/bec.png` remains the artwork master. Responsive display
images and dedicated favicon files are generated ahead of time and committed,
so normal website builds still need only Node.js and Pandoc. The social image
uses Bec, the wordmark, and the landing headline. Regeneration commands live in
`src/assets/GENERATING.txt`; font provenance is in
`src/assets/fonts/ibm-plex-mono/SOURCE.txt`.

The walkthrough's sanitized runtime evidence in `docs/evidence/` is copied beside
the generated guide, so its capture record can be opened on a self-hosted site.
