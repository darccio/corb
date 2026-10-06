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
database, or Sites account. The supplied `404.html` uses paths relative to the
web server's root; configure it as the error page if your server supports that.

Build again after editing a guide in `docs/`, the page template in
`website/template.html`, or the landing page and assets in `website/src/`.
Generated output is ignored by Git.
