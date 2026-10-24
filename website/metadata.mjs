const socialImage = {
  path: "assets/corb-social.png",
  width: 1200,
  height: 630,
  alt: "Bec beside the Corb wordmark and the headline: Run Pi in a restricted micro-VM.",
};

function escapeHtml(value) {
  return value.replaceAll("&", "&amp;").replaceAll('"', "&quot;")
    .replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll("'", "&#39;");
}

export function parseSiteUrl(value = process.env.CORB_SITE_URL) {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new Error("CORB_SITE_URL must be a string.");
  if (value.trim() === "") return undefined;
  let url;
  try {
    url = new URL(value.trim());
  } catch {
    throw new Error("CORB_SITE_URL must be an absolute HTTP or HTTPS deployment base URL.");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || value.includes("?") || value.includes("#")) {
    throw new Error("CORB_SITE_URL must use HTTP or HTTPS without credentials, a query or a fragment.");
  }
  if (!url.pathname.endsWith("/")) url.pathname += "/";
  return url;
}

export function sitePath(siteUrl) {
  return siteUrl?.pathname ?? "/";
}

export function renderMetadata({ title, description, pagePath = "", siteUrl = parseSiteUrl() }) {
  if (typeof title !== "string" || !title.trim() || typeof description !== "string" || !description.trim()) {
    throw new Error("Social metadata requires a plain-text title and description.");
  }
  if (typeof pagePath !== "string" || (pagePath !== "" &&
    (!/^[\w.-]+(?:\/[\w.-]+)*$/.test(pagePath) || pagePath.split("/").some((part) => part === "." || part === "..")))) {
    throw new Error("Social metadata pagePath must be a path relative to the deployment base.");
  }
  const base = siteUrl instanceof URL ? parseSiteUrl(siteUrl.href) : parseSiteUrl(siteUrl);
  const tag = (attribute, name, content) => '<meta ' + attribute + '="' + name + '" content="' + escapeHtml(content) + '">';
  const tags = [
    tag("property", "og:title", title),
    tag("property", "og:description", description),
    tag("property", "og:type", "website"),
    tag("property", "og:site_name", "corb"),
    tag("name", "twitter:card", "summary_large_image"),
    tag("name", "twitter:title", title),
    tag("name", "twitter:description", description),
  ];
  if (base) {
    const pageUrl = new URL(pagePath, base).href;
    const imageUrl = new URL(socialImage.path, base).href;
    tags.push(
      '<link rel="canonical" href="' + escapeHtml(pageUrl) + '">',
      tag("property", "og:url", pageUrl),
      tag("property", "og:image", imageUrl),
      tag("property", "og:image:type", "image/png"),
      tag("property", "og:image:width", String(socialImage.width)),
      tag("property", "og:image:height", String(socialImage.height)),
      tag("property", "og:image:alt", socialImage.alt),
      tag("name", "twitter:image", imageUrl),
      tag("name", "twitter:image:alt", socialImage.alt),
    );
  }
  return tags.join("\n  ");
}
