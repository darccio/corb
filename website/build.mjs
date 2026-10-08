import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("./", import.meta.url));
const output = path.join(root, "dist");
const docs = fileURLToPath(new URL("../docs/", import.meta.url));
const template = readFileSync(path.join(root, "template.html"), "utf8");
const pages = [
  { slug: "getting-started", label: "Getting started",
    description: "Build Corb from source, configure a host-held model credential, and start your first sandboxed Pi session.",
    note: 'Source of truth:<br><a href="https://github.com/darccio/corb/blob/main/docs/getting-started.md">repository guide</a>' },
  { slug: "walkthrough", label: "Development walkthrough",
    description: "Start a Corb workspace, apply repository settings, develop a feature with Pi, review changes, and keep conversation history across sessions.",
    note: 'One-time setup:<br><a href="getting-started.html">Getting started</a><br><br>Detailed mount behavior:<br><a href="workspaces.html">Workspaces</a>' },
  { slug: "workspaces", label: "Workspace model",
    description: "How Corb mounts multiple directories, selects Pi's working directory, merges configuration, and records workspace trust.",
    note: "One session has one VM and one configured Pi process.<br><br>Multiple mounts do not create multiple agents." },
  { slug: "configuration", label: "Configuration reference",
    description: "The Corb global TOML configuration: VM and agent settings, secret bindings, filesystem and network rules, content checks, and audit records.",
    note: 'Related document:<br><a href="workspaces.html#configuration-resolution">Workspace resolution</a><br><br>Configuration belongs outside every mount.' },
  { slug: "cli", label: "CLI reference",
    description: "Implemented Corb commands and flags for running, inspecting, attaching, stopping, diagnosing, and building sandboxed sessions.",
    note: 'Before your first run:<br><a href="getting-started.html">Getting started</a><br><br>For mount details:<br><a href="workspaces.html">Workspaces</a>' },
  { slug: "security", label: "Enforcement model",
    description: "Corb's enforcement model: unprivileged guest processes, filesystem and network rules, image-installed command shims, content checks, and audit records.",
    note: 'Detailed architecture:<br><a href="https://github.com/darccio/corb/blob/main/docs/design.md">design document</a><br><br>Design decisions:<br><a href="https://github.com/darccio/corb/tree/main/docs/adr">ADR directory</a>' },
  { slug: "todo", label: "Planned improvements",
    description: "Planned Corb command-policy improvements: required arguments for specific commands and extensible image-installed command shims.",
    note: 'Current behavior:<br><a href="security.html#command-filtering">Command filtering</a><br><br>These improvements are not implemented.' },
];
const navigation = [
  ["../index.html", "overview"],
  ["getting-started.html", "getting started"],
  ["walkthrough.html", "walkthrough"],
  ["workspaces.html", "workspaces"],
  ["cli.html", "reference"],
  ["https://github.com/darccio/corb", "source"],
];

function escapeHtml(text) {
  return text.replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

// Render first so conversion failures preserve the previous successful build.
const rendered = pages.map((page, index) => {
  const result = spawnSync("pandoc", [
    path.join(docs, page.slug + ".md"),
    "--from=gfm", "--to=html5", "--section-divs", "--no-highlight", "--wrap=none",
  ], { encoding: "utf8" });
  if (result.error) {
    const message = result.error.code === "ENOENT"
      ? "Building the website requires Pandoc on PATH."
      : "Could not start Pandoc while rendering " + page.slug + ".";
    throw new Error(message, { cause: result.error });
  }
  if (result.status !== 0) {
    throw new Error("Could not render " + page.slug + ": " + result.stderr.trim());
  }
  let body = result.stdout;
  if (/^<section[^>]*class="level1">/.test(body)) {
    body = body.replace(/^<section[^>]*class="level1">\s*/, "").replace(/<\/section>\s*$/, "");
  }
  const title = body.match(/<h1>(.*?)<\/h1>/)?.[1];
  if (!title) throw new Error("Documentation needs a level-one heading: " + page.slug);

  const contents = [...body.matchAll(/<section id="([^"]+)" class="level2">\s*<h2>(.*?)<\/h2>/g)]
    .map(([, id, heading]) => '<li><a href="#' + id + '">' + heading + "</a></li>").join("");
  let section = 0;
  body = body.replace(/<h2>(.*?)<\/h2>/g, (_, heading) => "<h2>" + (++section) + ". " + heading + "</h2>");
  body = body.replace(/href="([^":]+)\.md(#[^"]*)?"/g, (_, file, anchor = "") => 'href="' + file + ".html" + anchor + '"');
  body = body.replace(/<table\b([^>]*)>/g, '<div class="table-scroll"><table$1>').replaceAll("</table>", "</table></div>");
  body = body.replace(/<th(\s|>)/g, '<th scope="col"$1');
  body = body.replace(/<pre(\s|>)/g, '<pre tabindex="0"$1');
  body = body.replace("<strong>NOT IMPLEMENTED</strong>", '<span class="status">NOT IMPLEMENTED</span>');

  const next = pages[(index + 1) % pages.length];
  const values = {
    title, body, contents, slug: page.slug,
    label: escapeHtml(page.label), description: escapeHtml(page.description), note: page.note,
    next_href: next.slug + ".html", next_title: next.label.toLowerCase(),
    navigation: navigation.map(([href, text]) => '<a href="' + href + '"' +
      (href === page.slug + ".html" ? ' aria-current="page"' : "") + ">" + text + "</a>").join("\n      "),
  };
  return [page.slug, template.replace(/\{\{(\w+)\}\}/g, (_, key) => {
    if (!(key in values)) throw new Error("Unknown template field: " + key);
    return values[key];
  })];
});

rmSync(output, { recursive: true, force: true });
mkdirSync(path.join(output, "docs"), { recursive: true });
cpSync(path.join(root, "src"), output, { recursive: true });
for (const [slug, html] of rendered) writeFileSync(path.join(output, "docs", slug + ".html"), html);
console.log("Built static documentation in website/dist.");
