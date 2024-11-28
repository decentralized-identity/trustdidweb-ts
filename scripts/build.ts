import { BuildConfig } from "bun";
import pkg from "../package.json";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";

const external = [
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.peerDependencies || {})
];

// Library builds
const browserConfig: BuildConfig = {
  entrypoints: ["./src/index.ts"],
  minify: true,
  sourcemap: "external",
  external,
  target: "browser",
  format: "esm",
  outdir: "./dist/browser",
  define: {
    'process.env.NODE_ENV': '"production"',
    'global': 'window',
  },
};

const nodeConfig: BuildConfig = {
  entrypoints: ["./src/index.ts"],
  minify: false,
  sourcemap: "external",
  external,
  target: "node",
  format: "esm",
  outdir: "./dist/node",
};

const cliConfig: BuildConfig = {
  entrypoints: ["./src/cli.ts"],
  minify: false,
  sourcemap: "external",
  external,
  target: "node",
  format: "esm",
  outdir: "./dist/cli",
  naming: {
    entry: "tdw.js"
  }
};

async function ensureDir(dir: string) {
  await mkdir(dir, { recursive: true });
}

function createDistPackageJson() {
  // Create a simplified package.json for distribution
  const distPkg: any = {
    name: pkg.name,
    version: pkg.version,
    type: "module",
    main: "./node/index.js",
    module: "./browser/index.js",
    types: "./types/index.d.ts",
    bin: {
      "tdw": "./cli/tdw.js"
    },
    files: [
      "node",
      "browser",
      "cli",
      "types"
    ],
    dependencies: pkg.dependencies,
    peerDependencies: pkg.peerDependencies,
  };

  // Only add optional fields if they exist in the source package.json
  if ('description' in pkg) distPkg.description = pkg.description;
  if ('author' in pkg) distPkg.author = pkg.author;
  if ('license' in pkg) distPkg.license = pkg.license;
  if ('repository' in pkg) distPkg.repository = pkg.repository;
  if ('bugs' in pkg) distPkg.bugs = pkg.bugs;
  if ('homepage' in pkg) distPkg.homepage = pkg.homepage;

  writeFileSync("./dist/package.json", JSON.stringify(distPkg, null, 2));
}

function createDistReadme() {
  // Read the main README
  const readme = readFileSync("./README.md", "utf-8");
  
  // Add distribution-specific information
  const distReadme = `# ${pkg.name}

${readme}

## Distribution Package Structure

This package includes:
- \`node/\` - Node.js ESM bundle
- \`browser/\` - Browser ESM bundle
- \`cli/\` - Command-line interface
- \`types/\` - TypeScript type declarations
`;

  writeFileSync("./dist/README.md", distReadme);
}

async function build() {
  console.log("External packages:", external);
  
  // Clean dist directory first
  await Bun.spawn(["rm", "-rf", "dist"], {
    stdout: "inherit",
    stderr: "inherit",
  }).exited;
  
  // Create output directories
  console.log("\nCreating output directories...");
  await Promise.all([
    ensureDir("./dist/node"),
    ensureDir("./dist/browser"),
    ensureDir("./dist/cli"),
    ensureDir("./dist/types")
  ]);

  // Build for Node.js
  console.log("\nBuilding Node.js bundle...");
  const nodeResult = await Bun.build(nodeConfig);
  if (!nodeResult.success) {
    console.error("Node.js build failed:", nodeResult.logs);
    process.exit(1);
  }

  // Build for Browser
  console.log("\nBuilding Browser bundle...");
  const browserResult = await Bun.build(browserConfig);
  if (!browserResult.success) {
    console.error("Browser build failed:", browserResult.logs);
    process.exit(1);
  }

  // Build CLI
  console.log("\nBuilding CLI...");
  const cliResult = await Bun.build(cliConfig);
  if (!cliResult.success) {
    console.error("CLI build failed:", cliResult.logs);
    process.exit(1);
  }

  // Generate type declarations
  console.log("\nGenerating TypeScript declarations...");
  
  // Create a temporary tsconfig for declarations
  const declarationConfig = {
    compilerOptions: {
      declaration: true,
      emitDeclarationOnly: true,
      declarationDir: "./dist/types",
      moduleResolution: "bundler",
      module: "esnext",
      target: "esnext",
      allowSyntheticDefaultImports: true,
      esModuleInterop: true,
      skipLibCheck: true,
      rootDir: "./src",
    },
    include: ["src/**/*"],
    exclude: ["node_modules", "dist", "test"]
  };

  writeFileSync("tsconfig.declarations.json", JSON.stringify(declarationConfig, null, 2));

  const tscResult = await Bun.spawn([
    "tsc",
    "--project", "tsconfig.declarations.json",
  ], {
    stdout: "inherit",
    stderr: "inherit",
  }).exited;
  
  // Clean up temporary config
  await Bun.spawn(["rm", "tsconfig.declarations.json"]);
  
  if (tscResult !== 0) {
    console.error("TypeScript compilation failed");
    process.exit(1);
  }

  // Make CLI executable
  const proc2 = Bun.spawn(["chmod", "+x", "dist/cli/tdw.js"], {
    stdout: "inherit",
    stderr: "inherit",
  });
  await proc2.exited;

  // Create distribution package.json and README
  console.log("\nCreating distribution package files...");
  createDistPackageJson();
  createDistReadme();

  // Verify output directories exist and have content
  const dirs = ['node', 'browser', 'cli', 'types'].map(dir => `dist/${dir}`);
  for (const dir of dirs) {
    if (!existsSync(dir)) {
      console.error(`Missing output directory: ${dir}`);
      process.exit(1);
    }
    const files = readdirSync(dir);
    if (files.length === 0) {
      console.error(`No files in output directory: ${dir}`);
      process.exit(1);
    }
    console.log(`\nFiles in ${dir}:`, files);
  }

  console.log("\nBuild completed successfully!");
}

await build(); 