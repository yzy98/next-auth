import path from "node:path";

function buildEslintCommand(filenames) {
  return `next lint --fix --file ${filenames
    .map(f => path.relative(process.cwd(), f))
    .join(" --file ")}`;
}

const config = {
  "*.{js,jsx,ts,tsx}": [buildEslintCommand],
};

export default config;
