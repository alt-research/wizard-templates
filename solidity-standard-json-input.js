const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

// Define the base directories for contracts
const CONTRACTS_DIR = "lib/eigenlayer-middleware/src/";
const PERMISSIONS_DIR =
  "lib/eigenlayer-middleware/lib/eigenlayer-contracts/src/contracts/permissions/";
const TEMPLATES_DIR = "src/templates"; // Directory containing the Solidity templates

// Output directory for JSON files
const DIR_JSON_OUTPUT = "solidity-standard-json-input/";

// Ensure the output directory exists
if (!fs.existsSync(DIR_JSON_OUTPUT)) {
  fs.mkdirSync(DIR_JSON_OUTPUT, { recursive: true });
}

// List of specific Solidity files to verify
const solidityFiles = [
  path.join(CONTRACTS_DIR, "RegistryCoordinator.sol"),
  path.join(CONTRACTS_DIR, "StakeRegistry.sol"),
  path.join(CONTRACTS_DIR, "BLSApkRegistry.sol"),
  path.join(CONTRACTS_DIR, "IndexRegistry.sol"),
  path.join(PERMISSIONS_DIR, "PauserRegistry.sol"),
];

// Include template files from the TEMPLATES_DIR
const templateFiles = fs
  .readdirSync(TEMPLATES_DIR)
  .filter((file) => file.endsWith("Template.sol"))
  .map((file) => path.join(TEMPLATES_DIR, file));
solidityFiles.push(...templateFiles); // Append template files to the list of files to be processed

solidityFiles.forEach((file) => {
  const filename = path.basename(file, ".sol");
  const filePath = file;
  const jsonFilePath = path.join(DIR_JSON_OUTPUT, `${filename}.json`);

  // Check if the file exists to avoid errors
  if (!fs.existsSync(filePath)) {
    console.error(`File not found: ${filePath}`);
    return;
  }

  // Flatten the Solidity file
  const flattenedCode = execSync(`forge flatten ${filePath}`).toString();

  // Generate JSON content
  const jsonContent = JSON.stringify(
    {
      language: "Solidity",
      sources: {
        [`${filename}.sol`]: {
          content: flattenedCode,
        },
      },
      settings: {
        optimizer: {
          enabled: true,
          runs: 200,
        },
        evmVersion: "paris",
      },
    },
    null,
    2
  ); // The 'null' and '2' arguments format the JSON with indentation for readability

  // Write JSON file
  fs.writeFileSync(jsonFilePath, jsonContent);
});

console.log("JSON files creation complete.");
