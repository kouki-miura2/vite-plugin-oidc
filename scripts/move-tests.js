#!/usr/bin/env node

/**
 * Script to move test files from src/ to test/ directory
 */

const fs = require('fs');
const path = require('path');

// Test file mappings: [source, destination]
const testFileMappings = [
  // Unit tests
  ['src/utils/JWTUtil.test.ts', 'test/unit/utils/JWTUtil.test.ts'],
  ['src/utils/Logger.test.ts', 'test/unit/utils/Logger.test.ts'],
  ['src/utils/PKCEUtil.test.ts', 'test/unit/utils/PKCEUtil.test.ts'],
  ['src/utils/ValidationUtil.test.ts', 'test/unit/utils/ValidationUtil.test.ts'],
  ['src/storage/InMemoryStore.test.ts', 'test/unit/storage/InMemoryStore.test.ts'],
  ['src/services/TokenService.test.ts', 'test/unit/services/TokenService.test.ts'],
  ['src/handlers/DiscoveryHandler.test.ts', 'test/unit/handlers/DiscoveryHandler.test.ts'],
  ['src/handlers/JWKSHandler.test.ts', 'test/unit/handlers/JWKSHandler.test.ts'],
  ['src/handlers/TokenHandler.test.ts', 'test/unit/handlers/TokenHandler.test.ts'],
  ['src/handlers/UserInfoHandler.test.ts', 'test/unit/handlers/UserInfoHandler.test.ts'],
  ['src/index.test.ts', 'test/unit/index.test.ts'],
  
  // Integration tests
  ['src/EndToEnd.integration.test.ts', 'test/integration/EndToEnd.integration.test.ts'],
  ['src/VitePlugin.integration.test.ts', 'test/integration/VitePlugin.integration.test.ts'],
  ['src/handlers/AuthorizationFlow.integration.test.ts', 'test/integration/AuthorizationFlow.integration.test.ts'],
  
  // Test helpers
  ['src/test-helpers/PKCETestHelper.ts', 'test/helpers/PKCETestHelper.ts']
];

// Function to ensure directory exists
function ensureDirectoryExists(filePath) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// Function to update import paths in test files
function updateImportPaths(content, sourceFile, destFile) {
  // Calculate relative path from test file to src
  const testDir = path.dirname(destFile);
  const srcPath = path.relative(testDir, 'src').replace(/\\/g, '/');
  
  // Update imports from relative src paths to absolute src paths
  content = content.replace(/from\s+['"]\.\.?\/.*?[']/g, (match) => {
    const importPath = match.match(/['"](.+?)['"]/)[1];
    
    // Skip if already pointing to src or test directories
    if (importPath.startsWith('../../src/') || importPath.startsWith('../../../src/')) {
      return match;
    }
    
    // Convert relative imports to point to src
    let newPath = importPath;
    if (importPath.startsWith('./')) {
      // Same directory import - need to figure out the correct src path
      const sourceDir = path.dirname(sourceFile);
      newPath = path.relative(testDir, path.join(sourceDir, importPath.substring(2))).replace(/\\/g, '/');
    } else if (importPath.startsWith('../')) {
      // Parent directory import
      const sourceDir = path.dirname(sourceFile);
      newPath = path.relative(testDir, path.resolve(sourceDir, importPath)).replace(/\\/g, '/');
    }
    
    // Ensure it starts with the correct relative path to src
    if (!newPath.startsWith(srcPath)) {
      newPath = `${srcPath}/${newPath}`;
    }
    
    return match.replace(/['"](.+?)['"]/, `"${newPath}"`);
  });
  
  return content;
}

// Main execution
console.log('🚀 Starting test file migration...\n');

let movedCount = 0;
let skippedCount = 0;

testFileMappings.forEach(([source, dest]) => {
  if (fs.existsSync(source)) {
    console.log(`📁 Moving: ${source} → ${dest}`);
    
    // Ensure destination directory exists
    ensureDirectoryExists(dest);
    
    // Read source file
    let content = fs.readFileSync(source, 'utf8');
    
    // Update import paths
    content = updateImportPaths(content, source, dest);
    
    // Write to destination
    fs.writeFileSync(dest, content);
    
    // Remove source file
    fs.unlinkSync(source);
    
    movedCount++;
  } else {
    console.log(`⚠️  Skipped: ${source} (file not found)`);
    skippedCount++;
  }
});

console.log(`\n✅ Migration complete!`);
console.log(`📊 Moved: ${movedCount} files`);
console.log(`⚠️  Skipped: ${skippedCount} files`);

// Clean up empty test-helpers directory if it exists
const testHelpersDir = 'src/test-helpers';
if (fs.existsSync(testHelpersDir)) {
  const files = fs.readdirSync(testHelpersDir);
  if (files.length === 0) {
    fs.rmdirSync(testHelpersDir);
    console.log(`🗑️  Removed empty directory: ${testHelpersDir}`);
  }
}

console.log('\n🎉 Test files have been successfully moved to /test directory!');
console.log('📝 Next steps:');
console.log('   1. Run: npm test');
console.log('   2. Update any remaining import paths if needed');
console.log('   3. Update package.json test script if necessary');