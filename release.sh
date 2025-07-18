#!/bin/bash

# Simple Release Script for Leegion Framework
echo "🚀 Creating Leegion Framework Release..."

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Please authenticate first: gh auth login"
    exit 1
fi

# Create tag
TAG="v2.0.1"
echo "🏷️  Creating tag: $TAG"

git tag -a "$TAG" -m "Release $TAG - Type Safety & Code Quality Improvements"
git push origin "$TAG"

# Create release
echo "📦 Creating GitHub release..."
gh release create "$TAG" \
    --title "Leegion Framework $TAG" \
    --notes "## 🚀 Leegion Framework 2.0.1

### ✨ Major Improvements
- **Type Safety**: Added comprehensive type annotations throughout the codebase
- **Code Quality**: Fixed 113+ mypy type errors and all flake8 linting issues
- **CI/CD**: Improved GitHub Actions workflow with proper type checking
- **Code Formatting**: Applied consistent code formatting with black

### 🔧 Technical Enhancements
- Fixed type annotation issues in core modules
- Resolved variable type mismatches and return type annotations
- Added proper type stubs for external dependencies
- Improved error handling and null safety
- Enhanced code documentation and type hints

### 🐛 Bug Fixes
- Fixed import-related type errors
- Corrected function parameter and return types
- Resolved collection type issues
- Fixed SSL analyzer certificate parsing

### 📦 Dependencies
- Added type stubs for requests and tabulate libraries
- Updated GitHub Actions workflow dependencies

### 🧹 Repository Cleanup
- Removed unnecessary cache files and generated reports
- Updated .gitignore with project-specific exclusions
- Improved repository structure and organization

---
*This release focuses on improving code quality, type safety, and maintainability.*" \
    --target main

echo "✅ Release created successfully!"
echo "🔗 View at: https://github.com/RootHaktivity/Leegion-Framework-2.0.1/releases/tag/$TAG" 