#!/bin/bash

# Leegion Framework Release Script
# This script creates a GitHub release for the Leegion Framework

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Leegion Framework Release Creator${NC}"
echo "=================================="

# Check if gh is installed
if ! command -v gh &> /dev/null; then
    echo -e "${RED}❌ GitHub CLI (gh) is not installed. Please install it first.${NC}"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo -e "${YELLOW}⚠️  You are not authenticated with GitHub.${NC}"
    echo -e "${BLUE}Please run: gh auth login${NC}"
    exit 1
fi

echo -e "${GREEN}✅ GitHub CLI is installed and authenticated${NC}"

# Get current version from pyproject.toml
if [ -f "pyproject.toml" ]; then
    VERSION=$(grep '^version = ' pyproject.toml | cut -d'"' -f2)
    echo -e "${GREEN}📦 Current version: ${VERSION}${NC}"
else
    echo -e "${YELLOW}⚠️  pyproject.toml not found, using default version${NC}"
    VERSION="2.0.1"
fi

# Get the latest commit hash
LATEST_COMMIT=$(git rev-parse HEAD)
echo -e "${GREEN}📝 Latest commit: ${LATEST_COMMIT:0:8}${NC}"

# Create tag name
TAG_NAME="v${VERSION}"
echo -e "${BLUE}🏷️  Tag name: ${TAG_NAME}${NC}"

# Check if tag already exists
if git tag -l | grep -q "^${TAG_NAME}$"; then
    echo -e "${YELLOW}⚠️  Tag ${TAG_NAME} already exists${NC}"
    read -p "Do you want to delete and recreate it? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}🗑️  Deleting existing tag...${NC}"
        git tag -d "${TAG_NAME}" || true
        git push origin ":refs/tags/${TAG_NAME}" || true
    else
        echo -e "${RED}❌ Release cancelled${NC}"
        exit 1
    fi
fi

# Create and push tag
echo -e "${BLUE}🏷️  Creating tag...${NC}"
git tag -a "${TAG_NAME}" -m "Release ${TAG_NAME}"
git push origin "${TAG_NAME}"

# Generate release notes
echo -e "${BLUE}📝 Generating release notes...${NC}"

# Get commits since last tag
LAST_TAG=$(git describe --tags --abbrev=0 2>/dev/null || echo "")
if [ -n "$LAST_TAG" ]; then
    COMMITS=$(git log --oneline "${LAST_TAG}..HEAD" | head -20)
else
    COMMITS=$(git log --oneline -20)
fi

# Create release notes
RELEASE_NOTES=$(cat <<EOF
## 🚀 Leegion Framework ${VERSION}

### ✨ What's New
- **Type Safety**: Added comprehensive type annotations throughout the codebase
- **Code Quality**: Fixed all mypy type errors and flake8 linting issues
- **CI/CD**: Improved GitHub Actions workflow with proper type checking
- **Code Formatting**: Applied consistent code formatting with black

### 🔧 Technical Improvements
- Fixed 113+ mypy type errors
- Resolved all flake8 linting violations
- Added proper type stubs for external dependencies
- Improved error handling and null safety
- Enhanced code documentation and type hints

### 🐛 Bug Fixes
- Fixed type annotation issues in core modules
- Resolved variable type mismatches
- Corrected function return type annotations
- Fixed import-related type errors

### 📦 Dependencies
- Added type stubs for requests and tabulate libraries
- Updated GitHub Actions workflow dependencies

### 📋 Recent Commits
\`\`\`
${COMMITS}
\`\`\`

---
*This release focuses on improving code quality, type safety, and maintainability.*
EOF
)

# Create temporary file for release notes
RELEASE_NOTES_FILE=$(mktemp)
echo "$RELEASE_NOTES" > "$RELEASE_NOTES_FILE"

# Create the release
echo -e "${BLUE}🚀 Creating GitHub release...${NC}"
gh release create "${TAG_NAME}" \
    --title "Leegion Framework ${VERSION}" \
    --notes-file "$RELEASE_NOTES_FILE" \
    --target main

# Clean up
rm "$RELEASE_NOTES_FILE"

echo -e "${GREEN}✅ Release created successfully!${NC}"
echo -e "${BLUE}🔗 View your release: https://github.com/RootHaktivity/Leegion-Framework-v2.0.1/releases/tag/${TAG_NAME}${NC}"

# Optional: Create a summary
echo -e "\n${BLUE}📊 Release Summary:${NC}"
echo "=================="
echo -e "Version: ${GREEN}${VERSION}${NC}"
echo -e "Tag: ${GREEN}${TAG_NAME}${NC}"
echo -e "Branch: ${GREEN}$(git branch --show-current)${NC}"
echo -e "Commit: ${GREEN}${LATEST_COMMIT:0:8}${NC}"
echo -e "Date: ${GREEN}$(date)${NC}" 